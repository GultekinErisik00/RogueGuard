# RogueGuard — Mac'te (VMware Fusion) Sıfırdan Kurulum Rehberi

Nov 11, 2026 · @Gultekin

## Özet

Tüm lab, Mac'teki VMware Fusion'da çalışan tek bir Ubuntu ARM sanal makinesinin içinde kurulur. Adım 1'den 7'ye sırayla ilerle; 19 Kasım ara değerlendirmesi için hedef Adım 6.3'ün sonu.

### Öneriye göre değişenler

| Öneride | Bu rehberde | Neden |
| --- | --- | --- |
| OPNsense firewall ve API'si | nftables + dnsmasq çalışan router container (`rg-router`) | OPNsense Apple Silicon'da çalışmıyor |
| Wazuh ayrı sistem | Incus container içinde Docker ile tek düğüm | 16 GB RAM'e sığması için |
| ATT&CK for ICS | ATT&CK Enterprise | Hocanın 2. önerisi |
| Aynı imajdan 5–6 cihaz | 4 farklı imaj ve DHCP istemcisiyle 6 cihaz | Hocanın 1. önerisi |
| Kural tabanlı tespit | Ek olarak LLM ile cihaz türü tahmini (Groq) | Hocanın "güncel boyut" önerisi |

Firewall aracının değiştiğini hocaya geri bildirim başlığının altından bir cümleyle bildir.

### Hocanın geri bildirimi rehberde nerede

| Geri bildirim | Karşılandığı yer |
| --- | --- |
| 1. Cihazlara bilinçli olarak farklı ayarlar ver | Adım 3 (cihaz profilleri) ve 6.2'deki benzerlik testi |
| 2. ICS yerine Enterprise matrisi | Adım 4 (Wazuh kuralları) ve 6.3 (karar motoru) |
| 3. LLM tahmini kurallara göre ne kadar doğru | 6.7 (sınıflandırıcılar) ve Adım 7 (LLM deneyi) |

## Genel mimari

Tek VM'in içinde dört köprü vardır; cihazlar, broker, router ve Wazuh birer Incus container'ıdır, RogueGuard ise doğrudan VM'in kendisinde çalışır.

&#91;embedded content: Lab mimarisi · tek VM, 4 köprü\]

İki tasarım kararı:

- **RogueGuard VM host'unda çalışır.** Host `br-iot` köprüsünü promiscuous modda dinlediğinde köprüdeki tüm trafiği görür; ARP spoofing tespiti buna bağlı.
- **MQTT broker ayrı köprüdedir (`br-svc`).** Böylece cihazdan broker'a giden trafik `rg-router`'dan geçer ve engellenebilir. Aynı köprü içindeki saldırılar (ör. ARP spoofing) router'dan geçmez; onlar için cihaz `br-quar`'a taşınır.

### Köprüler

| Köprü | Rol | IP dağıtan |
| --- | --- | --- |
| `incusbr0` | Yönetim ve internet çıkışı (Incus oluşturur, NAT) | Incus |
| `br-iot` | Meşru ve rogue cihazlar | `rg-router` |
| `br-quar` | Karantina | `rg-router` |
| `br-svc` | MQTT broker | `rg-router` |

### Bileşenler

| Bileşen | Nerede çalışır | Bağlı olduğu köprü | Yaklaşık bellek |
| --- | --- | --- | --- |
| RogueGuard, Streamlit, arpwatch | VM host'u | `br-iot` (statik IP), `incusbr0` | 1 GB |
| `rg-router` | Container (Debian 13) | `incusbr0`, `br-iot`, `br-quar`, `br-svc` | 0,2 GB |
| `mqtt-broker` | Container (Debian 13) | `br-svc` | 0,1 GB |
| 6 cihaz ve rogue'lar | Container | `br-iot` | 1 GB (toplam) |
| `wazuh` | Container içinde Docker | `incusbr0` | 5 GB (sınır) |

### Bellek düzeni

- VM: 4 çekirdek, 10 GB RAM, 60 GB disk, içinde 4 GB swap.
- VM çalışırken Mac'te Docker Desktop kapalı olsun.
- **Geliştirme ve deney modu:** `wazuh` container'ı kapalı. Tespit ve karantina süresi ölçümleri Wazuh gerektirmez.
- **SIEM testi ve demo modu:** `incus start wazuh`; iş bitince `incus stop wazuh`.

### Yer tutucular

`<VM_IP>`, `<IOT_SUBNET>`, `<IOT_GW_IP>`, `<SENSOR_IOT_IP>`, `<BROKER_IP>`, `<WAZUH_IP>`, `<MGMT_SUBNET>` kendi seçeceğin değerlerdir. Rehberde `<IOT_NIC>` geçen her yerde `br-iot` kullan.

## Adım 1 — VMware Fusion'da Ubuntu VM

Fusion'da tek bir Ubuntu Server 24.04 ARM64 VM'i kur; ağ adaptörü NAT olsun, ek sanal ağ gerekmez.

### VM'i oluştur

1. Ubuntu'nun sitesinden **Ubuntu Server 24.04 LTS ARM64** ISO'sunu indir (dosya adı `...live-server-arm64.iso`).
2. Fusion'da **File → New**, ISO'yu sürükle. **Customize Settings** ile: 4 işlemci çekirdeği, 10240 MB bellek, 60 GB disk, ağ **Share with my Mac** (NAT).
3. Kurulumda **Install OpenSSH server** seçeneğini işaretle. Kullanıcı adı: `<KULLANICI>`.
4. Kurulum bitince VM'de `ip -br a` ile `<VM_IP>` değerini al. Bundan sonra Mac terminalinden çalış: `ssh <KULLANICI>@<VM_IP>`.

### Temel ayarlar

```bash
sudo apt update && sudo apt -y upgrade
sudo apt install -y incus git nmap tcpdump python3-venv

# 4 GB swap
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Wazuh indexer için gerekli çekirdek ayarı
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/90-wazuh.conf
sudo sysctl --system
```

### Incus

```bash
sudo usermod -aG incus-admin <KULLANICI>   # sonra oturumu kapatıp aç
incus admin init --minimal                 # incusbr0 ve varsayılan depolamayı oluşturur
incus launch images:debian/13 test && incus exec test -- ping -c 2 deb.debian.org
incus delete -f test
```

**Kontrol:** test container'ı internete çıkabiliyor. VM kapalıyken Fusion'da bir snapshot al: `temiz-kurulum`.

## Adım 2 — Köprüler ve router

VM'de üç köprü oluştur, sonra bu köprüleri birbirine ve internete bağlayan `rg-router` container'ını kur. Router DHCP ve DNS'i dnsmasq ile, filtrelemeyi nftables ile yapar.

### Köprüler (VM host'unda)

`/etc/netplan/60-rg-bridges.yaml`:

```yaml
network:
  version: 2
  bridges:
    br-iot:
      addresses: [<SENSOR_IOT_IP>/<IOT_PREFIX>]
      link-local: []
      optional: true
      parameters: {stp: false, forward-delay: 0}
    br-quar:
      link-local: []
      optional: true
      parameters: {stp: false, forward-delay: 0}
    br-svc:
      link-local: []
      optional: true
      parameters: {stp: false, forward-delay: 0}
```

```bash
sudo chmod 600 /etc/netplan/60-rg-bridges.yaml && sudo netplan apply
```

`br-iot` üzerindeki adres RogueGuard'ın tarama yaparken kullandığı adrestir; DHCP havuzunun dışında seç. Adres, köprüye ilk container bağlandığında görünebilir.

Host'un cihazlar için yönlendirme yapmaması gerekir; tek yol `rg-router` olmalı. `/etc/nftables.conf` dosyasının içeriğini şunla değiştir (`flush ruleset` satırı olmasın, Incus'un kurallarını siler):

```
#!/usr/sbin/nft -f
table inet rg_host
delete table inet rg_host
table inet rg_host {
  chain forward {
    type filter hook forward priority -5; policy accept;
    iifname { "br-iot", "br-quar", "br-svc" } drop
    oifname { "br-iot", "br-quar", "br-svc" } drop
  }
}
```

```bash
sudo systemctl enable --now nftables
```

### Router container

```bash
incus init images:debian/13 rg-router            # eth0 = incusbr0 (internet)
incus config device add rg-router eth1 nic nictype=bridged parent=br-iot
incus config device add rg-router eth2 nic nictype=bridged parent=br-quar
incus config device add rg-router eth3 nic nictype=bridged parent=br-svc
incus start rg-router
incus exec rg-router -- apt install -y nftables dnsmasq
```

Router'ın içinde (`incus exec rg-router -- bash`):

1. Arayüz adresleri. `/etc/systemd/network/eth1.network` (eth2 ve eth3 için aynı kalıpla `<QUAR_GW_IP>`, `<SVC_GW_IP>`):

```
[Match]
Name=eth1

[Network]
Address=<IOT_GW_IP>/<IOT_PREFIX>
```

2. Yönlendirme: `echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/90-router.conf`
3. DHCP ve DNS. `/etc/dnsmasq.d/lab.conf`:

```
interface=eth1
interface=eth2
interface=eth3
bind-interfaces
dhcp-range=<IOT_DHCP_START>,<IOT_DHCP_END>,12h
dhcp-range=<QUAR_DHCP_START>,<QUAR_DHCP_END>,1h
dhcp-range=<SVC_DHCP_START>,<SVC_DHCP_END>,12h
dhcp-host=<BROKER_MAC>,<BROKER_IP>
```

4. Firewall. `/etc/nftables.conf`:

```
#!/usr/sbin/nft -f
flush ruleset
table inet rg {
  set rg_approved { type ipv4_addr; }
  set rg_block    { type ipv4_addr; }

  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    iifname "eth1" ip saddr @rg_block counter drop
    ct state established,related accept
    iifname "eth0" accept
    iifname { "eth1", "eth2", "eth3" } udp dport 67 accept
    iifname { "eth1", "eth3" } meta l4proto { tcp, udp } th dport 53 accept
    iifname "eth1" icmp type echo-request accept
  }

  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "eth1" ip saddr @rg_block counter drop
    ct state established,related accept
    iifname "eth1" ip saddr @rg_approved ip daddr <BROKER_IP> tcp dport 1883 counter accept
    iifname "eth1" ip saddr @rg_approved oifname "eth0" counter accept
  }

  chain postrouting {
    type nat hook postrouting priority 100;
    oifname "eth0" masquerade
  }
}
```

5. `systemctl enable nftables dnsmasq`, sonra host'tan `incus restart rg-router`.

### Bu kurallar ne sağlar

| Cihazın durumu | Erişebildiği |
| --- | --- |
| Onaysız (pending) | Sadece DHCP ve DNS |
| `rg_approved` setinde | Broker (TCP 1883) ve internet |
| `rg_block` setinde | Hiçbir şey; açık bağlantıları da kesilir |
| `br-quar`'a taşınmış | Sadece DHCP |

Setler router yeniden başlayınca boşalır; RogueGuard açılışta ikisini de veritabanından yeniden doldurur.

### Test

```bash
incus exec rg-router -- nft add element inet rg rg_block { <TEST_IP> }
incus exec rg-router -- nft list set inet rg rg_block
incus exec rg-router -- nft delete element inet rg rg_block { <TEST_IP> }
incus exec rg-router -- nft list chain inet rg forward     # sayaçlar
```

**Kontrol:** `br-iot`'a bağladığın geçici bir container router'dan IP alıyor, ama `rg_approved`'a eklenene kadar internete çıkamıyor.

## Adım 3 — MQTT broker ve IoT cihazları

Her container'ı önce `incusbr0`'da kur (internet olduğu için paketler iner), sonra ağ kartını asıl köprüsüne taşı. Cihazlar `br-iot`'a bağlandıktan sonra kendi MAC'leriyle DHCP'yi `rg-router`'dan alır.

### MQTT broker

```bash
incus launch images:debian/13 mqtt-broker
incus exec mqtt-broker -- apt install -y mosquitto mosquitto-clients
incus exec mqtt-broker -- sh -c 'printf "listener 1883 0.0.0.0\nallow_anonymous true\n" > /etc/mosquitto/conf.d/lab.conf'
incus stop mqtt-broker
incus config device add mqtt-broker eth0 nic nictype=bridged parent=br-svc hwaddr=<BROKER_MAC>
incus start mqtt-broker
```

`<BROKER_MAC>` Adım 2'de dnsmasq'taki `dhcp-host` satırına yazdığın MAC ile aynı olmalı; broker böylece her zaman `<BROKER_IP>` alır. `allow_anonymous` sadece izole lab için.

### Cihaz profilleri

Her cihaz farklı bir imaj ve DHCP istemcisi kullanır; bu, DHCP option 55 sırasını doğal olarak farklılaştırır.

| Cihaz | Tür | İmaj | DHCP istemcisi | Dinlediği portlar | mDNS servisleri | MQTT yayını |
| --- | --- | --- | --- | --- | --- | --- |
| cam-01 | kamera | `images:alpine/<SURUM>` | udhcpc | 80, 554 | `_http._tcp`, `_rtsp._tcp` | hareket olayı, düzensiz |
| printer-01 | yazıcı | `images:debian/12` | dhclient | 631, 9100 | `_ipp._tcp`, `_printer._tcp` | durum, 300 s |
| plug-01 | akıllı priz | `images:debian/13` | dhcpcd | 80, `<PRIZ_PORTU>` | `_http._tcp` | güç ölçümü, 10 s |
| temp-01 | sıcaklık sensörü | `images:alpine/<SURUM>` | udhcpc (farklı vendor class) | yok | yok | sıcaklık, 15 s |
| thermo-01 | termostat | `images:ubuntu/24.04` | systemd-networkd | 80 | `_hap._tcp` | ayar noktası, 60 s |
| cam-02 | kamera (cam-01 ile aynı model) | cam-01 ile aynı | udhcpc | 80, 554 | aynı | aynı |

cam-02 bilerek cam-01'in ikizi: sadece MAC son üç byte'ı ve hostname farklı. Aynı modelden iki cihazın ayırt edilememesi raporda sınırlılık olarak gösterilir.

Her profil için ayrıca belirle: üretici OUI'si (`grep -i "<uretici>" /usr/share/nmap/nmap-mac-prefixes`), gerçekçi bir hostname, DHCP vendor class (option 60) ve HTTP `Server` başlığı. Hepsi `lab/devices.yaml` içinde dursun; bu dosya aynı zamanda doğru cevap etiketidir.

### DHCP istemcisini ayarlama

- **udhcpc:** `udhcpc -i eth0 -b -x hostname:<HOSTNAME> -V "<VENDOR_CLASS>"`
- **dhclient:** `/etc/dhcp/dhclient.conf` içinde `send host-name "<HOSTNAME>";` ve `send vendor-class-identifier "<VENDOR_CLASS>";`
- **dhcpcd:** `/etc/dhcpcd.conf` içinde `hostname <HOSTNAME>` ve `vendorclassid <VENDOR_CLASS>`
- **systemd-networkd:** `.network` dosyasında `[DHCPv4]` altında `Hostname=<HOSTNAME>` ve `VendorClassIdentifier=<VENDOR_CLASS>`

İmajda varsayılan olarak gelen ağ yöneticisi seçtiğin istemciyle çakışıyorsa kapat; DHCP'yi cihaz ajanının başlangıç script'i başlatsın.

### Cihaz ajanı

Tek bir `device_agent.py` tüm cihazları profil dosyasına göre taklit eder:

- profildeki portlarda dinler ve gerçekçi banner döner (HTTP `Server` başlığı, 554'te RTSP cevabı); nmap servis tespiti bunları okur
- `python-zeroconf` ile mDNS servislerini kaydeder
- `paho-mqtt` ile `<BROKER_IP>:1883`'e profildeki topic ve aralıkla yayın yapar, aralığa küçük rastgele sapma ekler
- İstersen profilde tanımlanan NTP veya DNS hedeflerine periyodik istek atar (davranış parmak izi için)

Alpine'da `apk add python3`, diğerlerinde `apt install python3-venv`; ajanı bir venv içinde çalıştır.

### Bir cihazı oluşturma

`lab/build_lab.py` bu adımları `devices.yaml`'daki her cihaz için tekrarlar:

```bash
incus launch images:alpine/<SURUM> cam-01          # önce incusbr0'da, internet var
incus file push -r lab/agent/ cam-01/opt/
incus file push lab/profiles/cam-01.yaml cam-01/opt/agent/profile.yaml
incus exec cam-01 -- sh /opt/agent/setup.sh        # paketler, hostname, DHCP istemcisi, servis
incus stop cam-01
incus config device add cam-01 eth0 nic nictype=bridged parent=br-iot hwaddr=<OUI>:<XX>:<XX>:<XX>
incus start cam-01
incus snapshot create cam-01 clean
```

**Kontrol:** `incus exec rg-router -- cat /var/lib/misc/dnsmasq.leases` çıktısında her cihaz kendi hostname'i ve farklı üretici MAC'iyle görünmeli. Yayınları `incus exec mqtt-broker -- mosquitto_sub -t '#' -v` ile izle. Cihazlar henüz `rg_approved` setinde olmadığı için broker'a erişemez; test için IP'lerini sete elle ekle (Adım 2'deki test komutları).

## Adım 4 — Wazuh (Docker)

Wazuh'u ayrı bir Incus container'ının içinde Docker ile tek düğüm olarak kur, RogueGuard'dan UDP 514 üzerinden JSON syslog al ve her tespit türünü ATT&CK Enterprise ID'si taşıyan bir kurala bağla. Docker'ı doğrudan VM host'una kurma; host'ta Docker'ın ağ kuralları köprülerdeki cihaz trafiğini kesebilir.

### Kurulum

VM host'unda:

```bash
incus launch images:ubuntu/24.04 wazuh -c security.nesting=true -c limits.memory=5GiB
incus config device override wazuh eth0 ipv4.address=<WAZUH_IP>
incus config device add wazuh dash proxy listen=tcp:0.0.0.0:8443 connect=tcp:127.0.0.1:443
incus restart wazuh
incus exec wazuh -- bash
```

Container'ın içinde:

```bash
apt update && apt install -y docker.io docker-compose-v2 git
git clone https://github.com/wazuh/wazuh-docker.git -b v<WAZUH_SURUM>
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
# docker-compose.yml: indexer servisinde OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
docker compose up -d
```

- `<WAZUH_SURUM>` için Wazuh'un Docker dokümanındaki güncel etiketi kullan; sertifika adımı sürüme göre değişebilir.
- Dashboard: Mac'te `https://<VM_IP>:8443`. Varsayılan kullanıcı ve şifre `docker-compose.yml` içinde; değiştir.
- Docker container'ları başlamıyorsa (iç içe container izin hatası) `incus config set wazuh security.privileged=true` ile yeniden dene; bu ayar sadece izole lab için kabul edilebilir.

### Syslog alımı

`single-node/config/wazuh_cluster/wazuh_manager.conf` içinde `<ossec_config>` altına ekle (514/udp portu compose dosyasında yayınlı olmalı; `ports` listesinden kontrol et):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips><MGMT_SUBNET></allowed-ips>
</remote>
```

### Decoder ve kurallar

Aşağıdaki iki dosyayı hazırla ve manager container'ına kopyala. `<MANAGER>` adını `docker compose ps` gösterir.

```bash
docker cp local_decoder.xml <MANAGER>:/var/ossec/etc/decoders/local_decoder.xml
docker cp local_rules.xml   <MANAGER>:/var/ossec/etc/rules/local_rules.xml
docker exec <MANAGER> chown wazuh:wazuh /var/ossec/etc/decoders/local_decoder.xml /var/ossec/etc/rules/local_rules.xml
```

`/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="rogueguard">
  <program_name>^rogueguard</program_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="rogueguard,">
  <rule id="100200" level="3">
    <decoded_as>rogueguard</decoded_as>
    <description>RogueGuard event</description>
  </rule>
  <rule id="100201" level="8">
    <if_sid>100200</if_sid>
    <field name="type">^unknown_device$</field>
    <description>RogueGuard: unknown device $(mac) $(ip)</description>
    <mitre><id>T1200</id></mitre>
  </rule>
  <rule id="100202" level="12">
    <if_sid>100200</if_sid>
    <field name="type">^impersonation$</field>
    <description>RogueGuard: impersonation of $(mac)</description>
    <mitre><id>T1036</id></mitre>
  </rule>
  <rule id="100203" level="12">
    <if_sid>100200</if_sid>
    <field name="type">^arp_spoofing$</field>
    <description>RogueGuard: ARP spoofing from $(mac)</description>
    <mitre><id>T1557.002</id></mitre>
  </rule>
  <rule id="100204" level="10">
    <if_sid>100200</if_sid>
    <field name="type">^abnormal_scan$</field>
    <description>RogueGuard: scanning from $(mac)</description>
    <mitre><id>T1046</id></mitre>
  </rule>
  <rule id="100205" level="10">
    <if_sid>100200</if_sid>
    <field name="type">^abnormal_behavior$</field>
    <description>RogueGuard: abnormal behavior $(mac)</description>
  </rule>
</group>
```

Sonra `docker compose restart wazuh.manager`.

### Test

1. Kural eşleşmesini docker exec -it \<MANAGER> `/var/ossec/bin/wazuh-logtest` ile dene; örnek satır:

```
Nov 10 12:00:00 rg-sensor rogueguard: {"type":"arp_spoofing","mac":"<MAC>","ip":"<IP>","severity":"high","action":"quarantine","reason":"<NEDEN>"}
```

2. VM host'undan ağ üzerinden gönder:

```bash
logger -n <WAZUH_IP> -P 514 -d -t rogueguard '{"type":"unknown_device","mac":"<MAC>","ip":"<IP>"}'
```

3. Dashboard'da **Threat Hunting** ve **MITRE ATT&CK** görünümlerinde alarmın teknik ID'siyle göründüğünü kontrol et.

Alarm gelmiyorsa `allowed-ips` değerini geçici olarak `0.0.0.0/0` yapıp tekrar dene. İşin bitince `incus stop wazuh` ile belleği boşalt.

## Adım 5 — RogueGuard ortamı ve proje iskeleti

RogueGuard doğrudan VM host'unda çalışır: `br-iot`'u dinler ve tarar, router'ı ve container'ları yerel `incus` komutlarıyla yönetir. Envantere ilk eklenecek kayıtlar altyapıdır: host'un `br-iot` adresi ve `rg-router`.

### Host hazırlığı

1. `sudo apt install -y arpwatch` (diğer paketler Adım 1'de kuruldu).
2. arpwatch'ı kıyaslama aracı olarak `br-iot`'ta başlat: `sudo systemctl enable --now arpwatch@br-iot`. Uyarıları `journalctl -u arpwatch@br-iot` ile okursun.
3. Dinlemeyi doğrula: `sudo tcpdump -i br-iot -n arp`. İki cihaz arasındaki ARP cevaplarını da görmelisin.
4. Kodu Mac'te yazacaksan repoyu GitHub'da tut, VM'de `git pull` ile güncelle; ya da VS Code Remote-SSH ile doğrudan VM'de çalış.

### Python ortamı

```bash
git init rogueguard && cd rogueguard
python3 -m venv .venv && . .venv/bin/activate
pip install scapy pyyaml requests streamlit pandas zeroconf openai pytest
```

Scapy ham soket ister. Daemon'u systemd servisi olarak çalıştır ve unit dosyasına `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` ekle. Geliştirme sırasında `sudo .venv/bin/python -m rogueguard ...` yeterli.

### Klasör yapısı

```
rogueguard/
├── config.yaml                 # IP'ler, API anahtarları, eşikler, aktif konfigürasyon (1/2/3)
├── rogueguard/
│   ├── __main__.py             # CLI: learn | protect | sync-aliases
│   ├── db.py                   # SQLite (WAL modu), tablolar
│   ├── discovery/
│   │   ├── arp_scan.py         # periyodik aktif ARP taraması
│   │   ├── sniffer.py          # pasif: DHCP, ARP, mDNS, trafik örneği
│   │   └── events.py           # "yeni cihaz", "değişen cihaz" olayları
│   ├── fingerprint/
│   │   ├── vendor.py           # OUI → üretici
│   │   ├── dhcp.py             # option 12, 55, 60, 61
│   │   ├── ports.py            # nmap -sT -sV, XML çıktısını ayrıştır
│   │   ├── mdns.py
│   │   ├── traffic.py          # hedefler, yayın aralığı, paket boyutu
│   │   └── compare.py          # özellik bazında benzerlik skoru
│   ├── decision/
│   │   ├── engine.py           # unknown / impersonation / abnormal / arp_spoofing
│   │   ├── arp_guard.py        # IP→MAC bağları, gratuitous ARP sayacı
│   │   └── attack_map.py       # tür → ATT&CK Enterprise ID, önem derecesi
│   ├── containment/
│   │   ├── router.py           # nft set ekle/sil (incus exec)
│   │   └── quarantine.py       # incus komutu: NIC'i br-quar'a taşı
│   ├── alerting/syslog.py      # Wazuh'a JSON syslog
│   └── classify/
│       ├── rules.py            # kural tabanlı cihaz türü
│       └── llm.py              # Groq ile cihaz türü tahmini
├── dashboard/app.py            # Streamlit
├── lab/
│   ├── devices.yaml            # meşru cihaz profilleri = doğru cevaplar
│   ├── rogues.yaml             # 4 rogue seviyesi
│   ├── build_lab.py
│   └── agent/                  # device_agent.py, setup.sh
├── experiments/
│   ├── run_scenarios.py
│   └── metrics.py
└── tests/
```

### Veritabanı tabloları

| Tablo | Ana alanlar |
| --- | --- |
| `devices` | mac, ip, hostname, vendor, dhcp\_fp, ports, mdns, destinations, publish\_interval, device\_type, status (approved / pending / blocked / quarantined), first\_seen, last\_seen |
| `observations` | ts, mac, ip, kaynak (arp / dhcp / mdns / nmap / traffic), ham veri (JSON) |
| `alerts` | ts, mac, ip, type, severity, attack\_id, action, reason, detected\_at, contained\_at |
| `approvals` | mac, karar (approve / reject), ts — dashboard yazar, daemon okur |

Daemon ve Streamlit aynı SQLite dosyasını kullanır. Dashboard sadece `approvals` tablosuna yazar; daemon bu tabloyu birkaç saniyede bir okuyup kararı uygular. Böylece iki süreç arasında başka bir iletişim katmanı gerekmez.

## Adım 6 — Modülleri geliştirme sırası

Modülleri aşağıdaki sırayla yaz; her biri "bitti" kontrolünü geçmeden sonrakine geçme. 6.1–6.3 ara değerlendirme için yeterli.

### 6.1 Keşif

- **Aktif ARP taraması** (her `<TARAMA_ARALIGI>` saniyede):

```python
from scapy.all import srp, Ether, ARP
ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="<IOT_SUBNET>"),
             iface="<IOT_NIC>", timeout=2, verbose=False)
seen = {(r.psrc, r.hwsrc) for _, r in ans}
```

- **Pasif dinleme:** tek bir `sniff(iface="<IOT_NIC>", filter="arp or udp port 67 or udp port 68 or udp port 5353", prn=handle, store=False)`. DHCP paketinde `pkt[DHCP].options` listesinden `hostname`, `vendor_class_id`, `param_req_list` ve `client_id` alanlarını al.
- **Trafik örneği:** ayrı bir sniff ile MAC başına hedef IP:port kümesi, paket sayısı ve MQTT yayınları arasındaki süreyi pencere bazında topla.
- **Olaylar:** yeni MAC → `new_device`; IP, hostname veya DHCP izi değişen MAC → `changed_device`.

**Bitti:** daemon çalışırken 6 cihazın hepsi `observations` tablosunda ARP, DHCP ve mDNS kayıtlarıyla görünüyor.

### 6.2 Öğrenme modu

1. `python -m rogueguard learn --duration <SURE>` keşif modülünü çalıştırır.
2. Her cihaz için bir kez `nmap -sT -sV -p <PORT_ARALIGI> -oX - <IP>` çalıştırır, XML çıktısından port ve servis bilgisini alır.
3. Süre sonunda her cihazı `devices` tablosuna `approved` olarak yazar, `inventory.yaml` olarak dışa aktarır ve `rg_approved` setini doldurur.
4. pytest: meşru cihazların parmak izi benzerliği ikili olarak `<ESIK>` altında olmalı. Beklenen tek istisna cam-01 / cam-02; bunu testte açıkça işaretle.

**Bitti:** envanterde 6 cihaz var, benzerlik testi geçiyor, cihazlar broker'a yayın yapabiliyor.

### 6.3 Parmak izi karşılaştırma ve karar motoru

`compare.py` özellik bazında skor üretir; ağırlıklar ve eşikler `config.yaml`'da durur ki deneylerde değiştirebilesin.

| Özellik | Karşılaştırma |
| --- | --- |
| MAC üreticisi | birebir |
| Hostname | birebir |
| DHCP option 55 sırası | birebir dizi |
| DHCP vendor class | birebir |
| Açık portlar ve servisler | Jaccard |
| mDNS servisleri | Jaccard |
| Trafik hedefleri | Jaccard |
| Yayın aralığı | göreli fark < `<ARALIK_TOLERANSI>` |

Karar kuralları:

| Koşul | Tür | Önem | Aksiyon |
| --- | --- | --- | --- |
| MAC envanterde yok | `unknown_device` | orta | pending: alarm, engelleme yok, dashboard onayı bekler |
| MAC envanterde, parmak izi skoru < `<ESLESME_ESIGI>` | `impersonation` | yüksek | karantina |
| ARP cevabı bir IP'nin envanterdeki MAC'iyle çelişiyor (özellikle gateway IP'si) | `arp_spoofing` | yüksek | karantina |
| Gratuitous ARP sayısı > `<GARP_ESIGI>` / saniye | `arp_spoofing` | yüksek | karantina |
| Kısa sürede > `<TARAMA_ESIGI>` farklı IP veya porta bağlantı | `abnormal_scan` | yüksek | firewall blok |
| Parmak izi uyuyor, trafik profil dışı (yeni hedef, aralık sapması) | `abnormal_behavior` | yüksek | firewall blok |

`config.yaml`'daki `detection_profile` değeri deneydeki üç konfigürasyonu seçer: `allowlist` sadece ilk satırı çalıştırır, `fingerprint` ilk iki satırı, `full` hepsini.

Yanlış pozitifleri azaltmak için:

- IP değişikliği tek başına alarm değil; DHCP ACK görülünce IP→MAC bağını güncelle.
- Yeniden başlayan cihaz için `<BEKLEME_SURESI>` boyunca trafik kontrolünü atla.
- `abnormal_behavior` için arka arkaya `<K>` anormal pencere iste.

**Bitti:** bilinmeyen bir container ağa bağlanınca `alerts` tablosuna `unknown_device` düşüyor ve cihaz `pending` görünüyor.

### 6.4 Karantina ve engelleme

- **`router.py`:** `block(ip)` → `incus exec rg-router -- nft add element inet rg rg_block { <ip> }`; `approve(ip)` → aynı komutla `rg_approved`; `sync()` → açılışta iki seti veritabanından yeniden doldur. `rg_block` kuralı "established" kuralından önce durduğu için açık bağlantılar da kesilir.
- **`quarantine.py`:** `incus list --format json` çıktısında `expanded_devices.eth0.hwaddr` üzerinden MAC'i container'a eşle, sonra `incus config device set <ad> eth0 parent=br-quar`. Container'ın ağ kartı yeniden oluşur ve karantina ağına düşer.
- **Hangisi ne zaman:** IP engelleme sadece router'dan geçen trafiği durdurur, ayrıca aynı IP'yi paylaşan kurbanı da etkiler. Bu yüzden `impersonation` ve `arp_spoofing` için karantina, `abnormal_*` için IP engelleme kullan.
- **Aynı MAC'e sahip iki container:** IP'si veya hostname'i envanterle uyuşmayanı seç. Gerçek ağlarda bu ayrımı switch portu bilgisi yapar; raporda sınırlılık olarak yaz.
- `alerts` satırına `detected_at` ve komut başarılı olduktan sonra `contained_at` yaz.

**Bitti:** dashboard'da reddedilen cihaz br-quar'a taşınıyor ve broker'a erişemiyor.

### 6.5 Alarm iletimi

```python
import json, logging, logging.handlers
h = logging.handlers.SysLogHandler(address=("<WAZUH_IP>", 514))
h.setFormatter(logging.Formatter("%(asctime)s rg-sensor rogueguard: %(message)s",
                                 datefmt="%b %d %H:%M:%S"))
log = logging.getLogger("rogueguard.siem")
log.addHandler(h)
log.setLevel(logging.INFO)
log.info(json.dumps(alert))  # alert: type, mac, ip, severity, attack_id, action, reason
```

**Bitti:** her alarm türü Wazuh'ta doğru kural ID'si ve ATT&CK tekniğiyle görünüyor.

### 6.6 Dashboard

Streamlit'te dört sayfa: **Cihazlar** (durum renkli tablo), **Onay bekleyenler** (Onayla / Reddet düğmeleri `approvals` tablosuna yazar), **Alarmlar** (tür, önem, ATT&CK ID, aksiyon, neden), **Deney sonuçları**. Canlı yenileme için tabloları `@st.fragment(run_every="5s")` ile sar.

### 6.7 Cihaz türü: kurallar ve LLM

1. `classify/rules.py`: sabit etiketler `camera`, `printer`, `smart_plug`, `sensor`, `thermostat`, `unknown`. Örnek: 554 portu veya `_rtsp._tcp` → camera; 631, 9100 veya `_ipp._tcp` → printer.
2. `classify/llm.py`: Groq'un OpenAI uyumlu API'si.

```python
import os, json
from openai import OpenAI
client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=os.environ["GROQ_API_KEY"])
resp = client.chat.completions.create(
    model="<MODEL>", temperature=0,
    response_format={"type": "json_object"},
    messages=[{"role": "system", "content": SYSTEM_PROMPT},   # etiket listesi + JSON şeması
              {"role": "user", "content": json.dumps(fingerprint)}])
result = json.loads(resp.choices[0].message.content)  # label, confidence, reason
```

3. Cevapları parmak izi hash'ine göre önbelleğe al; 429 alınca `retry-after` kadar bekle. Model adını ve limitleri Groq konsolundan kontrol et.
4. LLM çıktısı sadece dashboard'da "tahmini tür" olarak görünür; karar motoruna girdi olmaz. Hostname, mDNS adı ve vendor class saldırganın kontrolündeki alanlardır; prompt injection deneyi için Adım 7'ye bak.

## Adım 7 — Rogue cihazlar, senaryolar ve deney

Rogue cihazları meşru cihazlarda kullanmadığın bir saldırgan imajından üret (ör. `images:fedora/<SURUM>`). Böylece her seviye, kopyalamadığı özellikler yüzünden gerçekçi bir iz bırakır. Deneyi VM host'unda çalışan tek bir script yönetir; tüm zamanlar aynı saatten okunur.

### Rogue seviyeleri

| Seviye | Ne yapar | Nasıl kurulur | Beklenti (hipotez): 1 / 2 / 3 |
| --- | --- | --- | --- |
| R1 | Hiçbir şey gizlemez | Saldırgan imajı, kendi MAC'i | yakalar / yakalar / yakalar |
| R2 | Kurbanın MAC'ini kopyalar | `hwaddr=<KURBAN_MAC>`, kurban kapalı | kaçırır / yakalar / yakalar |
| R3 | MAC + hostname + portlar + mDNS | R2 + kurbanın profiliyle `device_agent.py`; DHCP istemcisi farklı kalır | kaçırır / DHCP izine bağlı / yakalar |
| R4 | R3 + gateway'e karşı ARP spoofing | R3 + `arpspoof -i eth0 -t <KURBAN_IP> <IOT_GW_IP>` (dsniff), `ip_forward=1` | kaçırır / kaçırır veya kısmen / yakalar |
| R3+ (opsiyonel) | R3 + kurbanın DHCP option'larını da kopyalar | Kurbanla aynı DHCP istemcisi ve vendor class | kaçırır / kaçırır / sadece davranış yakalar |

R2'yi bir de kurban açıkken çalıştır; aynı MAC'in iki yerde görünmesi ayrı bir sonuç satırı olur.

### Normal olaylar (negatif örnekler)

| Kod | Olay | Nasıl |
| --- | --- | --- |
| B1 | Meşru cihaz yeniden başlar | `incus restart temp-01` |
| B2 | Meşru cihazın IP'si değişir | Router'da dnsmasq kiralamasını sil, cihazı yeniden başlat |
| B3 | Yeni meşru cihaz eklenir ve onaylanır | Yeni profil, dashboard'dan **Onayla** (script `approvals`'a yazar) |
| B4 | Hiçbir şey olmaz | `<SESSIZ_SURE>` boyunca sadece izle |

Yanlış pozitif = B senaryolarında engellenen veya karantinaya alınan meşru cihaz sayısı. B3'teki `unknown_device` alarmı beklenen davranıştır, yanlış pozitif sayılmaz.

### Deney script'i (`experiments/run_scenarios.py`)

3 konfigürasyon × 8 senaryo (R1–R4, B1–B4) × 10 tekrar için her koşuda:

1. **Sıfırla:** rogue container'ları sil, meşru cihazları `clean` snapshot'ına döndür, `rg_block`'u boşalt, veritabanını öğrenilmiş envanter kopyasıyla değiştir, daemon'u seçilen `detection_profile` ile yeniden başlat.
2. `<DENGELENME_SURESI>` bekle.
3. `t0` zamanını kaydet, senaryoyu başlat.
4. `<ZAMAN_ASIMI>` dolana kadar `alerts` tablosunu yokla.
5. Sonucu yaz: yakalandı mı, tür doğru mu, `ttd = detected_at − t0`, `ttc = contained_at − t0`, engellenen meşru cihaz sayısı.
6. **arpwatch:** `journalctl -u arpwatch@<IOT_NIC> --since @<t0>` çıktısında `new station`, `changed ethernet address` ve `flip flop` satırlarını ara; aynı alanlarla ayrı bir satır olarak kaydet.

Sonuçlar `results.csv`'ye gider. Toplam 240 koşu var; her biri birkaç dakika sürerse deney saatler sürer, bu yüzden geceleri çalıştır ve script kaldığı yerden devam edebilsin.

### Metrikler (`experiments/metrics.py`)

Konfigürasyon × senaryo bazında: tespit oranı, ortalama ve medyan tespit süresi, ortalama ve medyan karantina süresi, yanlış pozitif sayısı. arpwatch aynı tabloda dördüncü sütun olarak yer alır (karantina yapmadığı için sadece tespit). Dashboard'un **Deney sonuçları** sayfası bu tabloyu ve grafikleri gösterir.

### LLM deneyi

1. **Veri kümesi:** 30–50 etiketli parmak izi JSON'u. Lab'dan canlı kayıtları al, `devices.yaml`'dan varyantlar üret: sadece portlar, hostname'siz, yanıltıcı hostname (ör. kameraya yazıcı adı).
2. **Karşılaştırma:** kurallar, LLM ve hibrit (kurallar `unknown` dediğinde LLM). Her biri için doğruluk, confusion matrix ve gecikme.
3. **Prompt injection:** bir rogue cihazın mDNS adına veya DHCP vendor class'ına talimat metni koy (vendor class 255 byte'a kadar yer verir). LLM'in etiketinin değişip değişmediğini ölç, raporda ayrı alt başlık olarak yaz.

## Takvim ve ara değerlendirme

19 Kasım'a kadar lab kurulumu, keşif, öğrenme modu ve bilinmeyen cihaz alarmı bitmeli. Karantina, SIEM, deney ve LLM işleri ara değerlendirmeden sonraya kalır.

&#91;embedded content: İş planı · 7 aşama, 19 Kasım ara değerlendirme\]

Deney koşuları saatler sürdüğü için 24–27 Kasım arasında gece çalıştırılır; LLM deneyi ana deneye bağlı değildir ve kayabilir.

### 19 Kasım kontrol listesi

- [ ] VM, köprüler ve router ayakta; cihazların clean snapshot'ları alınmış
- [ ] 6 cihaz farklı OUI, hostname, DHCP istemcisi, port ve mDNS ile çalışıyor
- [ ] Cihazlar arası parmak izi benzerlik tablosu (hocanın 1. maddesine cevap)
- [ ] Öğrenme modu envanteri oluşturuyor, `rg_approved` dolduruluyor
- [ ] Bilinmeyen container bağlanınca `unknown_device` alarmı ve `pending` durum
- [ ] Dashboard'da cihaz listesi ve alarmlar görünüyor (onay düğmeleri olmasa da olur)
- [ ] ATT&CK Enterprise eşleme tablosu (hocanın 2. maddesine cevap)
- [ ] LLM deneyi için plan slaytı (hocanın 3. maddesine cevap)
- [ ] İlk ölçüm: R1 için birkaç tekrarlık tespit süresi
