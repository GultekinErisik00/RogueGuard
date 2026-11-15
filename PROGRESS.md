# RogueGuard — İlerleme

## Oturum 1 — 15 Kasım 2026

### Durum
- [x] VM ayakta: `rogueguard-lab`, Ubuntu 26.10, 4 çekirdek, 9.2 GiB RAM, `enp2s0` = 192.168.23.136/24 (Fusion NAT 192.168.23.0/24)
- [x] `ssh rogue` çalışıyor
- [ ] Şifresiz sudo **yok** → kullanıcıdan `/etc/sudoers.d/rogue` istendi
- [ ] Kök bölüm 28 GB (LVM'de boş alan var, `lvextend` bekliyor, sudo gerekli)
- [x] Swap: kurulumdan gelen 4 GB `/swap.img` var → ayrı `/swapfile` gerekmiyor
- [x] `vm.max_map_count` zaten 1048576 (≥ 262144) → `90-wazuh.conf` gerekmiyor
- Kurulu: tcpdump, tmux, rsync, git, python3. Eksik: incus (apt aday 7.0.1), nmap, arpwatch, python3-venv
- Snap paketi yok (iyi; LXD/snap kurulmayacak)

### Seçilen değerler (§3)
| Yer tutucu | Değer |
| --- | --- |
| `<VM_IP>` | 192.168.23.136 (DHCP; değişirse `~/.ssh/config` güncellenir) |
| `<IOT_SUBNET>` | 10.20.0.0/24 |
| `<IOT_GW_IP>` | 10.20.0.1 |
| `<SENSOR_IOT_IP>` | 10.20.0.2 |
| `<IOT_DHCP_START>`–`<IOT_DHCP_END>` | 10.20.0.100–10.20.0.199 |
| `<QUAR_SUBNET>` / GW / DHCP | 10.20.1.0/24, 10.20.1.1, .100–.199 |
| `<SVC_SUBNET>` / GW / DHCP | 10.20.2.0/24, 10.20.2.1, .100–.199 |
| `<BROKER_MAC>` / `<BROKER_IP>` | 00:16:3e:20:02:10 / 10.20.2.10 |
| `<WAZUH_IP>` | Adım 4'te (incusbr0 subnet'i belli olunca) |

### Adım 1 ilerlemesi
- [x] Şifresiz sudo (`/etc/sudoers.d/rogue`, kullanıcı ekledi)
- [x] `lvextend -r` → `/` 56 GB
- [x] apt upgrade; incus 7.0.1, nmap, arpwatch, python3-venv, dsniff kuruldu
- [x] `rogue` → `incus-admin`; `incus admin init --minimal` → `incusbr0` = 10.160.244.1/24 (lab subnet'leriyle çakışmıyor), storage `default` (dir)
- [ ] **Kontrol takıldı:** `images:debian/13` container'ı IP almıyor (aşağıya bak). `images:alpine` container'ı internete ping atabiliyor → NAT/ağ sağlam.

### Karşılaşılan sorunlar
- **systemd'li container'lar açılışta takılıyor (Ubuntu 26.10 host).** Debian 13 container'ında journald/networkd/resolved `(sd-mkuser...)` adımında asılı kalıyor, `eth0` IP almıyor; host dmesg'de `incus-<ad>` profili için AppArmor ptrace DENIED satırları. Neden: Ubuntu'ya özgü AppArmor kısıtı `kernel.apparmor_restrict_unprivileged_unconfined=1` (ve `..._userns=1`). Incus geliştiricisinin önerdiği çözüm bu sysctl'i 0 yapmak (lxc/incus#3251; Zabbly paketleri bunu artık otomatik yapıyor, Ubuntu'nun incus paketi yapmıyor). Host güvenlik ayarı olduğu için kullanıcı onayıyla uygulanacak.
- Mac'teki proje klasörünün git kökü yanlışlıkla ev dizini (`/Users/gultekinqwe`) çıktı → proje klasöründe ayrı `git init` yapıldı.
- İlk `ssh rogue` denemesi "No route to host" verdi; VM açıktı, birkaç saniye sonra düzeldi (Fusion NAT köprüsü geç ayağa kalktı).

### Sıradaki adım
Şifresiz sudo gelince: Adım 1 (lvextend, paketler, incus init, test container) → Adım 2 (köprüler, host nftables, rg-router).
