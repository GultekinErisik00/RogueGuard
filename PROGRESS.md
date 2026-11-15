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

### Karşılaşılan sorunlar
- Mac'teki proje klasörünün git kökü yanlışlıkla ev dizini (`/Users/gultekinqwe`) çıktı → proje klasöründe ayrı `git init` yapıldı.
- İlk `ssh rogue` denemesi "No route to host" verdi; VM açıktı, birkaç saniye sonra düzeldi (Fusion NAT köprüsü geç ayağa kalktı).

### Sıradaki adım
Şifresiz sudo gelince: Adım 1 (lvextend, paketler, incus init, test container) → Adım 2 (köprüler, host nftables, rg-router).
