#!/bin/sh
# 7B deneylerinin rogue tabanı `rg-rogue`: images:fedora/43 (meşru cihazlarda kullanılmayan imaj),
# nmap + dsniff (arpspoof) + lab ajanı. eth0 br-iot'ta ama açılışta ağ yapılandırması YOK:
# experiments/lab_ops.py:rogue_bringup MAC'i içeriden ayarlayıp DHCP'yi başlatır, böylece klon
# senaryolarında rogue kendi MAC'iyle hiç görünmez. Sonunda `clean` snapshot alınır.
# VM host'unda, ~/rogueguard içinde çalıştır: sh lab/build_rogue.sh
set -eu
NAME=rg-rogue
incus info "$NAME" >/dev/null 2>&1 && { echo "$NAME zaten var"; exit 0; }

incus launch images:fedora/43 "$NAME" < /dev/null           # önce incusbr0'da (internet için)
for i in $(seq 1 60); do
  incus exec "$NAME" -- ping -c1 -W1 1.1.1.1 >/dev/null 2>&1 && break; sleep 1
done
incus exec "$NAME" -- dnf -y -q install python3 python3-pip nmap dsniff iproute procps-ng iputils < /dev/null
incus exec "$NAME" -- pip3 install -q zeroconf paho-mqtt < /dev/null
incus exec "$NAME" -- mkdir -p /opt/agent
incus file push -q lab/agent/device_agent.py "$NAME"/opt/agent/device_agent.py

# systemd-networkd'nin eth0 dosyasını kenara al (sessiz açılış), IPv6'yı kapat, ip_forward aç.
incus exec "$NAME" -- mv /etc/systemd/network/eth0.network /opt/agent/eth0.network
incus exec "$NAME" -- sh -c 'printf "net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\nnet.ipv4.ip_forward=1\n" > /etc/sysctl.d/99-rogue.conf'

incus stop "$NAME"
incus config device add "$NAME" eth0 nic nictype=bridged parent=br-iot
incus snapshot create "$NAME" clean
echo "$NAME hazır (durdurulmuş, snapshot 'clean')"
