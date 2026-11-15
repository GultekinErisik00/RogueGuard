#!/bin/sh
# Container içinde (incusbr0'dayken, internet varken) bir kez çalışır:
# paketler + venv, hostname, profildeki DHCP istemcisi ve ajan servisi.
# Değerler /opt/agent/profile.env'den gelir (build_lab.py yazar).
# Ağ değişiklikleri sadece bir sonraki açılışta (br-iot'ta) devreye girer.
set -eu
. /opt/agent/profile.env      # DEV_NAME DEV_HOSTNAME DHCP_CLIENT VENDOR_CLASS UDHCPC_EXTRA

if [ -f /etc/alpine-release ]; then OS=alpine; else OS=debian; fi

# --- 1. Paketler ve Python ortamı --------------------------------------------
if [ "$OS" = alpine ]; then
  apk add --no-cache python3 py3-pip >/dev/null
else
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q >/dev/null
  case "$DHCP_CLIENT" in
    dhclient) EXTRA=isc-dhcp-client ;;
    dhcpcd)   EXTRA=dhcpcd-base ;;
    *)        EXTRA= ;;
  esac
  apt-get install -y -q python3-venv $EXTRA >/dev/null
fi
python3 -m venv /opt/agent/venv
/opt/agent/venv/bin/pip install -q --disable-pip-version-check zeroconf paho-mqtt

# --- 2. Hostname --------------------------------------------------------------
echo "$DEV_HOSTNAME" > /etc/hostname

# --- 3. DHCP istemcisi ---------------------------------------------------------
case "$DHCP_CLIENT" in
  udhcpc)
    # İmajdaki dhcpcd'yi kaldır, eth0'ı ifupdown'dan çıkar; udhcpc'yi local.d başlatır.
    apk del -q dhcpcd 2>/dev/null || true
    printf 'auto lo\niface lo inet loopback\n' > /etc/network/interfaces
    OPTS=""
    for o in $UDHCPC_EXTRA; do OPTS="$OPTS -O $o"; done
    cat > /etc/local.d/10-dhcp.start <<EOF
#!/bin/sh
ip link set eth0 up
udhcpc -i eth0 -b -x hostname:$DEV_HOSTNAME -V "$VENDOR_CLASS"$OPTS
EOF
    chmod +x /etc/local.d/10-dhcp.start
    rc-update add local default >/dev/null
    ;;
  dhclient)
    rm -f /etc/systemd/network/eth0.network
    cat > /etc/dhcp/dhclient.conf <<EOF
send host-name "$DEV_HOSTNAME";
send vendor-class-identifier "$VENDOR_CLASS";
request subnet-mask, broadcast-address, routers, domain-name-servers, domain-name, ntp-servers;
EOF
    cat > /etc/systemd/system/rg-dhcp.service <<EOF
[Unit]
Description=Lab DHCP client (dhclient)
Before=network-online.target
[Service]
ExecStart=/sbin/dhclient -d -4 eth0
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl enable rg-dhcp.service >/dev/null 2>&1
    ;;
  dhcpcd)
    rm -f /etc/systemd/network/eth0.network
    cat > /etc/dhcpcd.conf <<EOF
hostname $DEV_HOSTNAME
vendorclassid $VENDOR_CLASS
option domain_name_servers, domain_name, routers, ntp_servers
ipv4only
EOF
    cat > /etc/systemd/system/rg-dhcp.service <<EOF
[Unit]
Description=Lab DHCP client (dhcpcd)
Before=network-online.target
[Service]
ExecStart=/usr/sbin/dhcpcd -B -4 eth0
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl enable rg-dhcp.service >/dev/null 2>&1
    ;;
  systemd-networkd)
    rm -f /etc/netplan/*.yaml
    cat > /etc/systemd/network/10-eth0.network <<EOF
[Match]
Name=eth0

[Network]
DHCP=ipv4

[DHCPv4]
Hostname=$DEV_HOSTNAME
VendorClassIdentifier=$VENDOR_CLASS
EOF
    systemctl enable systemd-networkd >/dev/null 2>&1
    ;;
esac

# --- 4. Ajan servisi -----------------------------------------------------------
if [ "$OS" = alpine ]; then
  cat > /etc/init.d/rg-agent <<'EOF'
#!/sbin/openrc-run
description="Lab IoT device agent"
command=/opt/agent/venv/bin/python
command_args=/opt/agent/device_agent.py
supervisor=supervise-daemon
respawn_delay=3
output_log=/var/log/rg-agent.log
error_log=/var/log/rg-agent.log
depend() { after local; }
EOF
  chmod +x /etc/init.d/rg-agent
  rc-update add rg-agent default >/dev/null
else
  cat > /etc/systemd/system/rg-agent.service <<'EOF'
[Unit]
Description=Lab IoT device agent
After=network.target
[Service]
ExecStart=/opt/agent/venv/bin/python /opt/agent/device_agent.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
  systemctl enable rg-agent.service >/dev/null 2>&1
fi
echo "SETUP_OK $DEV_NAME"
