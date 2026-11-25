#!/usr/bin/env bash
# wazuh Incus container'ı içinde çalışır: wazuh_manager.conf'a UDP 514 syslog ekler,
# sertifikaları üretir, Wazuh single-node yığınını başlatır ve RogueGuard decoder/rule
# dosyalarını manager container'ına yükleyip yeniden başlatır.
set -euo pipefail

DIR=/opt/wazuh-docker/single-node
cd "$DIR"

CONF="$DIR/config/wazuh_cluster/wazuh_manager.conf"
if ! grep -q '<connection>syslog</connection>' "$CONF"; then
  python3 - "$CONF" <<'PY'
import sys
from pathlib import Path

p = Path(sys.argv[1])
s = p.read_text()
block = """  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>10.160.244.0/24</allowed-ips>
    <allowed-ips>172.16.0.0/12</allowed-ips>
  </remote>

</ossec_config>"""
assert "</ossec_config>" in s
p.write_text(s.replace("</ossec_config>", block, 1))
PY
  echo "Syslog <remote> bloğu eklendi."
fi

# Unprivileged Incus container içinde RLIMIT_MEMLOCK (-1) izin hatası verir; kaldır.
python3 - "$DIR/docker-compose.yml" <<'PY'
import re, sys
from pathlib import Path

p = Path(sys.argv[1])
s = p.read_text()
s2 = re.sub(r"\n      memlock:\n        soft: -1\n        hard: -1", "", s)
if s2 != s:
    p.write_text(s2)
    print("docker-compose.yml içinden memlock rlimit kaldırıldı.")
PY

if [ ! -f "$DIR/config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
  docker compose -f generate-indexer-certs.yml run --rm generator
fi

docker compose up -d

MGR=$(docker compose ps -q wazuh.manager)
# Manager ilk kurulumda /var/ossec/etc hacmini doldurana kadar kısa bekle
for _ in $(seq 1 30); do
  if docker exec "$MGR" test -d /var/ossec/etc/decoders; then
    break
  fi
  sleep 2
done

docker cp "$DIR/local_decoder.xml" "$MGR:/var/ossec/etc/decoders/local_decoder.xml"
docker cp "$DIR/local_rules.xml" "$MGR:/var/ossec/etc/rules/local_rules.xml"
docker exec "$MGR" chown wazuh:wazuh /var/ossec/etc/decoders/local_decoder.xml /var/ossec/etc/rules/local_rules.xml

docker compose restart wazuh.manager
docker compose ps
