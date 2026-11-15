"""lab/devices.yaml'daki her meşru cihazı Incus container'ı olarak kurar (VM host'unda çalışır).

Sıra (CLAUDE.md §6): incusbr0'da başlat → ajanı ve profili it → setup.sh → durdur →
eth0'ı br-iot'a (profildeki MAC ile) taşı → başlat → 'clean' snapshot al.
Var olan container atlanır; yeniden kurmak için: build_lab.py --rebuild cam-01
"""
import argparse
import json
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

LAB = Path(__file__).resolve().parent
IOT_BRIDGE = "br-iot"


def sh(*args: str, check: bool = True) -> str:
    """incus komutunu çalıştır, stdout döndür; hata olursa çıktıyla birlikte dur."""
    res = subprocess.run(args, capture_output=True, text=True)
    if check and res.returncode != 0:
        sys.exit(f"HATA: {' '.join(args)}\n{res.stdout}{res.stderr}")
    return res.stdout


def exists(name: str) -> bool:
    return subprocess.run(["incus", "info", name], capture_output=True).returncode == 0


def wait_for_internet(name: str, timeout: int = 60) -> None:
    for _ in range(timeout):
        if subprocess.run(["incus", "exec", name, "--", "ping", "-c1", "-W1", "1.1.1.1"],
                          capture_output=True).returncode == 0:
            return
        time.sleep(1)
    sys.exit(f"HATA: {name} incusbr0 üzerinden internete çıkamadı")


def profile_files(name: str, dev: dict, broker: dict, tmp: Path) -> None:
    """Ajanın okuyacağı profile.json ve setup.sh'ın okuyacağı profile.env dosyalarını yaz."""
    agent_profile = {
        "name": name,
        "hostname": dev["hostname"],
        "vendor_class": dev["vendor_class"],
        "services": dev["services"],
        "mdns": dev["mdns"],
        "mqtt": dev["mqtt"],
        "broker": broker,
    }
    (tmp / "profile.json").write_text(json.dumps(agent_profile, indent=2))
    env = {
        "DEV_NAME": name,
        "DEV_HOSTNAME": dev["hostname"],
        "DHCP_CLIENT": dev["dhcp_client"],
        "VENDOR_CLASS": dev["vendor_class"],
        "UDHCPC_EXTRA": " ".join(dev.get("udhcpc_extra", [])),
    }
    (tmp / "profile.env").write_text("".join(f"{k}={shlex.quote(v)}\n" for k, v in env.items()))


def build(name: str, dev: dict, broker: dict) -> None:
    print(f"[{name}] {dev['image']} başlatılıyor (incusbr0)")
    sh("incus", "launch", dev["image"], name)
    wait_for_internet(name)
    sh("incus", "exec", name, "--", "mkdir", "-p", "/opt/agent")
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        profile_files(name, dev, broker, tmp)
        for f in [LAB / "agent" / "device_agent.py", LAB / "agent" / "setup.sh",
                  tmp / "profile.json", tmp / "profile.env"]:
            sh("incus", "file", "push", "-q", str(f), f"{name}/opt/agent/{f.name}")
    print(f"[{name}] setup.sh ({dev['dhcp_client']})")
    print(sh("incus", "exec", name, "--", "sh", "/opt/agent/setup.sh").strip())
    sh("incus", "stop", name)
    sh("incus", "config", "device", "add", name, "eth0", "nic",
       "nictype=bridged", f"parent={IOT_BRIDGE}", f"hwaddr={dev['mac']}")
    sh("incus", "start", name)
    sh("incus", "snapshot", "create", name, "clean")
    print(f"[{name}] hazır: {IOT_BRIDGE}, {dev['mac']}, snapshot 'clean'")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("names", nargs="*", help="sadece bu cihazlar (varsayılan: hepsi)")
    ap.add_argument("--rebuild", action="store_true", help="var olan container'ı silip yeniden kur")
    args = ap.parse_args()

    cfg = yaml.safe_load((LAB / "devices.yaml").read_text())
    for name, dev in cfg["devices"].items():
        if args.names and name not in args.names:
            continue
        if exists(name):
            if not args.rebuild:
                print(f"[{name}] zaten var, atlandı")
                continue
            sh("incus", "delete", "-f", name)
        build(name, dev, cfg["broker"])


if __name__ == "__main__":
    main()
