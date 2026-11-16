"""Bir cihazı karantina köprüsüne (br-quar) taşır. L2 saldırıları (ARP spoofing, MAC taklidi)
router'dan geçmediği için nftables ile durdurulamaz; container'ın eth0'ı br-iot'tan ayrılır.
Container, `incus list` çıktısındaki MAC'ten bulunur."""
import json
import subprocess
from typing import Callable

Runner = Callable[[list[str]], str]


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def _state_eth0(container: dict) -> dict:
    return ((container.get("state") or {}).get("network") or {}).get("eth0", {})


def _macs(container: dict) -> set[str]:
    """Container'ın eth0 MAC'leri: Incus yapılandırmasındaki ve o an arayüzde görünen.
    Saldırgan MAC'i container içinden değiştirirse (`ip link set address`) ikisi farklıdır."""
    eth0 = container.get("expanded_devices", {}).get("eth0", {})
    found = {eth0.get("hwaddr"), container.get("config", {}).get("volatile.eth0.hwaddr"),
             _state_eth0(container).get("hwaddr")}
    return {m.lower() for m in found if m}


def _ipv4(container: dict) -> str | None:
    return next((a["address"] for a in _state_eth0(container).get("addresses", [])
                 if a["family"] == "inet"), None)


def pick_container(containers: list[dict], mac: str, iot_bridge: str,
                   inventory_ip: str | None) -> str | None:
    """MAC'i taşıyan, br-iot'ta çalışan container'ın adı. Aynı MAC'li iki container varsa
    (MAC taklidi) envanterle uyuşmayan seçilir: IP'si envanterdeki IP olmayan; IP'ler de
    aynıysa en son oluşturulan (envantere öğrenme anında giren cihaz daha eskidir)."""
    matches = [c for c in containers
               if mac.lower() in _macs(c) and c.get("status") == "Running"
               and c["expanded_devices"]["eth0"].get("parent") == iot_bridge]
    if len(matches) > 1:
        odd = [c for c in matches if _ipv4(c) != inventory_ip]
        matches = odd if len(odd) == 1 else sorted(matches, key=lambda c: c["created_at"])[-1:]
    return matches[0]["name"] if matches else None


class Quarantine:
    def __init__(self, cfg: dict, runner: Runner = _run) -> None:
        self._iot = cfg["network"]["iot_iface"]
        self._quar = cfg["containment"]["quarantine_bridge"]
        self._run = runner

    def isolate(self, mac: str, inventory_ip: str | None) -> str | None:
        """Cihazı br-quar'a taşır; taşınan container'ın adını (bulunamazsa None) döndürür."""
        containers = json.loads(self._run(["incus", "list", "--format", "json"]))
        name = pick_container(containers, mac, self._iot, inventory_ip)
        if name:
            self._run(["incus", "config", "device", "set", name, "eth0", f"parent={self._quar}"])
        return name
