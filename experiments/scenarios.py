"""7B: 8 deney senaryosu. Her fonksiyon senaryoyu lab'da başlatır ve ölçüt tanımını
(Expectation), t0'ı (saldırının/olayın başladığı an) ve bekleme kuralını döndürür.

R1 kendi MAC'iyle rogue · R2 kurbanın MAC'i (kurban kapalı) · R3 R2 + hostname, port, mDNS,
MQTT taklidi · R4 R3 + başka bir cihaza `arpspoof` (ağ geçidi taklidi) · B1 meşru restart ·
B2 meşru IP değişimi (dnsmasq rezervasyonu) · B3 yeni meşru cihaz + dashboard onayı ·
B4 sessiz izleme. Kurban, tekrar numarasına göre 5 farklı cihaz arasında döner (cam-02, cam-01'in
ikizi olduğu için kurban seçilmez)."""
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from experiments import lab_ops
from experiments.outcome import Expectation

SCENARIOS = ("R1", "R2", "R3", "R4", "B1", "B2", "B3", "B4")
VICTIMS = ("cam-01", "printer-01", "plug-01", "temp-01", "thermo-01")
ROGUE_TIMEOUT = 60       # sn: rogue senaryolarında tespit için en uzun bekleme
BENIGN_WINDOW = 90       # sn: B senaryolarında yanlış pozitif gözlem penceresi
SILENT_WINDOW = 120      # sn: B4
SPARE_IPS = [f"10.20.0.{n}" for n in range(190, 200)]   # B2 için rezerve edilecek adresler


@dataclass
class Ctx:
    rep: int
    devices: dict[str, dict[str, Any]]          # lab/devices.yaml cihazları
    ips: dict[str, str]                         # koşu başındaki canlı IP'ler
    cfg: dict[str, Any]
    tmp: Path
    approve: Callable[[str], None]              # dashboard "Onayla" düğmesinin yaptığı yazma
    approval_applied: Callable[[str], float | None]
    alert_types: Callable[[str], set[str]]      # MAC için yazılmış alarm türleri

    @property
    def victim(self) -> str:
        return VICTIMS[self.rep % len(VICTIMS)]

    @property
    def other(self) -> str:
        return VICTIMS[(self.rep + 1) % len(VICTIMS)]

    @property
    def router(self) -> str:
        return self.cfg["router"]["container"]


@dataclass
class Started:
    expectation: Expectation
    t0: float
    wait: str                                   # "until_detected" | "window"
    window: float
    extra: dict[str, Any] = field(default_factory=dict)


def _agent_profile(name: str, dev: dict[str, Any], broker: dict[str, Any]) -> dict[str, Any]:
    keys = ("hostname", "vendor_class", "services", "mdns", "mqtt")
    return {"name": name, **{k: dev[k] for k in keys}, "broker": broker}


def _rogue(ctx: Ctx, mac: str, hostname: str | None) -> float:
    lab_ops.rogue_start()
    t0 = lab_ops.rogue_bringup(mac, hostname)
    lab_ops.rogue_wait_ip()
    return t0


def r1(ctx: Ctx) -> Started:
    mac = lab_ops.random_rogue_mac()
    t0 = _rogue(ctx, mac, None)
    return Started(Expectation(mac, frozenset({"unknown_device"})), t0, "until_detected",
                   ROGUE_TIMEOUT, {"victim": "", "rogue_mac": mac})


def r2(ctx: Ctx, clone_identity: bool = False, spoof: bool = False) -> Started:
    dev = ctx.devices[ctx.victim]
    mac = dev["mac"].lower()
    lab_ops.stop(ctx.victim)
    t0 = _rogue(ctx, mac, dev["hostname"] if clone_identity else None)
    if clone_identity:
        broker = {"ip": ctx.cfg["network"]["broker_ip"], "port": 1883}
        lab_ops.rogue_start_agent(_agent_profile(ctx.victim, dev, broker), ctx.tmp)
    expected = {"impersonation"}
    extra = {"victim": ctx.victim, "rogue_mac": mac}
    if spoof:
        lab_ops.rogue_arpspoof(ctx.ips[ctx.other], ctx.cfg["network"]["iot_gw_ip"])
        expected.add("arp_spoofing")
        extra["spoof_target"] = ctx.other
    return Started(Expectation(mac, frozenset(expected)), t0, "until_detected",
                   ROGUE_TIMEOUT, extra)


def r3(ctx: Ctx) -> Started:
    return r2(ctx, clone_identity=True)


def r4(ctx: Ctx) -> Started:
    return r2(ctx, clone_identity=True, spoof=True)


def b1(ctx: Ctx) -> Started:
    t0 = time.time()
    lab_ops.restart(ctx.victim)
    return Started(Expectation(None), t0, "window", BENIGN_WINDOW, {"victim": ctx.victim})


def b2(ctx: Ctx) -> Started:
    dev = ctx.devices[ctx.victim]
    new_ip = next(ip for ip in SPARE_IPS if ip not in ctx.ips.values())
    t0 = time.time()
    lab_ops.dnsmasq_reserve(ctx.router, dev["mac"].lower(), new_ip)
    lab_ops.restart(ctx.victim)
    return Started(Expectation(None), t0, "window", BENIGN_WINDOW,
                   {"victim": ctx.victim, "new_ip": new_ip, "old_ip": ctx.ips[ctx.victim]})


def b3(ctx: Ctx) -> Started:
    """Yeni meşru cihaz: unknown_device alarmı beklenir (yanlış pozitif sayılmaz); alarm gelince
    dashboard'un yaptığı gibi `approvals`'a onay yazılır ve daemon'un uygulaması ölçülür."""
    mac = lab_ops.random_rogue_mac()
    t0 = _rogue(ctx, mac, f"newcam-{mac[-5:].replace(':', '')}")
    end = t0 + ROGUE_TIMEOUT
    while time.time() < end and "unknown_device" not in ctx.alert_types(mac):
        time.sleep(0.5)
    approved_at = None
    if "unknown_device" in ctx.alert_types(mac):
        asked = time.time()
        ctx.approve(mac)
        while time.time() < asked + 20 and approved_at is None:
            time.sleep(0.5)
            approved_at = ctx.approval_applied(mac)
        if approved_at:
            approved_at -= asked
    return Started(Expectation(mac, frozenset({"unknown_device"})), t0, "window", 30,
                   {"victim": "", "rogue_mac": mac,
                    "approve_s": round(approved_at, 3) if approved_at else None})


def b4(ctx: Ctx) -> Started:
    return Started(Expectation(None), time.time(), "window", SILENT_WINDOW, {"victim": ""})


RUNNERS: dict[str, Callable[[Ctx], Started]] = {
    "R1": r1, "R2": r2, "R3": r3, "R4": r4, "B1": b1, "B2": b2, "B3": b3, "B4": b4,
}
