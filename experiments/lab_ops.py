"""7B: deney koşucusunun lab işlemleri (VM host'unda çalışır): container sıfırlama, rogue'u
ayağa kaldırma (MAC/hostname taklidi, ajan, arpspoof), dnsmasq rezervasyonu, rg_block boşaltma,
arpwatch günlüğü ve protect daemon'unu başlatıp durdurma. Sadece br-iot lab'ına dokunur.

Rogue tabanı: `rg-rogue` (images:fedora/43, nmap + dsniff + python ajanı), eth0 br-iot'ta ama
açılışta ağ yapılandırması yok (sessiz). `bringup` MAC'i içeriden ayarlayıp DHCP'yi başlatır;
böylece klon senaryolarında rogue kendi MAC'iyle hiç görünmez. Snapshot: `clean`."""
import json
import random
import shlex
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

ROGUE = "rg-rogue"
IOT_BRIDGE = "br-iot"
LEASES = "/var/lib/misc/dnsmasq.leases"
RESERVATION = "/etc/dnsmasq.d/zz-experiment.conf"
ROGUE_OUI = "10:66:6a"          # Incus'un kendi ürettiği MAC öneki (rogue'lar için)


def run(cmd: list[str], check: bool = True, timeout: float = 120) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                         stdin=subprocess.DEVNULL)   # incus stdin açıkken YAML bekleyip asılır
    if check and res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} → {res.returncode}: {res.stderr.strip()[:300]}")
    return res.stdout


def incus_exec(name: str, script: str, check: bool = True, timeout: float = 60) -> str:
    return run(["incus", "exec", name, "--", "sh", "-c", script], check=check, timeout=timeout)


def random_rogue_mac() -> str:
    return ROGUE_OUI + "".join(f":{random.randint(0, 255):02x}" for _ in range(3))


# --- Container durumu ------------------------------------------------------------------

def containers() -> dict[str, dict[str, Any]]:
    return {c["name"]: c for c in json.loads(run(["incus", "list", "--format", "json"]))}


def state(c: dict[str, Any]) -> dict[str, Any]:
    """{status, parent, ipv4}: container'ın çalışma durumu, eth0 köprüsü ve br-iot adresi."""
    eth0 = ((c.get("state") or {}).get("network") or {}).get("eth0") or {}
    ips = [a["address"] for a in eth0.get("addresses", []) if a["family"] == "inet"]
    return {"status": c["status"], "parent": c["expanded_devices"]["eth0"].get("parent"),
            "ipv4": ips[0] if ips else None}


def ensure_legit(names: list[str], timeout: float = 90) -> dict[str, str]:
    """Meşru cihazları çalışır ve br-iot'ta tutar (karantinadakini `clean` snapshot'a döndürür);
    hepsi IPv4 alana kadar bekler. {ad: ip} döndürür."""
    for name in names:
        st = state(containers()[name])
        if st["parent"] != IOT_BRIDGE:
            run(["incus", "stop", "-f", name], check=False)
            run(["incus", "snapshot", "restore", name, "clean"])
            st = state(containers()[name])
        if st["status"] != "Running":
            run(["incus", "start", name])
    end = time.time() + timeout
    while time.time() < end:
        now = {n: state(c) for n, c in containers().items() if n in names}
        if all(s["ipv4"] for s in now.values()):
            return {n: s["ipv4"] for n, s in now.items()}
        time.sleep(2)
    missing = [n for n, s in now.items() if not s["ipv4"]]
    raise RuntimeError(f"IPv4 alamayan meşru cihazlar: {missing}")


def quarantined(names: list[str]) -> list[str]:
    return [n for n, c in containers().items() if n in names and state(c)["parent"] != IOT_BRIDGE]


def restart(name: str) -> None:
    run(["incus", "restart", name], timeout=120)


def stop(name: str) -> None:
    run(["incus", "stop", "-f", name])


# --- Rogue -----------------------------------------------------------------------------

def rogue_reset() -> None:
    """Rogue'u durdurur ve `clean` snapshot'a döndürür (eth0 tekrar br-iot'ta, ağ kapalı)."""
    if ROGUE in containers():
        run(["incus", "stop", "-f", ROGUE], check=False)
        run(["incus", "snapshot", "restore", ROGUE, "clean"])


def rogue_start() -> None:
    run(["incus", "start", ROGUE])
    for _ in range(30):   # systemd ayağa kalkana kadar
        if incus_exec(ROGUE, "systemctl is-system-running 2>/dev/null; true").strip() in (
                "running", "degraded"):
            return
        time.sleep(1)


def rogue_bringup(mac: str, hostname: str | None = None) -> float:
    """MAC'i (ve istenirse hostname'i) içeriden ayarlar, DHCP'yi başlatır; t0'ı döndürür."""
    steps = []
    if hostname:
        steps.append(f"hostnamectl set-hostname {shlex.quote(hostname)}")
    steps += ["ip link set eth0 down", f"ip link set eth0 address {shlex.quote(mac)}",
              "ip link set eth0 up", "cp /opt/agent/eth0.network /etc/systemd/network/",
              "networkctl reload", "networkctl reconfigure eth0"]
    t0 = time.time()
    incus_exec(ROGUE, " && ".join(steps))
    return t0


def rogue_wait_ip(timeout: float = 30) -> str | None:
    end = time.time() + timeout
    while time.time() < end:
        out = incus_exec(ROGUE, "ip -4 -o addr show eth0", check=False)
        if "inet " in out:
            return out.split("inet ", 1)[1].split("/", 1)[0]
        time.sleep(1)
    return None


def rogue_start_agent(agent_profile: dict[str, Any], tmp_dir: Path) -> None:
    """Kurbanın port/banner/mDNS/MQTT profiliyle lab ajanını rogue içinde başlatır."""
    path = tmp_dir / "rogue-profile.json"
    path.write_text(json.dumps(agent_profile))
    run(["incus", "file", "push", "-q", str(path), f"{ROGUE}/opt/agent/profile.json"])
    incus_exec(ROGUE, "nohup python3 /opt/agent/device_agent.py </dev/null "
                      ">/tmp/agent.log 2>&1 &")


def rogue_arpspoof(target_ip: str, gateway_ip: str) -> None:
    incus_exec(ROGUE, f"nohup arpspoof -i eth0 -t {shlex.quote(target_ip)} "
                      f"{shlex.quote(gateway_ip)} </dev/null >/tmp/arpspoof.log 2>&1 &")


# --- Router (dnsmasq, nftables) --------------------------------------------------------

def lease_cleanup(leases: str, macs: list[str], ips: list[str] = ()) -> str:
    """Kira dosyasından verilen MAC'lerin ve IP'lerin satırlarını silen kabuk komutu.
    IP de silinir çünkü eski bir rogue kirası rezerve edilen adresi tutuyorsa dnsmasq
    rezervasyonu uygulamaz ("not using configured address ... leased to ...")."""
    if any(not k for k in [*macs, *ips]):
        raise ValueError("boş MAC/IP: sed '//d' tüm kira dosyasını hedefler")
    patterns = [m.lower() for m in macs] + [" " + ip.replace(".", r"\.") + " " for ip in ips]
    return " && ".join(f"sed -i '/{p}/d' {leases}" for p in patterns) or "true"


def dnsmasq_reserve(router: str, mac: str, ip: str) -> None:
    """Cihaza farklı bir IP rezerve eder (B2: meşru IP değişimi)."""
    deletes = lease_cleanup(LEASES, [mac], [ip])
    incus_exec(router, f"echo 'dhcp-host={mac},{ip}' > {RESERVATION} && "
                       f"systemctl stop dnsmasq && {deletes} && systemctl start dnsmasq")


def dnsmasq_clear(router: str, macs: list[str]) -> None:
    """Rezervasyonu ve verilen MAC'lerin kiralarını siler (cihaz eski adresine dönebilsin)."""
    incus_exec(router, f"rm -f {RESERVATION} && systemctl stop dnsmasq && "
                       f"{lease_cleanup(LEASES, macs)} && systemctl start dnsmasq")


def has_reservation(router: str) -> bool:
    return incus_exec(router, f"test -f {RESERVATION} && echo yes", check=False).strip() == "yes"


def flush_block(router: str, table: str, block_set: str) -> None:
    incus_exec(router, f"nft flush set {table} {block_set}")


def set_members(router: str, table: str, set_name: str) -> set[str]:
    out = incus_exec(router, f"nft -j list set {table} {set_name}")
    for obj in json.loads(out)["nftables"]:
        if "set" in obj:
            return {e if isinstance(e, str) else str(e) for e in obj["set"].get("elem", [])}
    return set()


# --- arpwatch --------------------------------------------------------------------------

def arpwatch_lines(since: float, unit: str = "arpwatch@br-iot") -> list[tuple[float, str]]:
    out = run(["sudo", "-n", "journalctl", "-u", unit, "--since", f"@{int(since) - 1}",
               "-o", "short-unix", "--no-pager", "-q"], check=False)
    lines = []
    for line in out.splitlines():
        head, _, rest = line.partition(" ")
        try:
            lines.append((float(head), rest))
        except ValueError:
            continue
    return lines


# --- protect daemon --------------------------------------------------------------------

class Daemon:
    """`sudo python -m rogueguard protect --profile P --db D` alt sürecini yönetir."""

    def __init__(self, root: Path, python: str = ".venv/bin/python") -> None:
        self._root = root
        self._python = python
        self._proc: subprocess.Popen | None = None
        self._log = None

    def start(self, profile: str, db_path: Path, log_path: Path) -> None:
        self._log = log_path.open("a")
        self._proc = subprocess.Popen(
            ["sudo", "-n", self._python, "-m", "rogueguard", "protect",
             "--profile", profile, "--db", str(db_path)],
            cwd=self._root, stdout=self._log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)

    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def stop(self, timeout: float = 15) -> None:
        """Önce SIGINT (temiz kapanış), olmazsa SIGTERM, en son SIGKILL. sudo sinyali iletir."""
        if self._proc is None:
            return
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
            if self._proc.poll() is not None:
                break
            self._proc.send_signal(sig)
            try:
                self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                continue
        self._proc = None
        kill_stray()   # SIGKILL sadece sudo'yu öldürür; root'taki çocuk kalmış olabilir
        if self._log:
            self._log.close()
            self._log = None


def kill_stray() -> None:
    """Önceki (çökmüş) koşudan kalan protect süreçlerini kapatır. Desen sadece deney
    koşucusunun başlattığı `--profile`'lı komut satırıyla eşleşir."""
    run(["sudo", "-n", "pkill", "-INT", "-f", "rogueguard protect --profile"], check=False)
    time.sleep(1)
    run(["sudo", "-n", "pkill", "-9", "-f", "rogueguard protect --profile"], check=False)
