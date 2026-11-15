"""MQTT yayınlarını rg-router'ın br-iot ayağında (eth1) yakalar. Host'un br-iot arayüzü
cihaz→router unicast trafiğini görmez (köprü bu çerçeveleri host'a iletmez); router ise
hepsini görür. Router'da `tcpdump` çalıştırılır, satırlar ayrıştırılıp geri çağrılır."""
import logging
import re
import subprocess
import threading
from typing import Callable

log = logging.getLogger("rogueguard.discovery")

# Sadece MQTT PUBLISH (sabit başlık tipi 3 → ilk bayt 0x3?). PINGREQ vb. sayılmaz.
BPF = ("tcp dst port 1883 and "
       "(tcp[((tcp[12:1] & 0xf0) >> 2):1] & 0xf0) = 0x30")
LINE = re.compile(r"^(?P<ts>\d+\.\d+) (?P<mac>[0-9a-f:]{17}) > [0-9a-f:]{17}, .*?: "
                  r"(?P<src>\d+\.\d+\.\d+\.\d+)\.\d+ > (?P<dst>\d+\.\d+\.\d+\.\d+)\.(?P<port>\d+):")

PublishHook = Callable[[float, str, str, str, int], None]


def parse_line(line: str) -> tuple[float, str, str, str, int] | None:
    m = LINE.match(line)
    if not m:
        return None
    return float(m["ts"]), m["mac"], m["src"], m["dst"], int(m["port"])


class RouterTap:
    def __init__(self, cfg: dict, on_publish: PublishHook) -> None:
        self._cmd = ["incus", "exec", cfg["router"]["container"], "--",
                     "tcpdump", "-l", "-n", "-e", "-tt", "-i", "eth1", BPF]
        self._on_publish = on_publish
        self._proc: subprocess.Popen | None = None
        self._thread = threading.Thread(target=self._run, name="router-tap", daemon=True)

    def start(self) -> None:
        self._proc = subprocess.Popen(self._cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True)
        self._thread.start()

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._thread.join(timeout=5)

    def _run(self) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            parsed = parse_line(line)
            if parsed:
                self._on_publish(*parsed)
        log.info("router-tap kapandı (çıkış kodu %s)", self._proc.poll())
