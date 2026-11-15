"""rg-router içindeki nftables setlerini yönetir (rg_approved, rg_block).
Komutlar `incus exec rg-router -- nft ...` ile çalışır. Router yeniden başlayınca setler
boşalır; sync() onları veritabanından yeniden doldurur."""
import ipaddress
import subprocess
from typing import Callable

Runner = Callable[[list[str]], str]


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


class Router:
    def __init__(self, cfg: dict, runner: Runner = _run) -> None:
        r = cfg["router"]
        self._container, self._table = r["container"], r["table"]
        self.approved_set, self.block_set = r["approved_set"], r["block_set"]
        self._run = runner

    def _nft(self, *args: str) -> str:
        return self._run(["incus", "exec", self._container, "--", "nft", *args])

    def add(self, set_name: str, ip: str) -> None:
        ip = str(ipaddress.ip_address(ip))   # enjeksiyona karşı: sadece geçerli IP
        self._nft("add", "element", *self._table.split(), set_name, f"{{ {ip} }}")

    def remove(self, set_name: str, ip: str) -> None:
        ip = str(ipaddress.ip_address(ip))
        self._nft("delete", "element", *self._table.split(), set_name, f"{{ {ip} }}")

    def flush(self, set_name: str) -> None:
        self._nft("flush", "set", *self._table.split(), set_name)

    def members(self, set_name: str) -> set[str]:
        out = self._nft("list", "set", *self._table.split(), set_name)
        return {tok.strip(",") for tok in out.split() if _is_ip(tok.strip(","))}

    def sync(self, approved_ips: list[str], blocked_ips: list[str] = ()) -> None:
        """Setleri veritabanındaki duruma eşitler (açılışta ve `sync` komutunda)."""
        for name, ips in ((self.approved_set, approved_ips), (self.block_set, blocked_ips)):
            self.flush(name)
            for ip in ips:
                self.add(name, ip)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False
