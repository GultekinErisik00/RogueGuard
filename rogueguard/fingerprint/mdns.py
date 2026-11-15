"""mDNS cevaplarından servis türlerini, örnek adlarını ve hostname'i çıkarır."""
from typing import Any

PTR, SRV, A = 12, 33, 1


def _name(value: Any) -> str:
    text = value.decode(errors="replace") if isinstance(value, bytes) else str(value)
    return text.rstrip(".")


def parse_records(records: list[tuple[int, Any, Any]]) -> dict[str, Any]:
    """[(rtype, rrname, rdata)] → {services: [tür], instances: [ad], hostname}.

    DNS-SD meta türü (_services._dns-sd._udp) servis listesi olarak sayılmaz.
    """
    services: set[str] = set()
    instances: set[str] = set()
    hostname = None
    for rtype, rrname, rdata in records:
        name = _name(rrname)
        if rtype == PTR and not name.startswith("_services._dns-sd"):
            services.add(name.removesuffix(".local"))
            instances.add(_name(rdata))
        elif rtype == SRV:
            target = getattr(rdata, "target", None) or rdata
            hostname = _name(target).removesuffix(".local")
        elif rtype == A and hostname is None:
            hostname = name.removesuffix(".local")
    return {"services": sorted(services), "instances": sorted(instances), "hostname": hostname}


def records_from_dns(dns: Any) -> list[tuple[int, Any, Any]]:
    """scapy DNS katmanının answer + additional bölümlerini düz listeye çevirir."""
    out: list[tuple[int, Any, Any]] = []
    for section in (dns.an, dns.ar):
        if section is None:
            continue
        items = section if isinstance(section, list) else _walk(section)
        for rr in items:
            rdata = rr if rr.type == SRV else getattr(rr, "rdata", None)
            out.append((rr.type, rr.rrname, rdata))
    return out


def _walk(rr: Any) -> list[Any]:
    """Eski scapy sürümlerinde kayıtlar payload zinciridir."""
    items = []
    while rr is not None and hasattr(rr, "type"):
        items.append(rr)
        rr = rr.payload if rr.payload else None
    return items
