"""nmap ile açık port ve servis bannerı çıkarır (`nmap -sT -sV -oX -`).
Sadece lab alt ağındaki (br-iot) adreslere izin verir; dışarı tarama yapmaz."""
import ipaddress
import subprocess
import xml.etree.ElementTree as ET

# Hızlı ama lab cihazlarının kullandığı yüksek portları (UPnP 49153) da kapsar.
NMAP_PORTS = "1-10000,49152-49160"


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """nmap XML çıktısından açık portları [{port, proto, service, banner}] olarak okur."""
    ports = []
    for p in ET.fromstring(xml_text).iterfind(".//port"):
        state = p.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = p.find("service")
        attrs = svc.attrib if svc is not None else {}
        banner = " ".join(x for x in (attrs.get("product"), attrs.get("version"),
                                      attrs.get("extrainfo")) if x)
        ports.append({"port": int(p.get("portid")), "proto": p.get("protocol"),
                      "service": attrs.get("name", "unknown"), "banner": banner})
    return sorted(ports, key=lambda d: (d["proto"], d["port"]))


def scan(ip: str, lab_subnet: str, timeout: int = 300) -> list[dict]:
    if ipaddress.ip_address(ip) not in ipaddress.ip_network(lab_subnet):
        raise ValueError(f"{ip} lab alt ağı ({lab_subnet}) dışında, taranmaz")
    out = subprocess.run(["nmap", "-sT", "-sV", "--version-light", "-Pn", "-p", NMAP_PORTS,
                          "-oX", "-", ip], capture_output=True, text=True,
                         timeout=timeout, check=True)
    return parse_nmap_xml(out.stdout)
