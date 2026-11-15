"""DHCP parmak izi: scapy'nin DHCP option listesinden option 12, 53, 55, 60, 61, 50'yi çıkarır."""
from typing import Any

MSG_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline",
             5: "ack", 6: "nak", 7: "release", 8: "inform"}


def _text(value: Any) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)


def parse_options(options: list) -> dict[str, Any]:
    """scapy `pkt[DHCP].options` → {msg_type, hostname, vendor_class, param_req_list, client_id, requested_addr}."""
    out: dict[str, Any] = {}
    for opt in options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue  # 'end', 'pad'
        key, value = opt[0], opt[1]
        if key == "message-type":
            out["msg_type"] = MSG_TYPES.get(value, str(value))
        elif key == "hostname":
            out["hostname"] = _text(value)
        elif key == "vendor_class_id":
            out["vendor_class"] = _text(value)
        elif key == "param_req_list":
            out["param_req_list"] = list(value) if isinstance(value, (list, tuple, bytes)) else [value]
        elif key == "client_id":
            out["client_id"] = value.hex() if isinstance(value, bytes) else _text(value)
        elif key == "requested_addr":
            out["requested_addr"] = str(value)
    return out


def fingerprint(parsed: dict[str, Any]) -> dict[str, Any]:
    """Karşılaştırmada kullanılan kararlı alanlar (msg_type ve IP hariç)."""
    return {k: parsed[k] for k in ("hostname", "vendor_class", "param_req_list", "client_id")
            if k in parsed}
