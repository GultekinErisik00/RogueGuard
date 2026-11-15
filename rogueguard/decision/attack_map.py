"""Tespit türü → MITRE ATT&CK Enterprise tekniği, önem ve uygulanacak aksiyon (CLAUDE.md §5).
Karar motoru alarm yazarken tek buradan okur; ICS matrisi kullanılmaz."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Attack:
    attack_id: str | None
    severity: str      # medium | high
    action: str        # pending | quarantine | block


ATTACKS: dict[str, Attack] = {
    "unknown_device":    Attack("T1200", "medium", "pending"),       # Hardware Additions
    "impersonation":     Attack("T1036", "high", "quarantine"),      # Masquerading
    "arp_spoofing":      Attack("T1557.002", "high", "quarantine"),  # ARP Cache Poisoning
    "abnormal_scan":     Attack("T1046", "high", "block"),           # Network Service Discovery
    "abnormal_behavior": Attack(None, "high", "block"),
}
