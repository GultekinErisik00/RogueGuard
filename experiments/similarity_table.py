"""Öğrenilmiş envanterden (inventory.yaml) meşru cihazların ikili benzerlik matrisini
Markdown tablosu olarak basar. notes/Benzerlik Tablosu.md bu çıktıyla güncellenir.
Kullanım (VM'de): .venv/bin/python -m experiments.similarity_table"""
import yaml

from rogueguard import config
from rogueguard.fingerprint import compare


def main() -> None:
    cfg = config.load()
    weights = cfg["fingerprint"]["weights"]
    names = {s["mac"].lower(): n for n, s in yaml.safe_load(
        (config.ROOT / "lab/devices.yaml").read_text())["devices"].items()}
    inv = yaml.safe_load((config.ROOT / cfg["learn"]["inventory_path"]).read_text())["devices"]
    profs = {names[p["mac"]]: p for p in inv if p["mac"] in names}
    order = sorted(profs)

    print("| | " + " | ".join(order) + " |")
    print("|---" * (len(order) + 1) + "|")
    for a in order:
        cells = ["—" if a == b else f"{compare.similarity(profs[a], profs[b], weights):.2f}"
                 for b in order]
        print(f"| **{a}** | " + " | ".join(cells) + " |")

    print("\n| Cihaz | OUI | option 55 | Portlar | mDNS | Yayın aralığı (sn) |")
    print("|---|---|---|---|---|---|")
    for n in order:
        p = profs[n]
        interval = f"{p['interval']:.0f}" if p["interval"] else "—"
        print(f"| {n} | `{p['oui']}` | `{p['opt55']}` | {', '.join(p['ports']) or '—'} | "
              f"{', '.join(p['mdns']) or '—'} | {interval} |")


if __name__ == "__main__":
    main()
