"""RogueGuard komut satırı: python -m rogueguard <discover|learn|protect|sync>.

discover: sadece keşif (6.1). learn: öğrenme modu (6.2). sync: rg_approved/rg_block'u DB'den doldurur.
protect sonraki adımda eklenir.
Ham soket gerektiği için root ya da CAP_NET_RAW,CAP_NET_ADMIN ile çalışır.
"""
import argparse
import logging

from rogueguard import config


def main() -> None:
    ap = argparse.ArgumentParser(prog="rogueguard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover", help="br-iot'u keşfet, gözlemleri DB'ye yaz")
    d.add_argument("--duration", type=float, default=None, help="saniye (boş = Ctrl+C'ye kadar)")
    l = sub.add_parser("learn", help="ağı öğren: nmap, onaylı envanter, rg_approved")
    l.add_argument("--duration", type=float, required=True, help="dinleme süresi (saniye)")
    sub.add_parser("sync", help="router setlerini veritabanındaki duruma eşitle")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("scapy").setLevel(logging.ERROR)
    cfg = config.load()

    if args.cmd == "discover":
        from rogueguard.discovery.runner import Discovery
        disc = Discovery(cfg)
        disc.start()
        disc.run_for(args.duration)
    elif args.cmd == "learn":
        from rogueguard.learn import learn
        learn(cfg, args.duration)
    elif args.cmd == "sync":
        from rogueguard import db
        from rogueguard.containment.router import Router
        conn = db.connect(cfg["database"]["path"])
        ips = lambda status: [r["ip"] for r in conn.execute(
            "SELECT ip FROM devices WHERE status=? AND ip IS NOT NULL "
            "AND COALESCE(device_type,'') != 'infrastructure'", (status,))]
        Router(cfg).sync(ips("approved"), ips("blocked"))


if __name__ == "__main__":
    main()
