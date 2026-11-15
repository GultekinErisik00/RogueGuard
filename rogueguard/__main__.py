"""RogueGuard komut satırı: python -m rogueguard <discover|learn|protect|sync>.

discover: sadece keşif (6.1). learn / protect / sync sonraki adımlarda eklenir.
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
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("scapy").setLevel(logging.ERROR)
    cfg = config.load()

    if args.cmd == "discover":
        from rogueguard.discovery.runner import Discovery
        disc = Discovery(cfg)
        disc.start()
        disc.run_for(args.duration)


if __name__ == "__main__":
    main()
