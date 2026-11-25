"""RogueGuard komut satırı: python -m rogueguard <discover|learn|protect|sync>.

discover: sadece keşif (6.1). learn: öğrenme modu (6.2). protect: keşif + karar motoru (6.3)
+ karantina/blok (6.4). sync: rg_approved/rg_block'u DB'den doldurur.
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
    p = sub.add_parser("protect", help="keşfi çalıştır, karar motoruyla alarm üret")
    p.add_argument("--duration", type=float, default=None, help="saniye (boş = Ctrl+C'ye kadar)")
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
    elif args.cmd == "protect":
        from rogueguard import db
        from rogueguard.containment.router import Router
        from rogueguard.decision.engine import DecisionEngine
        from rogueguard.discovery.runner import Discovery
        router = Router(cfg)
        _sync_router(router, db.connect(cfg["database"]["path"]))   # router setleri boşalmış olabilir

        def move_approved_ip(mac: str, old_ip: str | None, new_ip: str) -> None:
            if old_ip and old_ip in router.members(router.approved_set):
                router.remove(router.approved_set, old_ip)
            router.add(router.approved_set, new_ip)

        from rogueguard.alerting.syslog import SyslogForwarder
        alert_hooks = []
        if cfg["containment"]["enabled"]:
            from rogueguard.containment.actions import Containment
            from rogueguard.containment.quarantine import Quarantine
            from functools import partial
            from rogueguard.containment.arp_heal import heal
            alert_hooks.append(Containment(router, Quarantine(cfg),
                                           healer=partial(heal, cfg["network"]["iot_iface"])).apply)
        syslog = SyslogForwarder(cfg)
        alert_hooks.append(syslog.on_alert)

        def on_alert(conn, alert_id: int) -> None:
            for hook in alert_hooks:
                hook(conn, alert_id)

        engine = DecisionEngine(cfg, on_ip_change=move_approved_ip, on_alert=on_alert)
        engine.sweep()
        disc = Discovery(cfg, on_observation=engine.on_observation,
                         on_arp=engine.on_arp, on_syn=engine.on_syn)
        disc.start()
        try:
            disc.run_for(args.duration)
        finally:
            syslog.close()
    elif args.cmd == "sync":
        from rogueguard import db
        from rogueguard.containment.router import Router
        _sync_router(Router(cfg), db.connect(cfg["database"]["path"]))


def _sync_router(router, conn) -> None:
    """rg_approved / rg_block setlerini devices tablosundaki duruma eşitler."""
    def ips(status: str) -> list[str]:
        return [r["ip"] for r in conn.execute(
            "SELECT ip FROM devices WHERE status=? AND ip IS NOT NULL "
            "AND COALESCE(device_type,'') != 'infrastructure'", (status,))]
    router.sync(ips("approved"), ips("blocked"))


if __name__ == "__main__":
    main()
