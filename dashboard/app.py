"""RogueGuard Streamlit Dashboard (6.6): cihaz envanteri, onay bekleyen cihazlar
(Onayla/Reddet → approvals tablosu), alarmlar ve deney sonuçları.
Çalıştırma (VM'de): .venv/bin/streamlit run dashboard/app.py --server.address 0.0.0.0 --server.port 8501"""
from datetime import datetime
from pathlib import Path
import sys

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard import data as dash_data
from rogueguard import config, db


st.set_page_config(page_title="RogueGuard", layout="wide")


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _conn():
    cfg = config.load()
    return db.connect(cfg["database"]["path"])


@st.fragment(run_every="5s")
def render_live_tabs() -> None:
    conn = _conn()
    try:
        devices = dash_data.load_devices(conn)
        pending = dash_data.load_pending(conn)
        alerts = dash_data.load_alerts(conn)

        tab_pending, tab_devices, tab_alerts, tab_exp = st.tabs([
            f"Onay Bekleyenler ({len(pending)})",
            f"Cihazlar ({len(devices)})",
            f"Alarmlar ({len(alerts)})",
            "Deney Sonuçları",
        ])

        with tab_pending:
            st.subheader("Onay Bekleyen Cihazlar")
            if not pending:
                st.info("Şu anda onay bekleyen cihaz yok.")
            else:
                for item in pending:
                    c1, c2, c3, c4, c5 = st.columns([2.2, 1.5, 2.0, 1.8, 2.0])
                    c1.markdown(f"**`{item['mac']}`**  \nOUI: `{item['oui']}`")
                    c2.write(f"IP: {item['ip']}")
                    c3.write(f"Hostname: {item['hostname']}")
                    c4.write(f"İlk görülme: {_fmt_ts(item['first_seen'])}")
                    with c5:
                        if item["queued_decision"]:
                            st.caption(f"Daemon bekliyor: **{item['queued_decision']}**")
                        else:
                            b1, b2 = st.columns(2)
                            if b1.button("Onayla", key=f"app_{item['mac']}", type="primary"):
                                dash_data.submit_approval(conn, item["mac"], "approve")
                                st.rerun()
                            if b2.button("Reddet", key=f"rej_{item['mac']}"):
                                dash_data.submit_approval(conn, item["mac"], "reject")
                                st.rerun()
                    st.divider()

        with tab_devices:
            st.subheader("Cihaz Envanteri")
            counts = {s: sum(1 for d in devices if d["status"] == s)
                      for s in ("approved", "pending", "quarantined", "blocked")}
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Toplam", len(devices))
            m2.metric("Onaylı", counts["approved"])
            m3.metric("Bekleyen", counts["pending"])
            m4.metric("Karantina", counts["quarantined"])
            m5.metric("Engelli", counts["blocked"])

            if devices:
                df = pd.DataFrame(devices)
                df["first_seen"] = df["first_seen"].map(_fmt_ts)
                df["last_seen"] = df["last_seen"].map(_fmt_ts)
                st.dataframe(df, width="stretch", hide_index=True)
            else:
                st.info("Henüz kayıtlı cihaz yok.")

        with tab_alerts:
            st.subheader("Alarmlar")
            high = sum(1 for a in alerts if a["severity"] == "high")
            med = sum(1 for a in alerts if a["severity"] == "medium")
            contained = sum(1 for a in alerts if a["ttc_s"] is not None)
            a1, a2, a3, a4 = st.columns(4)
            a1.metric("Toplam Alarm", len(alerts))
            a2.metric("Yüksek Önem", high)
            a3.metric("Orta Önem", med)
            a4.metric("Kontrol Altında", contained)

            if alerts:
                adf = pd.DataFrame(alerts)
                adf["ts"] = adf["ts"].map(_fmt_ts)
                st.dataframe(adf, width="stretch", hide_index=True)
            else:
                st.info("Henüz alarm yok.")

        with tab_exp:
            st.subheader("Deney Sonuçları")
            results_csv = ROOT / "experiments" / "results.csv"
            if results_csv.exists():
                rdf = pd.read_csv(results_csv)
                st.dataframe(rdf, width="stretch", hide_index=True)
            else:
                st.info("Henüz `experiments/results.csv` yok — Adım 7 deneyleri çalıştırıldığında burada görünecek.")
    finally:
        conn.close()


st.title("RogueGuard — IoT Cihaz İzleme ve Karantina")
cfg = config.load()
st.caption(
    f"Profil: `{cfg['decision']['detection_profile']}` · "
    f"Arayüz: `{cfg['network']['iot_iface']}` · "
    f"Karantina: `{'açık' if cfg['containment']['enabled'] else 'kapalı'}`"
)
render_live_tabs()
