"""Lab IoT cihaz ajanı: tek script, profile.json'a göre bir cihazı taklit eder.

Profildeki TCP portlarında dinler ve gerçekçi banner döner (HTTP Server başlığı,
RTSP cevabı), mDNS servislerini python-zeroconf ile kaydeder ve MQTT broker'a
profildeki aralıkla (küçük jitter ile) yayın yapar.
"""
import json
import random
import socket
import socketserver
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt
from zeroconf import ServiceInfo, Zeroconf

PROFILE = json.loads((Path(__file__).parent / "profile.json").read_text())
JITTER = 0.1  # yayın aralığına ±%10 rastgele sapma


def wait_for_ip(broker_ip):
    """DHCP adresi gelene kadar bekle; broker'a giden yolun yerel IP'sini döndür."""
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((broker_ip, 9))  # UDP connect paket göndermez, sadece rota seçer
                ip = s.getsockname()[0]
                if not ip.startswith("0."):
                    return ip
        except OSError:
            pass
        time.sleep(2)


def make_handler(svc):
    """Servis türüne göre ilk satırı okuyup banner dönen TCP handler üretir."""
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                data = self.request.recv(2048).decode(errors="replace")
            except OSError:
                data = ""
            if svc["kind"] == "http":
                body = f"<html><head><title>{svc.get('title', '')}</title></head><body></body></html>"
                resp = ("HTTP/1.1 200 OK\r\n"
                        f"Server: {svc['banner']}\r\n"
                        "Content-Type: text/html\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Connection: close\r\n\r\n" + body)
            elif svc["kind"] == "rtsp":
                cseq = next((ln.split(":", 1)[1].strip() for ln in data.splitlines()
                             if ln.lower().startswith("cseq")), "1")
                resp = ("RTSP/1.0 200 OK\r\n"
                        f"CSeq: {cseq}\r\n"
                        f"Server: {svc['banner']}\r\n"
                        "Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN\r\n\r\n")
            else:  # raw (ör. 9100 JetDirect): veri kabul eder, cevap vermez
                return
            self.request.sendall(resp.encode())
    return Handler


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_services():
    for svc in PROFILE["services"]:
        srv = Server(("0.0.0.0", svc["port"]), make_handler(svc))
        threading.Thread(target=srv.serve_forever, daemon=True).start()


def register_mdns(ip):
    if not PROFILE["mdns"]:
        return None
    zc = Zeroconf(interfaces=[ip])
    host = PROFILE["hostname"]
    for m in PROFILE["mdns"]:
        info = ServiceInfo(
            m["type"] + ".local.",
            f"{host}.{m['type']}.local.",
            addresses=[socket.inet_aton(ip)],
            port=m["port"],
            properties={"model": PROFILE.get("vendor_class", "")},
            server=f"{host}.local.",
        )
        zc.register_service(info)
    return zc


def next_delay(cfg):
    if cfg["mode"] == "irregular":
        return random.expovariate(1.0 / cfg["mean_interval"])
    base = cfg["interval"]
    return base * random.uniform(1 - JITTER, 1 + JITTER)


def publish_loop():
    cfg = PROFILE["mqtt"]
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=PROFILE["name"])
    client.reconnect_delay_set(min_delay=2, max_delay=30)
    # connect_async: cihaz henüz onaylı değilse broker'a erişemez; paho arka planda yeniden dener.
    client.connect_async(PROFILE["broker"]["ip"], PROFILE["broker"]["port"], keepalive=60)
    client.loop_start()
    while True:
        time.sleep(next_delay(cfg))
        payload = dict(cfg["payload"], ts=int(time.time()))
        client.publish(cfg["topic"], json.dumps(payload), qos=0)


def main():
    ip = wait_for_ip(PROFILE["broker"]["ip"])
    start_services()
    register_mdns(ip)
    publish_loop()


if __name__ == "__main__":
    main()
