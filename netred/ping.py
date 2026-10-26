#info para program ping

#ICMP: usa el binario ping del sistema
# TCP: mide el tiempo de establecimiento de conexion
# HTTP: mide el tiempo hasta la respuesta HTTP



from __future__ import annotations

import re
import socket
import ssl
import statistics
import time
import urllib.parse
from http.client import HTTPConnection, HTTPSConnection

from . import util

_SUMMARY = re.compile(r"([\d.]+)% packet loss")
_RTT = re.compile(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)")


def _empty_stats(kind: str, target: str) -> dict:
    return {"kind": kind, "target": target, "sent": 0, "received": 0,
            "loss": 100.0, "min": None, "avg": None, "max": None, "mdev": None,
            "times": []}

def _parse_windows_icmp(host: str, out: str, count: int, errp: str = "") -> dict:
    stats = _empty_stats("ICMP", host)
    sent = received = None
    loss = None
    for line in out.splitlines():
        folded = util.fold_text(line)
        if ("sent" in folded or "enviado" in folded or "envoye" in folded
                or "gesendet" in folded):
            if ("received" in folded or "recibido" in folded or "recu" in folded
                    or "empfangen" in folded):
                numbers = re.findall(r"=\s*(\d+)", line)
                if len(numbers) >= 2:
                    sent, received = int(numbers[0]), int(numbers[1])
        if loss is None:
            pct = re.search(r"\((\d+)\s*%", line)
            if pct:
                loss = float(pct.group(1))

    times: list[float] = []
    for match in re.finditer(
        r"(?:time|tiempo|temps|zeit|tijd)\s*[=<]\s*([\d.,]+)\s*ms", out, re.IGNORECASE
    ):
        try:
            times.append(float(match.group(1).replace(",", ".")))
        except ValueError:
            pass

    stats["sent"] = sent if sent is not None else count
    stats["received"] = received if received is not None else len(times)
    if loss is None:
        stats["loss"] = (
            round(100.0 * (stats["sent"] - stats["received"]) / stats["sent"], 1)
            if stats["sent"] else 100.0
        )
    else:
        stats["loss"] = loss

    folded_out = util.fold_text(out)
    for label, key in (
        ("minimum", "min"), ("minimo", "min"),
        ("maximum", "max"), ("maximo", "max"),
        ("average", "avg"), ("media", "avg"), ("moyenne", "avg"),
        ("mittelwert", "avg"),
    ):
        match = re.search(rf"{label}\s*=\s*([\d.,]+)\s*ms", folded_out)
        if match and stats[key] is None:
            stats[key] = float(match.group(1).replace(",", "."))
    if stats["avg"] is None and times:
        stats["avg"] = round(statistics.fmean(times), 2)
        stats["min"] = round(min(times), 2)
        stats["max"] = round(max(times), 2)
    if stats["mdev"] is None:
        stats["mdev"] = round(statistics.pstdev(times), 2) if len(times) > 1 else 0.0
    stats["times"] = times
    if stats["received"] == 0:
        low = folded_out + " " + util.fold_text(errp)
        if "could not find host" in low or "no se puede encontrar" in low or "introuvable" in low:
            stats["error"] = "host no encontrado"
        else:
            stats["error"] = "sin respuesta"
    return stats


def _icmp_windows(host: str, count: int, timeout: float) -> dict:
    stats = _empty_stats("ICMP", host)
    if not util.have("ping"):
        util.err("binary ping =/= no disponible")
        return stats
    wait_ms = max(1, int(timeout * 1000))
    cmd = ["ping", "-n", str(count), "-w", str(wait_ms), host]
    rc, out, errp = util.run(cmd, timeout=count * (timeout + 1) + 5)
    if rc != 0 and not out:
        stats["error"] = errp.strip() or "sin respuesta"
        return stats
    return _parse_windows_icmp(host, out, count, errp)


    #icmp retorna estadisticas loss/min/avg/max/mdev
def icmp(host: str, count: int = 4, interval: float = 0.25, timeout: float = 2.0,
         quiet: bool = True) -> dict:

    if util.IS_WINDOWS:
        return _icmp_windows(host, count, timeout)

    stats = _empty_stats("ICMP", host)
    if not util.have("ping"):
        util.err("binary ping =/= no disponible")
        return stats
    cmd = ["ping", "-n"]
    if quiet:
        cmd.append("-q")
    cmd += ["-c", str(count), "-i", str(interval), "-W", str(max(1, int(timeout))), host]
    rc, out, errp = util.run(cmd, timeout=count * (interval + timeout) + 5)
    if rc != 0 and not out:
        stats["error"] = errp.strip() or "sin respuesta"
        return stats

    m = _SUMMARY.search(out)
    if m:
        stats["loss"] = float(m.group(1))
    m = _RTT.search(out)
    if m:
        stats["min"] = float(m.group(1))
        stats["avg"] = float(m.group(2))
        stats["max"] = float(m.group(3))
        stats["mdev"] = float(m.group(4))
    # Paquetes enviados/recibidos RX Y TX
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", out)
    if m:
        stats["sent"] = int(m.group(1))
        stats["received"] = int(m.group(2))
    else:
        stats["sent"] = count
        stats["received"] = count if stats["loss"] == 0 else 0
    times = [float(x) for x in re.findall(r"time[=<]([\d.]+)", out)]
    stats["times"] = times
    if stats["avg"] is None and times:
        stats["avg"] = statistics.fmean(times)
        stats["min"] = min(times)
        stats["max"] = max(times)
    return stats


#pinf tcp - medida de time x conexion de puerto
def tcp(host: str, port: int = 80, count: int = 4, timeout: float = 2.0) -> dict:

    stats = _empty_stats("TCP", f"{host}:{port}")
    times: list[float] = []
    for _ in range(count):
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            rc = sock.connect_ex((host, port))
        finally:
            sock.close()
        if rc == 0:
            times.append((time.perf_counter() - start) * 1000.0)
        time.sleep(0.05)
    _fill(stats, times, count)
    return stats

#RX
def http(url: str, count: int = 3, timeout: float = 5.0) -> dict:

    stats = _empty_stats("HTTP", url)
    if "://" not in url:
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host:
        stats["error"] = "URL invalida"
        return stats
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    times: list[float] = []
    for _ in range(count):
        start = time.perf_counter()
        try:
            if parsed.scheme == "https":
                conn = HTTPSConnection(
                    host, port, timeout=timeout,
                    context=ssl.create_default_context(),
                )
            else:
                conn = HTTPConnection(host, port, timeout=timeout)
            conn.request("HEAD", path, headers={"User-Agent": "scp-red"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            times.append((time.perf_counter() - start) * 1000.0)
        except Exception as exc:
            stats.setdefault("error", str(exc))
        time.sleep(0.05)
    _fill(stats, times, count)
    return stats


def _fill(stats: dict, times: list[float], count: int) -> None:
    stats["times"] = times
    stats["sent"] = count
    stats["received"] = len(times)
    stats["loss"] = round(100.0 * (count - len(times)) / count, 1) if count else 100.0
    if times:
        stats["min"] = round(min(times), 2)
        stats["avg"] = round(statistics.fmean(times), 2)
        stats["max"] = round(max(times), 2)
        stats["mdev"] = round(statistics.pstdev(times), 2) if len(times) > 1 else 0.0


def print_stats(stats: dict) -> None:
    util.title(f"Ping {stats['kind']} -> {stats['target']}")
    util.kv("Enviados", stats["sent"])
    util.kv("Recibidos", stats["received"])
    util.kv("Perdida", f"{stats['loss']}%")
    if stats.get("avg") is not None:
        util.kv("Min/Avg/Max", f"{stats['min']} / {stats['avg']} / {stats['max']} ms")
        util.kv("Desv. (mdev)", f"{stats['mdev']} ms")
    if stats.get("error"):
        util.kv("Error", stats["error"])


def run_ping_menu() -> None:
    host = input("Host o IP: ").strip()
    if not host:
        return
    print("  [1] ICMP   [2] TCP   [3] HTTP")
    kind = input("Tipo [1]: ").strip() or "1"
    try:
        count = int(input("Repeticiones [4]: ").strip() or "4")
    except ValueError:
        count = 4
    if kind == "2":
        port = input("Puerto [80]: ").strip() or "80"
        stats = tcp(host, int(port) if port.isdigit() else 80, count=count)
    elif kind == "3":
        stats = http(host if "://" in host else "http://" + host, count=count)
    else:
        stats = icmp(host, count=count, quiet=True)
    print_stats(stats)
