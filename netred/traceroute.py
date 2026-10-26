#traceroute (UDP/ICMP) y traceroute visual en texto

from __future__ import annotations

import re
import socket

from . import util

_HOP_RE = re.compile(r"^\s*(\d+)\??:\s+(.*)$")
_ADDR_RE = re.compile(r"^([0-9a-fA-F:.]+|\S+)\s+([\d.]+)ms")


def trace(host: str, max_hops: int = 30, timeout: float = 4.0, resolve: bool = False) -> list[dict]:
    if util.IS_WINDOWS:
        return _trace_tracert(host, max_hops, timeout, resolve)
    if util.have("tracepath"):
        return _trace_tracepath(host, max_hops, timeout, resolve)
    # Fallback: usar 'traceroute' si existe.
    if util.have("traceroute"):
        return _trace_traceroute(host, max_hops, timeout, resolve)
    util.err("No tracepath ni traceroute disponibles")
    return []


_RTT_TOKEN = re.compile(r"(<)?\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)


def _parse_tracert(text: str) -> list[dict]:
    hops: list[dict] = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not match:
            continue
        hop = int(match.group(1))
        rest = match.group(2)
        rtts: list[float] = []
        for token in _RTT_TOKEN.finditer(rest):
            try:
                value = float(token.group(2).replace(",", "."))
            except ValueError:
                continue
            if token.group(1) == "<":
                value = 0.5
            rtts.append(value)
        host_part = _RTT_TOKEN.sub(" ", rest)
        host_part = re.sub(r"(?:\*\s*)+", " ", host_part).strip()
        if re.search(r"timed out|agotado|expir|zeituberschreitung|delai", util.fold_text(host_part)):
            host_part = ""
        host_name = host_part.split()[0] if host_part else None
        hops.append({"hop": hop, "host": host_name, "rtt": min(rtts) if rtts else None})
    return hops


def _trace_tracert(host: str, max_hops: int, timeout: float, resolve: bool) -> list[dict]:
    if not util.have("tracert"):
        util.err("tracert no disponible")
        return []
    cmd = ["tracert", "-h", str(max_hops), "-w", str(max(1, int(timeout * 1000)))]
    if not resolve:
        cmd.append("-d")
    cmd.append(host)
    rc, out, errp = util.run(cmd, timeout=max_hops * (timeout * 3 + 1) + 15)
    hops = _parse_tracert(out)
    if not hops:
        message = (errp or out).strip().splitlines()
        if message:
            util.err(message[-1])
    return hops


def _trace_tracepath(host: str, max_hops: int, timeout: float, resolve: bool) -> list[dict]:
    cmd = ["tracepath", "-m", str(max_hops)]
    if not resolve:
        cmd.append("-n")
    cmd.append(host)
    rc, out, errp = util.run(cmd, timeout=max_hops * (timeout * 3 + 1) + 15)
    hops: dict[int, dict] = {}
    for line in out.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2).strip()
        if rest.startswith("no reply"):
            hops.setdefault(hop_num, {"hop": hop_num, "host": None, "rtt": None})
            continue
        am = _ADDR_RE.match(rest)
        if am:
            address = am.group(1)
            rtt = float(am.group(2))
            if address == "[LOCALHOST]":
                continue
            existing = hops.get(hop_num)
            if existing is None or existing.get("rtt") is None or rtt < existing["rtt"]:
                hops[hop_num] = {"hop": hop_num, "host": address, "rtt": rtt}
        else:
            token = rest.split()[0] if rest.split() else None
            if token:
                hops.setdefault(hop_num, {"hop": hop_num, "host": token, "rtt": None})
    if not hops and rc != 0:
        util.err(errp.strip() or "tracepath fallo")
    return [hops[k] for k in sorted(hops)]


def _trace_traceroute(host: str, max_hops: int, timeout: float, resolve: bool) -> list[dict]:
    cmd = ["traceroute", "-m", str(max_hops), "-w", str(max(1, int(timeout)))]
    if not resolve:
        cmd.append("-n")
    cmd.append(host)
    rc, out, errp = util.run(cmd, timeout=max_hops * (timeout * 3 + 1) + 15)
    hops: list[dict] = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if not parts:
            continue
        try:
            hop_num = int(parts[0])
        except ValueError:
            continue
        host_token = parts[1] if len(parts) > 1 else None
        rtts = [float(p.split("ms")[0]) for p in parts if p.endswith("ms") and p.split("ms")[0].replace(".", "").isdigit()]
        rtt = min(rtts) if rtts else None
        if host_token and host_token != "*":
            hops.append({"hop": hop_num, "host": host_token, "rtt": rtt})
        else:
            hops.append({"hop": hop_num, "host": None, "rtt": None})
    if not hops and errp:
        util.err(errp.strip())
    return hops

#salto a la latencia
def visual(hops: list[dict], width: int = 40) -> None:

    if not hops:
        util.table(["Salto", "Host", "RTT (ms)"], [])
        return
    max_rtt = max((h["rtt"] for h in hops if h.get("rtt")), default=1.0) or 1.0
    for h in hops:
        rtt = h.get("rtt")
        if rtt is None:
            bar = util.Style.paint("* * *", util.Style.RED)
            rtt_txt = "sin respuesta"
        else:
            size = max(1, int(round(width * rtt / max_rtt)))
            colour = util.Style.GREEN if rtt < max_rtt / 3 else (
                util.Style.YELLOW if rtt < 2 * max_rtt / 3 else util.Style.RED
            )
            bar = util.Style.paint("#" * size, colour)
            rtt_txt = f"{rtt:7.2f} ms"
        host = h.get("host") or "*"
        print(f" {h['hop']:>2}  {host:<35} {rtt_txt}  {bar}")


def run_menu() -> None:
    host = input("Host o IP: ").strip()
    if not host:
        return
    try:
        max_hops = int(input("Maximo de saltos [30]: ").strip() or "30")
    except ValueError:
        max_hops = 30
    util.info(f"Trazando ruta a {host}...")
    hops = trace(host, max_hops=max_hops, resolve=True)
    util.title(f"Traceroute -> {host}")
    visual(hops)
