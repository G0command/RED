#Speedtest: mide latencia, descarga y subida



from __future__ import annotations

import os
import statistics
import time
import urllib.error
import urllib.request

from . import util

_DOWN_URLS = [
    "https://speed.cloudflare.com/__down?bytes={n}",
    "https://proof.ovh.net/files/1Mb.dat",
    "https://speedtest.tele2.net/1MB.zip",
]
_UP_URL = "https://speed.cloudflare.com/__up"
_LAT_URL = "https://speed.cloudflare.com/__down?bytes=0"


def _open(url: str, timeout: float, data: bytes | None = None):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "scp-red"})
    return urllib.request.urlopen(req, timeout=timeout)


#retornno ping y jitter
def latency(samples: int = 6, timeout: float = 5.0) -> tuple[float | None, float | None]:

    times: list[float] = []
    for _ in range(samples):
        try:
            start = time.perf_counter()
            with _open(_LAT_URL, timeout) as resp:
                resp.read()
            times.append((time.perf_counter() - start) * 1000.0)
        except Exception:
            pass
        time.sleep(0.05)
    if not times:
        return None, None
    jitter = statistics.pstdev(times) if len(times) > 1 else 0.0
    return round(min(times), 2), round(jitter, 2)

#descarhga url devolviendo butes y seconds
def download_bytes(url: str, timeout: float = 30.0) -> tuple[int, float]:

    start = time.perf_counter()
    total = 0
    with _open(url, timeout) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
    return total, max(time.perf_counter() - start, 1e-6)


#velocidad de descarga|bajada de mbps
def download(urls: list[str] | None = None, size: int = 25_000_000,
             timeout: float = 30.0) -> float | None:

    urls = urls or _DOWN_URLS
    best = 0.0
    for template in urls:
        url = template.format(n=size) if "{n}" in template else template
        try:
            nbytes, seconds = download_bytes(url, timeout=timeout)
        except (urllib.error.URLError, OSError, ValueError):
            continue
        if nbytes <= 0:
            continue
        mbps = (nbytes * 8) / seconds / 1_000_000
        best = max(best, mbps)
    return round(best, 2) if best else None

#velocidad de subida de mbps
def upload(size: int = 10_000_000, timeout: float = 30.0) -> float | None:

    payload = os.urandom(size)
    try:
        start = time.perf_counter()
        with _open(_UP_URL, timeout, data=payload) as resp:
            resp.read()
        seconds = max(time.perf_counter() - start, 1e-6)
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return round((size * 8) / seconds / 1_000_000, 2)


def measure(skip_upload: bool = False) -> dict:
    #util.info("Midiendo latencia...")
    ping_ms, jitter = latency()
    util.info("SCAN ⬇⬇⬇⬇⬇")
    down = download()
    up = None
    if not skip_upload:
        util.info("SCAN ⬆⬆⬆⬆⬆")
        up = upload()
    return {"ping_ms": ping_ms, "jitter_ms": jitter, "down_mbps": down, "up_mbps": up}


def print_result(result: dict) -> None:
    util.title("Speedtest")
    util.kv("Ping (ms)", result.get("ping_ms") if result.get("ping_ms") is not None else "-")
    util.kv("Jitter (ms)", result.get("jitter_ms") if result.get("jitter_ms") is not None else "-")
    util.kv("Bajada (Mbps)", result.get("down_mbps") if result.get("down_mbps") is not None else "-")
    util.kv("Subida (Mbps)", result.get("up_mbps") if result.get("up_mbps") is not None else "-")


def run_menu() -> None:
    result = measure()
    print_result(result)
