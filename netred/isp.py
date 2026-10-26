# analisis y ubicacion del isp + conexion wifi
#
#
# uso de apis a consulatr geolocalizacion

from __future__ import annotations

import json
import socket
import ssl
import urllib.request

from . import util

_ENDPOINTS = [
    "http://ip-api.com/json/?fields=status,message,country,regionName,city,isp,org,as,query,lat,lon,timezone",
    "https://ipapi.co/json/",
    "https://ipinfo.io/json",
]


#
#retorno ip/isp/asn y location
#
def public_info(timeout: float = 8.0) -> dict:
    last_error = "sin respuesta"
    for url in _ENDPOINTS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "scp-red"})
            context = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as exc:
            last_error = str(exc)
            continue
        normalised = _normalise(url, data)
        if normalised.get("ip"):
            normalised["source"] = url.split("/")[2]
            return normalised
    return {"error": last_error}


def _normalise(url: str, data: dict) -> dict:
    if "ip-api" in url:
        return {
            "ip": data.get("query"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "city": data.get("city"),
            "region": data.get("regionName"),
            "country": data.get("country"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
        }
    if "ipapi.co" in url:
        return {
            "ip": data.get("ip"),
            "isp": data.get("org"),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country_name"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "timezone": data.get("timezone"),
        }
    return {
        "ip": data.get("ip"),
        "isp": data.get("org"),
        "org": data.get("org"),
        "asn": data.get("org"),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "lat": (data.get("loc", ",").split(",") + [None])[0],
        "lon": (data.get("loc", ",").split(",") + [None, None])[1],
        "timezone": data.get("timezone"),
    }


#
# checar la conexion de DNS, TCP y HTTP verificando = wifi
#
def check_connectivity() -> dict:

    result = {
        "dns": False,
        "tcp": False,
        "http": False,
        "icmp": False,
    }
    try:
        socket.getaddrinfo("one.one.one.one", 443)
        result["dns"] = True
    except (socket.gaierror, OSError):
        pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        result["tcp"] = sock.connect_ex(("1.1.1.1", 443)) == 0
    except OSError:
        pass
    finally:
        sock.close()

    try:
        req = urllib.request.Request("http://connectivitycheck.gstatic.com/generate_204",
                                     headers={"User-Agent": "scp-red"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        result["http"] = True
    except Exception:
        try:
            req = urllib.request.Request("https://www.google.com/generate_204",
                                         headers={"User-Agent": "scp-red"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
            result["http"] = True
        except Exception:
            pass

    if util.have("ping"):
        from . import ping as ping_mod  # noqa: PLC0415

        stats = ping_mod.icmp("1.1.1.1", count=2, timeout=2)
        result["icmp"] = stats["received"] > 0
    result["online"] = result["dns"] or result["tcp"] or result["http"] or result["icmp"]
    return result


def print_info(data: dict) -> None:
    util.title("Analisis del ISP")
    if data.get("error"):
        util.err(f"NO DATA: {data['error']}")
        return
    util.kv("IP publica", data.get("ip") or "-")
    util.kv("ISP", data.get("isp") or "-")
    util.kv("Organizacion", data.get("org") or "-")
    util.kv("ASN", data.get("asn") or "-")
    location = ", ".join(filter(None, [data.get("city"), data.get("region"), data.get("country")]))
    util.kv("Ubicacion", location or "-")
    if data.get("lat") is not None:
        util.kv("Coordenadas", f"{data.get('lat')}, {data.get('lon')}")
    util.kv("Zona horaria", data.get("timezone") or "-")
    util.kv("Fuente", data.get("source") or "-")


def print_connectivity(result: dict) -> None:
    util.title("Conectividad a Internet")
    marks = {True: util.Style.paint("OK", util.Style.GREEN),
             False: util.Style.paint("FALLO", util.Style.RED)}
    util.kv("DNS", marks[result["dns"]])
    util.kv("TCP (1.1.1.1:443)", marks[result["tcp"]])
    util.kv("HTTP", marks[result["http"]])
    util.kv("ICMP", marks[result["icmp"]])
    util.kv("Estado", util.Style.paint("EN LINEA", util.Style.GREEN, util.Style.BOLD)
            if result["online"] else util.Style.paint("SIN CONEXION", util.Style.RED, util.Style.BOLD))


def run_menu() -> None:
    which = input("  [1] Analisis ISP   [2] Verificar conectividad [1]: ").strip() or "1"
    if which == "2":
        util.info("comprobando conectividad...")
        print_connectivity(check_connectivity())
    else:
        util.info("info ISP...")
        print_info(public_info())
