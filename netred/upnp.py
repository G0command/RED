# scan y retorno nombre, fabricante, modelo, tipo desde el xml


from __future__ import annotations

import socket
import urllib.request
import xml.etree.ElementTree as ET

from . import util

_MCAST = ("239.255.255.250", 1900)
_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)

# buscar dispositivos ssdsa para retornar la data
def discover(timeout: float = 3.0, retries: int = 2) -> list[dict]:

    seen: dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(1.0)
    try:
        for _ in range(retries):
            try:
                sock.sendto(_MSEARCH.encode(), _MCAST)
            except OSError:
                break
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                if not seen:
                    # Una espera extra por si la red es lenta
                    try:
                        data, addr = sock.recvfrom(65535)
                    except socket.timeout:
                        break
                else:
                    break
            text = data.decode("latin-1", "replace")
            headers = _parse_headers(text)
            location = headers.get("location")
            key = location or headers.get("usn") or addr[0]
            if key in seen:
                continue
            info = _describe(location) if location else {}
            info.update(
                {
                    "ip": addr[0],
                    "location": location,
                    "server": headers.get("server", ""),
                    "st": headers.get("st", ""),
                    "usn": headers.get("usn", ""),
                }
            )
            info.update({k: v for k, v in _from_server(info.get("server", "")).items() if v})
            seen[key] = info
    finally:
        sock.close()
    return list(seen.values())


def _parse_headers(text: str) -> dict:
    headers: dict[str, str] = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers


def _describe(location: str) -> dict:
    try:
        req = urllib.request.Request(location, headers={"User-Agent": "scp-red"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            raw = resp.read(262144)
    except Exception:
        return {}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {}
    found = {}
    wanted = {
        "friendlyName": "name",
        "manufacturer": "manufacturer",
        "manufacturerURL": "manufacturer_url",
        "modelName": "model",
        "modelNumber": "model_number",
        "modelDescription": "model_description",
        "deviceType": "device_type",
        "UDN": "udn",
    }
    for elem in root.iter():
        tag = elem.tag.split("}")[-1]
        if tag in wanted and elem.text:
            found.setdefault(wanted[tag], elem.text.strip())
    return found


def _from_server(server: str) -> dict:
    #extrae encabeazdo de server
    if not server:
        return {}
    parts = server.split("/")
    return {"manufacturer": parts[0].strip()} if parts else {}


def print_devices(devices: list[dict]) -> None:
    util.title("Dispositivos UPnP / DLNA")
    rows = []
    for d in devices:
        rows.append([
            d.get("ip", "-"),
            (d.get("name") or "(sin nombre)")[:30],
            (d.get("manufacturer") or "-")[:20],
            (d.get("model") or "-")[:20],
            (d.get("device_type") or "-").split(":")[-1][:20],
        ])
    util.table(["IP", "Nombre", "Fabricante", "Modelo", "Tipo"], rows)


def run_menu() -> None:
    util.info("Buscando dispositivos -SSDP...")
    devices = discover()
    print_devices(devices)
    util.info(f"Total: {len(devices)}")
