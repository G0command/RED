# program salida por terminal, ejecucion de comandos e info de red, colores - info



from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence


class Style:
    _enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GREY = "\033[90m"

    @classmethod
    def set_enabled(cls, value: bool) -> None:
        cls._enabled = value

    @classmethod
    def paint(cls, text: object, *codes: str) -> str:
        text = str(text)
        if not cls._enabled or not codes:
            return text
        return "".join(codes) + text + cls.RESET

    @classmethod
    def strip(cls, text: str) -> str:
        return re.sub(r"\033\[[0-9;]*m", "", text)


def info(msg: str) -> None:
    print(f"{Style.paint('[*]', Style.CYAN, Style.BOLD)} {msg}")


def ok(msg: str) -> None:
    print(f"{Style.paint('[+]', Style.GREEN, Style.BOLD)} {msg}")


def warn(msg: str) -> None:
    print(f"{Style.paint('[!]', Style.YELLOW, Style.BOLD)} {msg}")


def err(msg: str) -> None:
    print(f"{Style.paint('[-]', Style.RED, Style.BOLD)} {msg}", file=sys.stderr)


def title(msg: str, char: str = "=") -> None:
    line = char * max(len(msg) + 2, 8)
    print()
    print(Style.paint(line, Style.BLUE))
    print(Style.paint(f" {msg}", Style.BOLD, Style.CYAN))
    print(Style.paint(line, Style.BLUE))


def kv(key: str, value: object, width: int = 26) -> None:
    """Imprime un par clave/valor alineado."""
    key_txt = Style.paint(f"{key:<{width}}", Style.BOLD)
    print(f"  {key_txt}: {value}")


#
#
#
#espacio de tablas y bordes
#
#

def _visible_len(text: str) -> int:
    return len(Style.strip(str(text)))

#TABLA Y BORDES
def table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> None:

    rows = [[("" if c is None else str(c)) for c in row] for row in rows]
    widths = [_visible_len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], _visible_len(cell))

    def fmt(cells: Sequence[str]) -> str:
        parts = []
        for i, cell in enumerate(cells):
            pad = widths[i] - _visible_len(cell)
            parts.append(str(cell) + " " * pad)
        return " | ".join(parts)

    head = " | ".join(
        Style.paint(str(h).ljust(widths[i]), Style.BOLD, Style.CYAN)
        for i, h in enumerate(headers)
    )
    sep = "-+-".join("-" * w for w in widths)
    print(" " + head)
    print(" " + sep)
    for row in rows:
        print(" " + fmt(row))
    if not rows:
        print(Style.paint("  (sin resultados)", Style.GREY))


#
#COMMANDOSDSF
#
#
#

def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(
    cmd: Sequence[str], timeout: float = 15.0, input_text: str | None = None
) -> tuple[int, str, str]:
    #argu en cli
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"binario no encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "tiempo de espera agotado"
    except Exception as exc:  # pragma: no cover - defensivo
        return 1, "", str(exc)


#info local 51131313213213215631

def _ip_json(args: Sequence[str]) -> list | dict | None:
    if not have("ip"):
        return None
    rc, out, _ = run(["ip", "-j", *args], timeout=5)
    if rc != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def get_interfaces() -> list[dict]:
    #retorna interfaces con ipv4 - prefijo - MAC
    ifaces: list[dict] = []
    data = _ip_json(["addr", "show"])
    if isinstance(data, list):
        for item in data:
            name = item.get("ifname")
            if not name:
                continue
            ipv4 = None
            prefix = None
            for addr in item.get("addr_info", []):
                if addr.get("family") == "inet":
                    ipv4 = addr.get("local")
                    prefix = addr.get("prefixlen")
                    break
            ifaces.append(
                {
                    "name": name,
                    "ip": ipv4,
                    "prefix": prefix,
                    "mac": item.get("address"),
                    "up": "UP" in item.get("flags", []),
                    "loopback": name == "lo",
                }
            )
        return ifaces

    # Fallback: /sys + ioctl
    netdir = "/sys/class/net"
    try:
        names = sorted(os.listdir(netdir))
    except OSError:
        return ifaces
    for name in names:
        ip = get_interface_ip(name)
        mac = read_mac(name)
        ifaces.append(
            {
                "name": name,
                "ip": ip,
                "prefix": 24 if ip else None,
                "mac": mac,
                "up": read_operstate(name) == "up",
                "loopback": name == "lo",
            }
        )
    return ifaces


def read_mac(ifname: str) -> str | None:
    try:
        with open(f"/sys/class/net/{ifname}/address") as fh:
            return fh.read().strip()
    except OSError:
        return None


def read_operstate(ifname: str) -> str | None:
    try:
        with open(f"/sys/class/net/{ifname}/operstate") as fh:
            return fh.read().strip()
    except OSError:
        return None


def get_interface_ip(ifname: str) -> str | None:
    #obtener la ipv4 de una interfaz mediante ioctl (
    import fcntl  # noqa: PLC0415
    import struct  # noqa: PLC0415

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", ifname[:15].encode())
        res = fcntl.ioctl(sock.fileno(), 0x8915, packed)  # SIOCGIFADDR
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def default_route() -> dict | None:
    data = _ip_json(["route", "show", "default"])
    if isinstance(data, list) and data:
        return data[0]
    rc, out, _ = run(["ip", "route", "show", "default"], timeout=5)
    if rc == 0 and out.strip():
        parts = out.split()
        route: dict = {}
        for i, tok in enumerate(parts):
            if tok == "via" and i + 1 < len(parts):
                route["gateway"] = parts[i + 1]
            if tok == "dev" and i + 1 < len(parts):
                route["dev"] = parts[i + 1]
            if tok == "src" and i + 1 < len(parts):
                route["prefsrc"] = parts[i + 1]
        return route or None
    return None


def default_interface() -> str | None:
    route = default_route()
    if route and route.get("dev"):
        return route["dev"]
    for iface in get_interfaces():
        if not iface["loopback"] and iface["up"] and iface["ip"]:
            return iface["name"]
    return None


def get_gateway() -> str | None:
    route = default_route()
    return route.get("gateway") if route else None


def get_local_ip() -> str | None:
    #ip local usada para salir a Internet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def ip_and_prefix(ifname: str | None = None) -> tuple[str | None, int]:
    #devuelve ip - prefijo para una interfaz
    if ifname is None:
        ifname = default_interface()
    for iface in get_interfaces():
        if iface["name"] == ifname and iface["ip"]:
            return iface["ip"], int(iface["prefix"] or 24)
    ip = get_local_ip()
    return ip, 24


def local_network(ifname: str | None = None) -> ipaddress.IPv4Network | None:
    ip, prefix = ip_and_prefix(ifname)
    if not ip:
        return None
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return net if isinstance(net, ipaddress.IPv4Network) else None
    except ValueError:
        return None


def is_wireless(ifname: str) -> bool:
    return os.path.isdir(f"/sys/class/net/{ifname}/wireless")


def wireless_interfaces() -> list[str]:
    ifaces = []
    for iface in get_interfaces():
        if not iface["loopback"] and is_wireless(iface["name"]):
            ifaces.append(iface["name"])
    if not ifaces and have("iwconfig"):
        rc, out, _ = run(["iwconfig"], timeout=5)
        if rc == 0:
            for line in out.splitlines():
                if line and not line.startswith(" "):
                    ifaces.append(line.split()[0])
    return ifaces


def nameservers() -> list[str]:
    servers: list[str] = []
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except OSError:
        pass
    return servers or ["1.1.1.1", "8.8.8.8"]



def now_str() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def is_valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def is_valid_mac(text: str) -> bool:
    return bool(re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", text.strip()))


def normalize_mac(mac: str) -> str:
    hexonly = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(hexonly) != 12:
        return mac.lower()
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))

#oculta mac
def mask_mac(mac: str | None, keep_oui: bool = True, hidden: str = "██") -> str:

    if not mac:
        return ""
    parts = normalize_mac(mac).split(":")
    if len(parts) == 6:
        if keep_oui:
            return ":".join([parts[0], parts[1], parts[2], hidden, hidden, parts[5]])
        return ":".join([hidden] * 6)
    return hidden


def next_numbered_path(directory: str | Path | None = None, prefix: str = "escaneo",
                       extension: str = "xlsx") -> Path:

    directory = Path(directory) if directory else Path.cwd()
    directory.mkdir(parents=True, exist_ok=True)
    pattern = re.compile(rf"^{re.escape(prefix)}_(\d+)\.{re.escape(extension)}$", re.IGNORECASE)
    highest = 0
    for entry in directory.iterdir():
        m = pattern.match(entry.name)
        if m:
            highest = max(highest, int(m.group(1)))
    return directory / f"{prefix}_{highest + 1}.{extension}"



def reverse_dns(ip: str, timeout: float = 1.5) -> str | None:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None
    finally:
        socket.setdefaulttimeout(old)


def human_seconds(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def human_bytes(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"
