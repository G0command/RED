# program salida por terminal, ejecucion de comandos e info de red, colores - info



from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import locale
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import unicodedata
from pathlib import Path
from typing import Iterable, Sequence

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"

# windowsz uso dee  UTF-8 y VT

if IS_WINDOWS:
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):  #pragma: no cover - consola antigua
            pass

#activacion de secuencias ansi windows
def _enable_windows_vt() -> bool:

    if not IS_WINDOWS:
        return True
    try:
        import ctypes  #noqa: PLC0415

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  #STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:  # pragma: no cover - defensivo
        return False


class Style:
    _enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    if _enabled and IS_WINDOWS:
        _enabled = _enable_windows_vt()

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
    print(f"{Style.paint('[?]', Style.CYAN, Style.BOLD)} {msg}")


def ok(msg: str) -> None:
    print(f"\n{Style.paint('[+]', Style.GREEN, Style.BOLD)} {msg}\n")


def warn(msg: str) -> None:
    print(f"{Style.paint('[!]', Style.YELLOW, Style.BOLD)} {msg}")


def err(msg: str) -> None:
    print(f"{Style.paint('[X]', Style.RED, Style.BOLD)} {msg}", file=sys.stderr)


def title(msg: str, char: str = "=") -> None:
    line = char * max(len(msg) + 2, 8)
    print()
    print(Style.paint(line, Style.BLUE))
    print(Style.paint(f" {msg}", Style.BOLD, Style.CYAN))
    print(Style.paint(line, Style.BLUE))

#print cla=ve valor
def kv(key: str, value: object, width: int = 26) -> None:
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
        print(Style.paint("  -sin resultados-", Style.GREY))


#
#COMMANDOSDSF
#
#
#

def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

#normalisa texto (solo minusculas sin acentos)
def fold_text(text: str) -> str:
    normalised = unicodedata.normalize("NFKD", str(text))
    return normalised.encode("ascii", "ignore").decode("ascii").lower()


def _windows_codepage(kind: str) -> str | None:
    if not IS_WINDOWS:
        return None
    try:
        import ctypes  # noqa:PLC0415

        code = ctypes.windll.kernel32.GetOEMCP() if kind == "oem" else ctypes.windll.kernel32.GetACP()
        return f"cp{int(code)}"
    except Exception:  # pragma: no cover - defensivo
        return "cp850" if kind == "oem" else "cp1252"


def _decode_bytes(data: bytes) -> str:
    if not data:
        return ""
    #return UTF-16 o BOM en power
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError:
            pass
    if b"\x00" in data[:200] and data.count(b"\x00") > len(data) // 4:
        try:
            return data.decode("utf-16-le" if data[1:2] == b"\x00" else "utf-16-be")
        except UnicodeDecodeError:
            pass
    encodings: list[str] = ["utf-8"]
    if IS_WINDOWS:
        encodings += [enc for enc in (_windows_codepage("oem"), _windows_codepage("ansi")) if enc]
        encodings += ["cp850", "cp1252"]
    else:
        encodings += [locale.getpreferredencoding(False), "latin-1"]
    seen: set[str] = set()
    for encoding in encodings:
        if not encoding or encoding.lower() in seen:
            continue
        seen.add(encoding.lower())
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")


def run(
    cmd: Sequence[str], timeout: float = 15.0, input_text: str | None = None
) -> tuple[int, str, str]:
    #argu en cli
    kwargs: dict = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            timeout=timeout,
            input=input_text.encode("utf-8") if input_text is not None else None,
            **kwargs,
        )
        return proc.returncode, _decode_bytes(proc.stdout), _decode_bytes(proc.stderr)
    except FileNotFoundError:
        return 127, "", f"binario no encontrado: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "tiempo de espera agotado"
    except Exception as exc:  # pragma: no cover - defensivo
        return 1, "", str(exc)


def powershell_exe() -> str | None:
    if not IS_WINDOWS:
        return None
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if exe:
        return exe
    candidate = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(candidate) if candidate.exists() else None


def powershell(script: str, timeout: float = 10.0) -> str | None:
    exe = powershell_exe()
    if not exe:
        return None
    rc, out, _ = run(
        [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout=timeout,
    )
    if rc != 0 or not out.strip():
        return None
    return out.strip()


def powershell_json(script: str, timeout: float = 10.0):
    text = powershell(script, timeout=timeout)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None

#direcytorios de datos del usr segun su SO
def data_dir() -> Path:
    override = os.environ.get("SCP_RED_DATA")
    if override:
        return Path(override).expanduser()
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "scp-red"
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / "scp-red"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "scp-red"

#open url browser
def open_url(url: str) -> bool:
    try:
        if IS_WINDOWS:
            os.startfile(url)  # type: ignore[attr-defined]
            return True
        if IS_MAC:
            subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        opener = os.environ.get("BROWSER") or shutil.which("xdg-open")
        if not opener:
            return False
        subprocess.Popen([opener, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


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


_WIN_IFACE_CACHE: tuple[float, list[dict] | None] = (0.0, None)
_WIN_NS_CACHE: tuple[float, list[str] | None] = (0.0, None)
_CACHE_TTL = 5.0


def _netmask_to_prefix(mask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


_PS_INTERFACES = r"""
$ErrorActionPreference = 'SilentlyContinue'
Get-NetIPConfiguration | ForEach-Object {
    $ip = $_.IPv4Address | Select-Object -First 1
    if (-not $ip) { return }
    [PSCustomObject]@{
        name     = $_.InterfaceAlias
        ip       = $ip.IPAddress
        prefix   = $ip.PrefixLength
        mac      = $_.NetAdapter.MacAddress
        up       = ($_.NetAdapter.Status -eq 'Up')
        loopback = (($_.InterfaceAlias -match 'Loopback') -or ($ip.IPAddress -like '127.*'))
        wireless = ($_.NetAdapter.InterfaceDescription -match 'Wi-?Fi|Wireless|WLAN|802\.11')
    }
} | ConvertTo-Json -Compress
"""


def _parse_ipconfig(text: str) -> list[dict]:
    ifaces: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if not raw[:1].isspace() and line.endswith(":"):
            header = line[:-1].strip()
            low = fold_text(header)
            if "configuration" in low or "configuracion" in low:
                current = None
                continue
            name = header.split()[-1] if header.split() else header
            adapter_match = re.search(r"(?i)\badapter\b\s+(.+)$", header)
            if adapter_match:
                name = adapter_match.group(1).strip()
            elif "adaptador" in low and header.split():
                name = header.split()[-1]
            current = {
                "name": name,
                "ip": None,
                "prefix": None,
                "mac": None,
                "up": False,
                "loopback": "loopback" in low or "bucle" in low,
                "wireless": any(k in low for k in ("wireless", "wi-fi", "wlan", "inalambr")),
            }
            ifaces.append(current)
            continue
        if current is None:
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key_fold = fold_text(key)
        value = value.strip()
        mac_match = re.search(r"(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}", value)
        if mac_match and not current["mac"]:
            current["mac"] = normalize_mac(mac_match.group(0))
        if "ipv4" in key_fold and not any(
            k in key_fold for k in ("mask", "subnet", "mascara", "masque", "subnetz")
        ):
            ipv4 = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", value)
            if ipv4:
                current["ip"] = ipv4.group(1)
                current["up"] = True
                if current["ip"].startswith("127."):
                    current["loopback"] = True
        if any(k in key_fold for k in (
            "subnet mask", "subnetmask", "mascara de subred",
            "masque de sous-reseau", "subnetzmaske",
        )):
            mask = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", value)
            if mask:
                current["prefix"] = _netmask_to_prefix(mask.group(1))
    result: list[dict] = []
    for iface in ifaces:
        if iface["ip"] and iface["prefix"] is None:
            iface["prefix"] = 24
        if iface["loopback"]:
            iface["up"] = True
        # Descarta bloques de tuneles sin direccion ni MAC.
        if iface["ip"] is None and iface["mac"] is None:
            continue
        result.append(iface)
    return result


def _windows_interfaces_ipconfig() -> list[dict]:
    rc, out, _ = run(["ipconfig", "/all"], timeout=10)
    if rc != 0 and not out:
        return []
    return _parse_ipconfig(out)


def _windows_interfaces() -> list[dict]:
    global _WIN_IFACE_CACHE
    now = time.time()
    if _WIN_IFACE_CACHE[1] is not None and now - _WIN_IFACE_CACHE[0] < _CACHE_TTL:
        return [dict(item) for item in _WIN_IFACE_CACHE[1]]
    data = powershell_json(_PS_INTERFACES, timeout=12)
    ifaces: list[dict] = []
    if isinstance(data, dict):
        data = [data]
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            prefix = item.get("prefix")
            try:
                prefix = int(prefix) if prefix is not None else None
            except (TypeError, ValueError):
                prefix = None
            mac = item.get("mac")
            ifaces.append({
                "name": str(item["name"]),
                "ip": item.get("ip"),
                "prefix": prefix,
                "mac": normalize_mac(mac) if mac else None,
                "up": bool(item.get("up")),
                "loopback": bool(item.get("loopback")),
                "wireless": bool(item.get("wireless")),
            })
    if not ifaces:
        ifaces = _windows_interfaces_ipconfig()
    _WIN_IFACE_CACHE = (now, [dict(item) for item in ifaces])
    return ifaces


def get_interfaces() -> list[dict]:
    #retorna interfaces con ipv4 - prefijo - MAC
    if IS_WINDOWS:
        return _windows_interfaces()
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
    if IS_WINDOWS:
        for iface in get_interfaces():
            if iface["name"].lower() == ifname.lower():
                return iface.get("mac")
        return None
    try:
        with open(f"/sys/class/net/{ifname}/address") as fh:
            return fh.read().strip()
    except OSError:
        return None


def read_operstate(ifname: str) -> str | None:
    if IS_WINDOWS:
        for iface in get_interfaces():
            if iface["name"].lower() == ifname.lower():
                return "up" if iface.get("up") else "down"
        return None
    try:
        with open(f"/sys/class/net/{ifname}/operstate") as fh:
            return fh.read().strip()
    except OSError:
        return None


def get_interface_ip(ifname: str) -> str | None:
    if IS_WINDOWS:
        for iface in get_interfaces():
            if iface["name"].lower() == ifname.lower():
                return iface.get("ip")
        return None
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


def _parse_route_print(text: str) -> dict | None:
    for line in text.splitlines():
        parts = line.split()
        if (len(parts) >= 4 and parts[0] == "0.0.0.0"
                and parts[1] == "0.0.0.0" and is_valid_ip(parts[2])
                and is_valid_ip(parts[3])):
            return {"gateway": parts[2], "prefsrc": parts[3]}
    return None


def _windows_default_route() -> dict | None:
    rc, out, _ = run(["route", "print", "-4"], timeout=8)
    if rc == 0:
        route = _parse_route_print(out)
        if route:
            source = route.get("prefsrc")
            if is_valid_ip(source):
                for iface in get_interfaces():
                    if iface.get("ip") == source:
                        route["dev"] = iface["name"]
                        break
            return route
    data = powershell_json(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | "
        "Select-Object -First 1 | ForEach-Object { [PSCustomObject]@{ gateway=$_.NextHop; "
        "prefsrc=(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 | "
        "Select-Object -First 1).IPAddress; dev=$_.InterfaceAlias } } | ConvertTo-Json -Compress",
        timeout=10,
    )
    if isinstance(data, dict) and data.get("gateway"):
        return data
    # Ultimo recurso: puerta de enlace de ipconfig
    rc, out, _ = run(["ipconfig"], timeout=8)
    if rc == 0:
        gateway = None
        for line in out.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key_fold = fold_text(key)
            if any(k in key_fold for k in ("gateway", "puerta de enlace", "passerelle")):
                match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", value)
                if match:
                    gateway = match.group(1)
        if gateway:
            return {"gateway": gateway}
    return None


def default_route() -> dict | None:
    if IS_WINDOWS:
        return _windows_default_route()
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
    ip: str | None = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    except OSError:
        ip = None
    finally:
        sock.close()
    if ip:
        return ip
    # Sin ruta a Internet: usa la primera interfaz activa con IPv4.
    for iface in get_interfaces():
        if not iface["loopback"] and iface.get("ip"):
            return iface["ip"]
    return None


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


_WIN_WLAN_CACHE: tuple[float, list[str] | None] = (0.0, None)


def _windows_wlan_names() -> list[str]:
    global _WIN_WLAN_CACHE
    now = time.time()
    if _WIN_WLAN_CACHE[1] is not None and now - _WIN_WLAN_CACHE[0] < 10.0:
        return list(_WIN_WLAN_CACHE[1])
    rc, out, _ = run(["netsh", "wlan", "show", "interfaces"], timeout=8)
    names: list[str] = []
    if rc == 0:
        for line in out.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key_fold = fold_text(key).strip()
            if key_fold in ("name", "nombre", "nom"):
                value = value.strip()
                if value and value not in names:
                    names.append(value)
    _WIN_WLAN_CACHE = (now, list(names))
    return names


def is_wireless(ifname: str) -> bool:
    if IS_WINDOWS:
        for iface in get_interfaces():
            if iface["name"].lower() == ifname.lower() and iface.get("wireless"):
                return True
        return ifname.lower() in {n.lower() for n in _windows_wlan_names()}
    return os.path.isdir(f"/sys/class/net/{ifname}/wireless")


def wireless_interfaces() -> list[str]:
    if IS_WINDOWS:
        names = [
            iface["name"] for iface in get_interfaces()
            if not iface["loopback"] and iface.get("wireless")
        ]
        return names or _windows_wlan_names()
    ifaces: list[str] = []
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


def _parse_dns_ipconfig(text: str) -> list[str]:
    servers: list[str] = []
    collecting = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            collecting = False
            continue
        if ":" in raw:
            key, _, value = raw.partition(":")
            key_fold = fold_text(key)
            collecting = "dns" in key_fold and any(
                k in key_fold for k in ("server", "servidor", "serveur", "dns-server")
            )
            if collecting:
                servers.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value))
            continue
        if collecting and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", stripped):
            servers.append(stripped)
        else:
            collecting = False
    return servers


def _windows_nameservers() -> list[str]:
    global _WIN_NS_CACHE
    now = time.time()
    if _WIN_NS_CACHE[1] is not None and now - _WIN_NS_CACHE[0] < 30.0:
        return list(_WIN_NS_CACHE[1])
    servers: list[str] = []
    data = powershell_json(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { "
        "$_.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique | "
        "ConvertTo-Json -Compress",
        timeout=10,
    )
    if isinstance(data, str):
        servers = [data]
    elif isinstance(data, list):
        servers = [str(item) for item in data if item]
    if not servers:
        rc, out, _ = run(["ipconfig", "/all"], timeout=10)
        if rc == 0:
            servers = _parse_dns_ipconfig(out)
    seen: list[str] = []
    for server in servers:
        if server not in seen:
            seen.append(server)
    _WIN_NS_CACHE = (now, list(seen))
    return seen


def nameservers() -> list[str]:
    if IS_WINDOWS:
        servers = _windows_nameservers()
        return servers or ["1.1.1.1", "8.8.8.8"]
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
    if not servers and IS_MAC:
        rc, out, _ = run(["scutil", "--dns"], timeout=5)
        if rc == 0:
            servers.extend(re.findall(r"nameserver\[\d+\]\s*:\s*([0-9a-fA-F:.]+)", out))
    return servers or ["1.1.1.1", "8.8.8.8"]



def now_str() -> str:
    return _dt.datetime.now().strftime("%d-%m-%Y %H:%M:%S")


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
    #ocultar mac, fines practicas
    if len(parts) == 6:
        if keep_oui:
            return ":".join([parts[0], parts[1], parts[2], hidden, hidden, hidden])
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
