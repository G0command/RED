#[escan de puertos  ]+ [hilos]\



from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from . import util

COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 500: "isakmp",
    514: "syslog", 515: "printer", 548: "afp", 554: "rtsp", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 4444: "krb5", 5000: "upnp", 5432: "postgresql",
    5900: "vnc", 6000: "x11", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9000: "cslistener", 9090: "websm",
    9100: "jetdirect", 10000: "snet-sensor-mgmt", 11211: "memcached",
    27017: "mongodb", 32400: "plex", 49152: "upnp",
}

_TOP_PORTS = list(COMMON_PORTS.keys())


def parse_ports(spec: str | None) -> list[int]:
    #lista de puertos unicos y ordenados
    if not spec:
        return sorted(_TOP_PORTS)
    ports: set[int] = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            try:
                a, b = int(lo), int(hi)
            except ValueError:
                continue
            for p in range(max(1, a), min(65535, b) + 1):
                ports.add(p)
        else:
            try:
                ports.add(int(chunk))
            except ValueError:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)


def _service(port: int) -> str:
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "desconocido"


def _grab_banner(ip: str, port: int, timeout: float) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if port in (80, 443, 8080, 8000, 8888, 3000):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        sock.settimeout(1.5)
        data = sock.recv(256)
        sock.close()
        text = data.decode("latin-1", "replace").strip()
        return text.splitlines()[0][:120] if text else None
    except OSError:
        return None


def scan(host: str, ports: list[int] | None = None, workers: int = 256,
         timeout: float = 0.6, banner: bool = False) -> list[dict]:
    #scan  connect de puertos tcp abiertos
    ports = ports if ports is not None else sorted(_TOP_PORTS)
    open_ports: list[dict] = []

    def work(port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) == 0:
                result = {"port": port, "service": _service(port)}
                if banner:
                    result["banner"] = _grab_banner(host, port, timeout)
                return result
        except OSError:
            return None
        finally:
            sock.close()
        return None

    with ThreadPoolExecutor(max_workers=min(workers, len(ports) or 1)) as pool:
        for result in pool.map(work, ports):
            if result:
                open_ports.append(result)
    open_ports.sort(key=lambda r: r["port"])
    return open_ports


def print_results(host: str, results: list[dict], banner: bool = False) -> None:
    util.title(f"Puertos abiertos en {host}")
    headers = ["Puerto", "Servicio"] + (["Banner"] if banner else [])
    rows = []
    for r in results:
        row = [r["port"], r["service"]]
        if banner:
            row.append((r.get("banner") or "-")[:80])
        rows.append(row)
    util.table(headers, rows)
    util.info(f"Total abiertos: {len(results)}")


def run_menu() -> None:
    host = input("Host o IP: ").strip()
    if not host:
        return
    spec = input("Puertos (ej. 22,80,1-1024) [top comunes]: ").strip()
    ports = parse_ports(spec or None)
    banner = input("Obtener banner? [s/N]: ").strip().lower() == "s"
    util.info(f"Escaneando {len(ports)} puertos en {host}...")
    results = scan(host, ports, banner=banner)
    print_results(host, results, banner=banner)
