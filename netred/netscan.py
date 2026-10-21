# PROGRAM Descubrimiento de red:  ARP, barrido de subred y dispositivos



from __future__ import annotations

import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from . import inventory, nbns, util, vendor

_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


#ARP

#RETORNO {ip: {mac, iface, state}} a partir de la tabla ARP
def neighbors() -> dict[str, dict]:

    result: dict[str, dict] = {}
    if util.have("ip"):
        rc, out, _ = util.run(["ip", "neigh", "show"], timeout=5)
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                ip = parts[0]
                mac = None
                iface = None
                state = None
                for i, tok in enumerate(parts):
                    if tok == "dev" and i + 1 < len(parts):
                        iface = parts[i + 1]
                    elif tok == "lladdr" and i + 1 < len(parts):
                        mac = parts[i + 1]
                if parts[-1].isupper():
                    state = parts[-1]
                if mac and mac != "00:00:00:00:00:00":
                    result[ip] = {
                        "mac": util.normalize_mac(mac),
                        "iface": iface,
                        "state": state,
                    }
            return result

    # Fallback: /proc/net/arp
    try:
        with open("/proc/net/arp") as fh:
            lines = fh.readlines()[1:]
        for line in lines:
            cols = line.split()
            if len(cols) >= 4 and cols[3] != "00:00:00:00:00:00":
                result[cols[0]] = {
                    "mac": util.normalize_mac(cols[3]),
                    "iface": cols[5] if len(cols) > 5 else None,
                    "state": None,
                }
    except OSError:
        pass
    return result


#sondeo host
#icmp  de un solo paquete usando ping
def ping_once(ip: str, timeout: float = 1.0) -> tuple[bool, float | None]:

    rc, out, _ = util.run(
        ["ping", "-c", "1", "-n", "-W", str(max(1, int(timeout))), str(ip)],
        timeout=timeout + 2,
    )
    match = _TIME_RE.search(out)
    if rc == 0 and match:
        return True, float(match.group(1))
    return rc == 0, (float(match.group(1)) if match else None)


def tcp_probe(ip: str, port: int, timeout: float = 0.6) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def _host_alive(ip: str, icmp_timeout: float, tcp_ports: list[int]) -> tuple[bool, float | None]:
    alive, rtt = ping_once(ip, icmp_timeout)
    if alive:
        return True, rtt
    for port in tcp_ports:
        if tcp_probe(ip, port, timeout=0.5):
            return True, None
    return False, None


#barrido de host
def ping_sweep(
    network: ipaddress.IPv4Network,
    workers: int = 64,
    timeout: float = 1.0,
    tcp_ports: list[int] | None = None,
) -> dict[str, float | None]:

    hosts = [str(h) for h in network.hosts()]
    tcp_ports = tcp_ports if tcp_ports is not None else [80, 443, 22, 445]
    results: dict[str, float | None] = {}

    def work(ip: str):
        alive, rtt = _host_alive(ip, timeout, tcp_ports)
        if alive:
            results[ip] = rtt

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(work, hosts))
    return results


#Descubrimiento rapido via ARP tras generar trafico
#
#Lanza pings para poblar la cache ARP y despues lee la tabla de vecinos
def arp_scan(network: ipaddress.IPv4Network | None = None, workers: int = 64) -> dict[str, dict]:

    net = network or util.local_network()
    if net is not None:
        ping_sweep(net, workers=workers, timeout=1, tcp_ports=[])
    return neighbors()


# nombres y tipos de dispositivo


def _guess_type(vendor_name: str, hostname: str | None, netbios: str | None,
                model: str | None = None, upnp_type: str | None = None) -> str:
    text = " ".join(filter(None, [vendor_name, hostname, netbios, model, upnp_type])).lower()
    upnp = (upnp_type or "").lower()
    upnp_rules = [
        (("internetgatewaydevice", "wanconnectiondevice", "wandevice",
          "wanipconnection"), "Router/AP"),
        (("mediarenderer", "mediaplayer", "mediaserver", "avtransport"), "Multimedia"),
        (("printer", "printbasic"), "Impresora"),
        (("scanner",), "Escaner"),
        (("digitalsecuritycamera", "camera"), "Camara IP"),
        (("nas", "storage"), "NAS"),
        (("phone",), "Telefono"),
        (("computer", "pc"), "PC"),
        (("tv",), "TV"),
    ]
    for keywords, label in upnp_rules:
        if any(k in upnp for k in keywords):
            return label

    rules = [
        (("internetgatewaydevice", "router", "gateway", "access point", "tp-link",
          "netgear", "d-link", "linksys", "ubiquiti", "huawei", "mikrotik",
          "aruba", "cisco"), "Router/AP"),
        (("iphone", "ipad", "macbook", "apple tv", "homepod", "apple"), "Apple / movil"),
        (("vmware", "virtualbox", "qemu", "kvm", "hyper-v", "virtual"), "Maquina virtual"),
        (("raspberry",), "Raspberry Pi"),
        (("printer", "canon", "epson", "hp inc", "hewlett", "brother", "lexmark",
          "xerox"), "Impresora"),
        (("samsung", "xiaomi", "oneplus", "motorola", "lg electronics", "oppo",
          "vivo", "realme", "sony mobile"), "Movil/Tablet"),
        (("nas", "synology", "qnap", "buffalo", "western digital", "seagate"), "NAS"),
        (("camera", "hikvision", "dahua", "axis", "reolink", "foscam", "wyze"), "Camara IP"),
        (("espressif", "tuya", "sonoff", "shelly", "philips", "hue", "smart",
          "iot", "esp32"), "IoT"),
        (("playstation", "xbox", "nintendo", "sony"), "Consola"),
        (("roku", "chromecast", "google", "amazon", "fire tv", "nvidia",
          "shield"), "Multimedia"),
        (("intel", "dell", "lenovo", "asus", "gigabyte", "msi", "micro-star",
          "acer", "toshiba", "hp"), "PC"),
    ]
    for keywords, label in rules:
        if any(k in text for k in keywords):
            return label
    return "No determinado"


def resolve_names(devices: list[dict], workers: int = 32) -> None:
    #hostname|netbios
    def work(device: dict) -> None:
        ip = device["ip"]
        name = util.reverse_dns(ip)
        if not name:
            name = _mdns_reverse_name(ip)
        device["hostname"] = name
        nb = nbns.name_of(ip)
        if nb:
            device["netbios"] = nb

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(work, devices))


def _mdns_reverse_name(ip: str, timeout: float = 1.2) -> str | None:
    """Intenta resolver el nombre por mDNS (PTR inverso) como respaldo."""
    try:
        from . import bonjour, dns  # noqa: PLC0415

        rev = ipaddress.ip_address(ip).reverse_pointer
        for record in bonjour._query_name(rev, dns.QTYPES["PTR"], timeout=timeout):
            if record.get("type") == "PTR" and record.get("values"):
                return record["values"][0].rstrip(".")
    except Exception:
        return None
    return None


def _finalize(device: dict) -> dict:
    device.setdefault("hostname", None)
    device.setdefault("netbios", None)
    device.setdefault("model", None)
    device["vendor"] = device.get("vendor") or vendor.lookup(device.get("mac") or "")
    device["name"] = device.get("hostname") or device.get("netbios") or "(sin nombre)"
    device["type"] = _guess_type(
        device["vendor"], device.get("hostname"), device.get("netbios"),
        device.get("model"), device.get("upnp_type"),
    )
    device.setdefault("state", "online" if device.get("online") else "offline")
    return device


def enrich_from_upnp(devices: list[dict], upnp_devices: list[dict] | None) -> None:
    """Completa nombre, fabricante, modelo y tipo con datos UPnP/DLNA."""
    if not upnp_devices:
        return
    by_ip: dict[str, dict] = {}
    for info in upnp_devices:
        ip = info.get("ip")
        if ip and ip not in by_ip:
            by_ip[ip] = info
    for device in devices:
        info = by_ip.get(device.get("ip"))
        if not info:
            continue
        vendor_name = device.get("vendor") or ""
        if info.get("manufacturer") and (
            not vendor_name or vendor_name in ("Desconocido", "MAC local/aleatoria (no fabricante)")
        ):
            device["vendor"] = info["manufacturer"]
        if info.get("model"):
            device["model"] = info["model"]
        if info.get("device_type"):
            device["upnp_type"] = info["device_type"]
        current_name = device.get("name") or ""
        if info.get("name") and (not current_name or current_name == "(sin nombre)"):
            device["name"] = info["name"]
        if not device.get("type") or device.get("type") == "No determinado":
            device["type"] = _guess_type(
                device.get("vendor") or "", device.get("hostname"),
                device.get("netbios"), device.get("model"), device.get("upnp_type"),
            )


def summarize_detection(devices: list[dict]) -> dict:
    """Cuenta cuantos dispositivos tienen nombre y tipo identificados."""
    total = len(devices)
    named = sum(
        1 for d in devices
        if d.get("name") and d.get("name") not in ("(sin nombre)", "")
    )
    typed = sum(
        1 for d in devices
        if d.get("type") and d.get("type") != "No determinado"
    )
    with_mac = sum(1 for d in devices if (d.get("mac") or "").strip())
    online = sum(1 for d in devices if d.get("state") == "online")
    return {
        "total": total,
        "named": named,
        "typed": typed,
        "with_mac": with_mac,
        "online": online,
        "offline": total - online,
    }


def _merge_device(merged: dict[str, dict], new: dict) -> None:
    ip = new["ip"]
    base = merged.get(ip)
    if base is None:
        merged[ip] = dict(new)
        return
    weak = (None, "", "(sin nombre)", "No determinado", "Desconocido")
    for key in ("mac", "vendor", "hostname", "netbios", "name", "type", "model", "upnp_type"):
        if base.get(key) in weak and new.get(key) not in (None, "", "(sin nombre)",
                                                          "No determinado", "Desconocido"):
            base[key] = new[key]
    if new.get("online"):
        base["online"] = True
        base["state"] = "online"
    if base.get("rtt") is None:
        base["rtt"] = new.get("rtt")


def discover_monitored(
    network: ipaddress.IPv4Network | None = None,
    ifname: str | None = None,
    rounds: int = 2,
    interval: float = 0.8,
    workers: int = 64,
    resolve: bool = True,
    upnp_devices: list[dict] | None = None,
    include_inventory_offline: bool = True,
) -> list[dict]:
    """Escaneo con monitorizacion: varias rondas + dispositivos ya conocidos.

    Detecta equipos online/offline e incorpora IPs conocidas por el inventario
    que una sola pasada no devuelve (marcadas como ``offline``).
    """
    net = network or util.local_network(ifname)
    rounds = max(1, int(rounds))
    merged: dict[str, dict] = {}

    for r in range(rounds):
        found = discover(net, ifname=ifname, resolve=resolve, workers=workers)
        for device in found:
            _merge_device(merged, device)
        if r < rounds - 1:
            time.sleep(interval)

    if include_inventory_offline and net is not None:
        known = inventory.load().get("devices", {})
        for entry in known.values():
            ip = entry.get("ip")
            if not ip or ip in merged:
                continue
            try:
                if ipaddress.ip_address(ip) not in net:
                    continue
            except ValueError:
                continue
            merged[ip] = {
                "ip": ip,
                "mac": entry.get("mac") or "",
                "vendor": entry.get("vendor") or "",
                "hostname": entry.get("hostname"),
                "netbios": entry.get("netbios"),
                "name": entry.get("name") or "(sin nombre)",
                "type": entry.get("type") or "No determinado",
                "model": entry.get("model"),
                "rtt": None,
                "online": False,
                "state": "offline",
                "_from_inventory": True,
            }

    devices = list(merged.values())
    enrich_from_upnp(devices, upnp_devices)
    for device in devices:
        if (not device.get("type") or device["type"] == "No determinado") and not device.get("_from_inventory"):
            device["type"] = _guess_type(
                device.get("vendor") or "", device.get("hostname"),
                device.get("netbios"), device.get("model"), device.get("upnp_type"),
            )
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))



    #Descubre dispositivos de la red local

    #RETORNO de lista de diccionarios con: ip, mac, vendor, hostname, netbios, name, type, state
def discover(
    network: ipaddress.IPv4Network | None = None,
    ifname: str | None = None,
    do_ping: bool = True,
    resolve: bool = True,
    workers: int = 64,
    include_offline: bool = False,
) -> list[dict]:

    net = network or util.local_network(ifname)
    alive: dict[str, float | None] = {}
    if net is not None and do_ping:
        alive = ping_sweep(net, workers=workers)

    neigh = neighbors()
    devices: dict[str, dict] = {}

    for ip, rtt in alive.items():
        info = neigh.get(ip, {})
        devices[ip] = {
            "ip": ip,
            "mac": info.get("mac", ""),
            "rtt": rtt,
            "online": True,
            "state": "online",
        }

    for ip, info in neigh.items():
        if net is not None:
            try:
                if ipaddress.ip_address(ip) not in net:
                    continue
            except ValueError:
                continue
        if ip not in devices:
            devices[ip] = {
                "ip": ip,
                "mac": info.get("mac", ""),
                "rtt": None,
                "online": True,
                "state": "online" if info.get("state") in ("REACHABLE", "STALE", "DELAY", "PROBE") else "offline",
            }

    # Hosts de la red sin respuesta
    if include_offline and net is not None:
        for host in net.hosts():
            sip = str(host)
            if sip not in devices:
                devices[sip] = {
                    "ip": sip,
                    "mac": "",
                    "rtt": None,
                    "online": False,
                    "state": "offline",
                }

    # Incluir / completar la propia maquina
    local_ip = util.get_local_ip()
    if local_ip:
        own_mac = util.read_mac(util.default_interface() or "") or ""
        if local_ip not in devices:
            devices[local_ip] = {
                "ip": local_ip,
                "mac": own_mac,
                "rtt": 0.0,
                "online": True,
                "state": "online",
                "hostname": socket.gethostname(),
            }
        else:
            if not devices[local_ip].get("mac"):
                devices[local_ip]["mac"] = own_mac
            devices[local_ip]["hostname"] = devices[local_ip].get("hostname") or socket.gethostname()

    device_list = list(devices.values())
    if resolve:
        resolve_names(device_list, workers=min(workers, 32))
    return [_finalize(d) for d in sorted(device_list, key=lambda d: ipaddress.ip_address(d["ip"]))]


def print_devices(devices: list[dict], show_mac: bool = True,
                  show_names: bool = True) -> None:
    rows = []
    for d in devices:
        state = d.get("state", "")
        painted = util.Style.paint(state, util.Style.GREEN) if state == "online" else util.Style.paint(state, util.Style.RED)
        mac = d.get("mac") or "-"
        if not show_mac:
            mac = util.mask_mac(d.get("mac")) or "-"
        name = d.get("name") or "-"
        if not show_names:
            name = "██████"
        rows.append(
            [
                d["ip"],
                mac,
                d.get("vendor") or "-",
                name,
                d.get("type") or "-",
                painted,
            ]
        )
    util.table(["IP", "MAC", "Fabricante", "Nombre", "Tipo", "Estado"], rows)


def _ask_network() -> ipaddress.IPv4Network | None:
    text = input("Red a escanear (vacio = red local): ").strip()
    if not text:
        return util.local_network()
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        util.err("NO NETWORK")
        return util.local_network()


def run_lan_menu() -> None:

    network = _ask_network()
    if network is None:
        util.err("NETWORK NO DETERMINADA")
        return
    util.info(f"SCAN {network} ...")
    devices = discover(network)
    util.title(f"Dispositivos en {network}")
    print_devices(devices)
    util.info(f"Total: {len(devices)}")
    save = input("guardar en inventario? [s/N]: ").strip().lower()
    if save == "s":
        from . import inventory  # noqa: PLC0415

        inventory.update(devices, network=str(network))
        util.ok("UPDATED INVENTORY")


def run_subnet_menu() -> None:

    network = _ask_network()
    if network is None:
        util.err("RED NO DETERMINADA")
        return
    util.info(f"Barriendo {network} ...")
    alive = ping_sweep(network)
    rows = [[ip, f"{rtt:.2f} ms" if rtt is not None else "-"] for ip, rtt in sorted(
        alive.items(), key=lambda kv: ipaddress.ip_address(kv[0]))]
    util.title(f"Hosts activos en {network}")
    util.table(["IP", "RTT"], rows)
    util.info(f"Activos: {len(rows)} de {max(network.num_addresses - 2, 0)}")

