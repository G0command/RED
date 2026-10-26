#PROGRAMA DE MONITOR DEL NETWORK: watcher, estado de dispositivos e intrusos
#
# watcher: monitoriza recursos remotos
# monitor de red: estado de los dispositivos online/offline
# intrusos: compara los dispositivos actuales con el inventario conocido

from __future__ import annotations

import ipaddress
import socket
import time

from . import inventory, netscan, util


def parse_targets(text: str, default_port: int = 80) -> list[tuple[str, int]]:
    targets: list[tuple[str, int]] = []
    for chunk in text.replace(" ", "").split(","):
        if not chunk:
            continue
        if ":" in chunk:
            host, _, port = chunk.partition(":")
            targets.append((host, int(port) if port.isdigit() else default_port))
        else:
            targets.append((chunk, default_port))
    return targets


def _probe(host: str, port: int, timeout: float = 2.0) -> tuple[bool, float | None]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        alive = sock.connect_ex((host, port)) == 0
    except OSError:
        alive = False
    finally:
        sock.close()
    rtt = (time.perf_counter() - start) * 1000.0 if alive else None
    return alive, rtt

#MONITOR DE RECURSOS
def watch(targets: list[tuple[str, int]], interval: float = 5.0,
          duration: float | None = None) -> None:

    if not targets:
        return
    util.info("vigilando recursos ...")
    header = f"{'HORA':<10} {'RECURSO':<25} {'ESTADO':<8} {'RTT'}"
    print(util.Style.paint(header, util.Style.BOLD))
    start_time = time.time()
    while True:
        stamp = time.strftime("%H:%M:%S")
        for host, port in targets:
            alive, rtt = _probe(host, port)
            status = util.Style.paint("UP", util.Style.GREEN) if alive else util.Style.paint("DOWN", util.Style.RED)
            rtt_txt = f"{rtt:7.2f} ms" if rtt is not None else "   -"
            print(f"{stamp:<10} {host + ':' + str(port):<25} {status:<16} {rtt_txt}", flush=True)
        if duration and time.time() - start_time >= duration:
            break
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            break

#"MONITOR DEL NETWOERK Y REPORTAR CAMBIOS
def monitor_network(network: ipaddress.IPv4Network | None = None,
                    interval: float = 15.0, duration: float | None = None) -> None:

    net = network or util.local_network()
    if net is None:
        util.err("RED LOCAL NO DETERMINADA")
        return
    util.info(f"Monitorizando {net}...")
    states: dict[str, str] = {}
    start_time = time.time()
    while True:
        devices = netscan.discover(net, resolve=False)
        inventory.update(devices, network=str(net))
        current = {d["ip"]: d["state"] for d in devices}
        if not states:
            util.info(f"Estado inicial: {len(current)} dispositivos")
            states = current
        else:
            for ip, state in current.items():
                old = states.get(ip)
                if old != state:
                    device = next((d for d in devices if d["ip"] == ip), {})
                    label = util.Style.paint(state.upper(), util.Style.GREEN if state == "online" else util.Style.RED)
                    print(f"  [{time.strftime('%H:%M:%S')}] {ip} ({device.get('name', '-')}) -> {label}", flush=True)
            for ip in set(states) - set(current):
                print(f"  [{time.strftime('%H:%M:%S')}] {ip} -> "
                      f"{util.Style.paint('DESAPARECIDO', util.Style.YELLOW)}", flush=True)
            states = current
        if duration and time.time() - start_time >= duration:
            break
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            break



#retorno de dispositivos no presentes en el inventario conocido


def detect_intruders(network: ipaddress.IPv4Network | None = None,
                     devices: list[dict] | None = None) -> list[dict]:

    if devices is None:
        devices = netscan.discover(network, resolve=True)
    known = inventory.load()["devices"]
    known_macs = {k.lower() for k in known.keys()}
    known_ips = {(v.get("ip") or "").lower() for v in known.values()}

    intruders: list[dict] = []
    for device in devices:
        mac = (device.get("mac") or "").lower()
        ip = (device.get("ip") or "").lower()
        if mac and mac in known_macs:
            continue
        if ip and ip in known_ips:
            continue
        intruders.append(device)
    return intruders


def print_intruders(intruders: list[dict]) -> None:
    util.title("DETECCION DE INTRUSOS")
    if not intruders:
        util.ok("no deteccion de dispositvos desconocidos")
        return
    util.warn(f"{len(intruders)} dispositivo(s) desconocido(s):")
    netscan.print_devices(intruders)


def run_watcher_menu() -> None:
    text = input("Recursos host[:puerto], separados por coma (ej. 1.1.1.1:443,8.8.8.8:53): ").strip()
    if not text:
        return
    targets = parse_targets(text)
    try:
        interval = float(input("Intervalo en segundos [5]: ").strip() or "5")
    except ValueError:
        interval = 5.0
    watch(targets, interval=interval)


def run_monitor_menu() -> None:
    network = None
    text = input("Red (vacio = local): ").strip()
    if text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            util.err("ERROR RED, [local activado]")
    try:
        interval = float(input("Intervalo en segundos [15]: ").strip() or "15")
    except ValueError:
        interval = 15.0
    monitor_network(network, interval=interval)


def run_intruder_menu() -> None:
    util.info("Comparando dispositivos actuales con el inventario...")
    intruders = detect_intruders()
    print_intruders(intruders)
    if intruders:
        save = input("add this devices to inventoru? [s/N]: ").strip().lower()
        if save == "s":
            inventory.update(intruders)
            util.ok("updated invetory")
