#despiertar equipos program

#construye el paquete magico [6x 0xFF + 16 repeticiones de la mac] y lo envia por udp broadcast


from __future__ import annotations

import ipaddress
import socket
import time

from . import util


def _magic_packet(mac: str) -> bytes:
    hexonly = "".join(ch for ch in mac if ch.isalnum())
    if len(hexonly) != 12:
        raise ValueError(f"MAC invalida: {mac}")
    mac_bytes = bytes.fromhex(hexonly)
    return b"\xff" * 6 + mac_bytes * 16

#envia brownis retornando tru si se completo con exito la entrega
def wake(mac: str, broadcast: str | None = None, port: int = 9,
         count: int = 3, delay: float = 0.15) -> bool:


    try:
        packet = _magic_packet(mac)
    except ValueError as exc:
        util.err(str(exc))
        return False

    targets = [broadcast] if broadcast else _default_targets()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        for _ in range(count):
            for target in targets:
                try:
                    sock.sendto(packet, (target, port))
                except OSError:
                    pass
            time.sleep(delay)
    finally:
        sock.close()
    return True


def _default_targets() -> list[str]:
    targets = ["255.255.255.255"]
    net = util.local_network()
    if net is not None:
        targets.append(str(net.broadcast_address))
    gw = util.get_gateway()
    if gw:
        targets.append(gw)
    # Sin duplicados, manteniendo orden
    seen: list[str] = []
    for t in targets:
        if t not in seen:
            seen.append(t)
    return seen


def run_menu() -> None:
    mac = input("MAC destino [ej. aa:bb:cc:dd:ee:ff]: ").strip()
    if not mac:
        return
    bcast = input("Broadcast (vacio = automatico): ").strip() or None
    port = input("Puerto UDP [9]: ").strip() or "9"
    if wake(mac, bcast, int(port) if port.isdigit() else 9):
        util.ok(f"Box magic => {mac} ({bcast or 'broadcast auto'}:{port})")
    else:
        util.err("No magic box")
