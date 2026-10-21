
from __future__ import annotations

import socket
import struct

from . import dns, util

_MDNS_ADDR = "224.0.0.251"
_MDNS_PORT = 5353
_META = "_services._dns-sd._udp.local"

# consult mdns with  bit qu
def _query_name(name: str, qtype: int, timeout: float = 2.5) -> list[dict]:

    qid = 0x0000  # En mDNS el ID suele ser 0
    header = struct.pack("!HHHHHH", qid, 0x0000, 1, 0, 0, 0)
    question = dns._encode_name(name) + struct.pack("!HH", qtype | 0x8000, 1)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)
    records: list[dict] = []
    try:
        sock.sendto(packet, (_MDNS_ADDR, _MDNS_PORT))
        while True:
            try:
                data, _ = sock.recvfrom(9000)
            except socket.timeout:
                break
            records.extend(_parse_records(data))
    finally:
        sock.close()
    return records


def _parse_records(data: bytes) -> list[dict]:
    if len(data) < 12:
        return []
    (_, _, qd, an, ns, ar) = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        _, offset = dns._read_name(data, offset)
        offset += 4
    records: list[dict] = []
    for _ in range(an + ns + ar):
        name, offset = dns._read_name(data, offset)
        rtype, _, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        values = dns._parse_rdata(rtype, data, offset, rdlength)
        offset += rdlength
        records.append({
            "name": name,
            "type": dns.QTYPE_NAMES.get(rtype, str(rtype)),
            "ttl": ttl,
            "values": values,
        })
    return records


def browse_mdns(service_type: str = _META, timeout: float = 2.5) -> list[dict]:
    records = _query_name(service_type, dns.QTYPES["PTR"], timeout=timeout)
    services: dict[str, dict] = {}
    for rec in records:
        if rec["type"] != "PTR":
            continue
        for target in rec["values"]:
            services[target] = {"service": target, "name": rec["name"]}
    return list(services.values())


def browse_avahi() -> list[dict]:
    if not util.have("avahi-browse"):
        return []
    rc, out, errp = util.run(["avahi-browse", "-atp"], timeout=6)
    if rc != 0 or "Daemon not running" in errp:
        return []
    services: list[dict] = []
    for line in out.splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 8:
            continue
        services.append({
            "iface": parts[1],
            "protocol": parts[2],
            "name": parts[3],
            "service": parts[4],
            "hostname": parts[6],
            "address": parts[7],
        })
    return services

# list service bnjourno y mdns dispon
def browse() -> list[dict]:

    services = browse_avahi()
    if services:
        return services
    return browse_mdns()


def print_services(services: list[dict]) -> None:
    util.title("service bnjourno y mdns")
    rows = []
    for s in services:
        rows.append([
            s.get("service", "-"),
            s.get("name", "-"),
            s.get("address", s.get("hostname", "-")),
            s.get("iface", s.get("protocol", "-")),
        ])
    util.table(["Servicio", "Nombre", "Direccion", "Interfaz"], rows)


def run_menu() -> None:
    util.info("exploring service bonjour - mdns")
    services = browse()
    if not services:
        util.warn("no services")
    print_services(services)
