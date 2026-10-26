# NetBIOS UDP/137 consulta
# => nombre netbios y el dominio de un equipo


from __future__ import annotations

import socket
import struct
import threading

_QUERY_LOCK = threading.Lock()
_TID = 0x1337


def _next_tid() -> int:
    global _TID
    with _QUERY_LOCK:
        _TID = (_TID + 1) & 0xFFFF
        return _TID


# format first level encodig codificando un nombre netbios
def _encode_name(name: bytes) -> bytes:
    out = bytearray()
    for byte in name:
        out.append((byte >> 4) + ord("A"))
        out.append((byte & 0x0F) + ord("A"))
    return bytes(out)


def _build_node_status_query() -> bytes:
    tid = _next_tid()
    header = struct.pack("!HHHHHH", tid, 0x0000, 1, 0, 0, 0)
    # bit comodin "*" + relleno
    wildcard = b"*" + b"\x00" * 15
    question = _encode_name(wildcard) + b"\x00"
    question += struct.pack("!HH", 0x0021, 0x0001)  # NBSTAT, IN
    return header + question


def _parse_node_status(data: bytes) -> dict | None:
    if len(data) < 12:
        return None
    (_, flags, qd, an, _, _) = struct.unpack("!HHHHHH", data[:12])
    if not (flags & 0x8000) or an < 1:
        return None
    #salta cabecera (12) + pregunta (nombre 34 + 4)
    offset = 12
    while offset < len(data) and data[offset] != 0:
        offset += 1
    offset += 1
    offset += 4  # qtype + qclass
    #answer nombre (34) + type(2) + class(2) + ttl(4) + rdlength(2)
    if offset + 34 + 10 > len(data):
        return None
    offset += 34 + 2 + 2 + 4
    rdlength = struct.unpack("!H", data[offset : offset + 2])[0]
    offset += 2
    rdata = data[offset : offset + rdlength]
    if not rdata:
        return None
    num_names = rdata[0]
    names: list[tuple[str, int, int]] = []
    pos = 1
    for _ in range(num_names):
        if pos + 18 > len(rdata):
            break
        raw = rdata[pos : pos + 15]
        suffix = rdata[pos + 15]
        flags_name = struct.unpack("!H", rdata[pos + 16 : pos + 18])[0]
        pos += 18
        try:
            name = raw.decode("cp437").strip()
        except Exception:
            continue
        names.append((name, suffix, flags_name))
    if not names:
        return None

    workstation = None
    workgroup = None
    for name, suffix, flags_name in names:
        is_group = bool(flags_name & 0x8000)
        if suffix == 0x00 and not is_group and not workstation:
            workstation = name
        elif suffix == 0x00 and is_group and not workgroup:
            workgroup = name
        elif suffix == 0x20 and not workstation:
            workstation = name
    return {
        "netbios": workstation or (names[0][0] if names else None),
        "workgroup": workgroup,
        "names": [n[0] for n in names],
    }

#manda peticion de estado de nodo netbios y devuelve los nombres
def query(ip: str, timeout: float = 1.5) -> dict | None:
    packet = _build_node_status_query()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(2048)
        return _parse_node_status(data)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


#1 o devuelve le nomr netbios del equaopio o nada
def name_of(ip: str, timeout: float = 1.5) -> str | None:
    result = query(ip, timeout=timeout)
    return result["netbios"] if result else None
