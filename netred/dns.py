#DNS: resolucion directa, inversa y consultas de registros

##
#registros A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV y CAA.


from __future__ import annotations

import ipaddress
import random
import socket
import struct

from . import util

QTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "CAA": 257,
}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    original = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            if not jumped:
                original = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset : offset + length].decode("latin-1"))
        offset += length
    return ".".join(labels), (original if jumped else offset)


def _build_query(name: str, qtype: int, qid: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype, 1)
    return header + question


def _parse_rdata(rtype: int, data: bytes, offset: int, rdlength: int) -> list[str]:
    end = offset + rdlength
    if rtype == 1:  # A
        return [socket.inet_ntoa(data[offset:offset + 4])]
    if rtype == 28:  # AAAA
        return [socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])]
    if rtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = _read_name(data, offset)
        return [name]
    if rtype == 15:  # MX
        pref = struct.unpack("!H", data[offset : offset + 2])[0]
        exchange, _ = _read_name(data, offset + 2)
        return [f"{pref} {exchange or '.'}"]
    if rtype == 16:  # TXT
        strings = []
        pos = offset
        while pos < end:
            ln = data[pos]
            strings.append(data[pos + 1 : pos + 1 + ln].decode("latin-1", "replace"))
            pos += 1 + ln
        return ['"' + "".join(strings) + '"']
    if rtype == 33:  # SRV
        priority, weight, port = struct.unpack("!HHH", data[offset : offset + 6])
        target, _ = _read_name(data, offset + 6)
        return [f"{priority} {weight} {port} {target}"]
    if rtype == 6:  # SOA
        mname, pos = _read_name(data, offset)
        rname, pos = _read_name(data, pos)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[pos : pos + 20])
        return [f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"]
    if rtype == 257:  # CAA
        flags = data[offset]
        tag_len = data[offset + 1]
        tag = data[offset + 2 : 2 + offset + tag_len].decode("latin-1")
        value = data[offset + 2 + tag_len : end].decode("latin-1", "replace")
        return [f'{flags} {tag} "{value}"']
    return [data[offset:end].hex()]

#CONSLUIDATSA DE REGISTROS DNS
def query(name: str, rtype: str = "A", server: str | None = None,
          timeout: float = 3.0) -> dict:

    rtype = rtype.upper()
    if rtype not in QTYPES:
        return {"name": name, "type": rtype, "answers": [], "error": "tipo no soportado"}
    servers = [server] if server else util.nameservers()
    qid = random.randint(0, 0xFFFF)
    packet = _build_query(name, QTYPES[rtype], qid)

    last_error = "NO ANSWER"
    for srv in servers:
        family = socket.AF_INET6 if ":" in srv else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (srv, 53))
            data, _ = sock.recvfrom(4096)
        except (socket.timeout, OSError) as exc:
            last_error = str(exc)
            continue
        finally:
            sock.close()

        if len(data) < 12:
            last_error = "ANSWER TRUNCA"
            continue
        (rid, flags, qd, an, ns, ar) = struct.unpack("!HHHHHH", data[:12])
        if rid != qid:
            continue
        rcode = flags & 0x0F
        if rcode != 0:
            return {"name": name, "type": rtype, "answers": [], "rcode": rcode,
                    "error": f"rcode={rcode}"}
        offset = 12
        for _ in range(qd):
            _, offset = _read_name(data, offset)
            offset += 4
        answers: list[dict] = []
        for _ in range(an):
            _, offset = _read_name(data, offset)
            rtype_num, _, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            values = _parse_rdata(rtype_num, data, offset, rdlength)
            offset += rdlength
            answers.append({
                "type": QTYPE_NAMES.get(rtype_num, str(rtype_num)),
                "ttl": ttl,
                "values": values,
            })
        return {"name": name, "type": rtype, "answers": answers, "server": srv}

    return {"name": name, "type": rtype, "answers": [], "error": last_error}

# A + AAAA
def lookup(name: str) -> dict:

    return {"A": query(name, "A"), "AAAA": query(name, "AAAA")}

# RESOLUVION INVERSA PTR
def reverse(ip: str) -> dict:

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "IP invalida"}
    if parsed.version == 4:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    else:
        rev = parsed.reverse_pointer
    return query(rev, "PTR")


def all_records(name: str) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for rtype in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"):
        results[rtype] = query(name, rtype)
    return results


def _print_result(res: dict) -> None:
    name = res.get("name", "")
    rtype = res.get("type", "")
    header = f"{rtype} -> {name}"
    answers = res.get("answers", [])
    if not answers:
        reason = res.get("error", "sin registros")
        print(f"  {util.Style.paint(header, util.Style.CYAN)}: "
              f"{util.Style.paint(reason, util.Style.YELLOW)}")
        return
    print(f"  {util.Style.paint(header, util.Style.CYAN, util.Style.BOLD)}")
    for ans in answers:
        for value in ans["values"]:
            print(f"      {value}  {util.Style.paint('TTL=' + str(ans['ttl']), util.Style.GREY)}")


def run_menu() -> None:
    target = input("Dominio o IP: ").strip()
    if not target:
        return
    util.title(f"DNS -> {target}")
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        _print_result(reverse(target))
        return
    mode = input("  [1] A/AAAA  [2] Todos los registros  [3] Tipo concreto [1]: ").strip() or "1"
    if mode == "2":
        for res in all_records(target).values():
            _print_result(res)
    elif mode == "3":
        rtype = input("Tipo (A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA): ").strip().upper()
        _print_result(query(target, rtype))
    else:
        for res in lookup(target).values():
            _print_result(res)
