#whois informacion de registro de dominios y ips


from __future__ import annotations

import ipaddress
import re
import socket

from . import util

_DEFAULT_SERVER = "whois.iana.org"
_REFER_RE = re.compile(r"(?:refer|referralserver|whois):\s*([^\s]+)", re.IGNORECASE)


def _query(server: str, query_text: str, timeout: float = 10.0) -> str:
    server = server.replace("whois://", "").split("/")[0].split(":")[0]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, 43))
        sock.sendall((query_text + "\r\n").encode("latin-1", "replace"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 1_000_000:
                break
        return b"".join(chunks).decode("latin-1", "replace")
    finally:
        sock.close()


def _follow_referral(text: str) -> str | None:
    for line in text.splitlines():
        m = _REFER_RE.match(line.strip())
        if m:
            server = m.group(1)
            if server and server.lower() not in ("", "whois://"):
                return server
    return None


def whois(target: str, timeout: float = 12.0) -> str:
    target = target.strip()
    if not target:
        return ""

    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        text = _query("whois.arin.net", f"n + {target}", timeout=timeout)
    else:
        tld = target.rsplit(".", 1)[-1].lower()
        iana = _query(_DEFAULT_SERVER, tld, timeout=timeout)
        referral = _follow_referral(iana)
        if not referral:
            return iana
        text = _query(referral, target, timeout=timeout)

    # Seguir una referencia adicional (ARIN -> RIR, etc.).
    referral = _follow_referral(text)
    if referral and referral.lower() != "whois.iana.org":
        try:
            deeper = _query(referral, target, timeout=timeout)
            if deeper.strip():
                text = deeper
        except OSError:
            pass
    return text


_HIGHLIGHT = (
    "domain name", "registrar:", "registrant", "name server", "nserver",
    "creation date", "created", "updated date", "expiry", "expiration",
    "orgname", "org-name", "organisation", "country", "netname", "cidr",
    "inetnum", "netrange", "abuse-mailbox", "descr", "status",
)


def print_whois(target: str, text: str) -> None:
    util.title(f"WHOIS -> {target}")
    if not text.strip():
        util.warn("server =/ no conexion")
        return
    printed = 0
    for line in text.splitlines():
        low = line.lower()
        if any(key in low for key in _HIGHLIGHT):
            util.kv(line.split(":", 1)[0].strip(), line.split(":", 1)[1].strip()
                    if ":" in line else "")
            printed += 1
    if printed == 0:
        print(text)
    else:
        print(util.Style.paint("\n (respuesta completa)", util.Style.GREY))


def run_menu() -> None:
    target = input("Dominio o IP: ").strip()
    if not target:
        return
    util.info(f"consulta whois de {target}...")
    try:
        text = whois(target)
    except OSError as exc:
        util.err(f"Error whois: {exc}")
        return
    print_whois(target, text)
    show = input("Mostrar respuesta completa? [s/N]: ").strip().lower()
    if show == "s":
        print(text)
