#Calculadora ip: datos de una red y division en subredes

from __future__ import annotations

import ipaddress

from . import util

#
#calcula la data de una red a partir de ip/ip mask
#

def info(network: str) -> dict:

    network = network.strip().replace(" ", "/") if " " in network else network.strip()
    if "/" not in network:
        network += "/24"
    try:
        iface = ipaddress.ip_interface(network)
        net = iface.network
    except ValueError as exc:
        raise ValueError(f"error network: {exc}") from exc

    hosts = list(net.hosts())
    first = str(hosts[0]) if hosts else None
    last = str(hosts[-1]) if hosts else None
    version = net.version
    try:
        cls = _ipv4_class(net) if version == 4 else "N/A"
    except Exception:
        cls = "N/A"
    return {
        "input": network,
        "version": version,
        "network": str(net),
        "netmask": str(net.netmask),
        "hostmask": str(net.hostmask),
        "broadcast": str(net.broadcast_address) if version == 4 else None,
        "prefix": net.prefixlen,
        "first_host": first,
        "last_host": last,
        "num_addresses": net.num_addresses,
        "num_hosts": max(net.num_addresses - 2, 0) if version == 4 and net.prefixlen < 31
        else net.num_addresses,
        "is_private": net.is_private,
        "class": cls,
    }


def _ipv4_class(net: ipaddress.IPv4Network) -> str:
    first_octet = int(str(net.network_address).split(".")[0])
    if first_octet < 128:
        return "A"
    if first_octet < 192:
        return "B"
    if first_octet < 224:
        return "C"
    if first_octet < 240:
        return "D (multicast)"
    return "E (reservada)"


#
# Divide una red en count subredes del mismo size
#
#
def split(network: str, count: int) -> list[str]:

    base = ipaddress.ip_network(network if "/" in network else network + "/24", strict=False)
    import math

    extra_bits = max(0, math.ceil(math.log2(count)))
    new_prefix = base.prefixlen + extra_bits
    if new_prefix > base.max_prefixlen:
        raise ValueError("error max de divisiones")
    return [str(sub) for sub in base.subnets(new_prefix=new_prefix)]


def print_info(data: dict) -> None:
    util.title(f"Calculadora IP -> {data['input']}")
    util.kv("Version", f"IPv{data['version']}")
    util.kv("Direccion de red", data["network"])
    util.kv("Prefijo (CIDR)", f"/{data['prefix']}")
    util.kv("Mascara de red", data["netmask"])
    util.kv("Mascara inversa", data["hostmask"])
    if data["broadcast"]:
        util.kv("Broadcast", data["broadcast"])
    util.kv("Primer host", data["first_host"] or "-")
    util.kv("Ultimo host", data["last_host"] or "-")
    util.kv("N host utilizables", data["num_hosts"])
    util.kv("N total direcciones", data["num_addresses"])
    util.kv("Clase", data["class"])
    util.kv("Rango", "Privada" if data["is_private"] else "Publica")


def run_menu() -> None:
    network = input("Red (ej. 192.168.1.0/24): ").strip()
    if not network:
        return
    try:
        data = info(network)
    except ValueError as exc:
        util.err(str(exc))
        return
    print_info(data)
    do_split = input("Dividir en subredes? [s/N]: ").strip().lower()
    if do_split == "s":
        try:
            count = int(input("N de subredes: ").strip())
            subs = split(network, count)
        except (ValueError, OSError) as exc:
            util.err(f"Error: {exc}")
            return
        util.table([f"Subred ({len(subs)})"], [[s] for s in subs])
