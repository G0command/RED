#program de info del equipo y de su red

#print  hostname, ip, mac, puerta de enlace, red local, dns y la ip y isp


from __future__ import annotations

import socket

from . import isp, util


def show(include_public: bool = True) -> None:
    util.title("Informacion basica del equipo / red")
    util.kv("Hostname", socket.gethostname())
    util.kv("SO", util.Style.strip(_os_name()))
    util.kv("Fecha/Hora", util.now_str())

    util.title("Interfaces")
    rows = []
    for iface in util.get_interfaces():
        if iface["loopback"]:
            continue
        rows.append([
            iface["name"],
            iface["ip"] or "-",
            f"/{iface['prefix']}" if iface["prefix"] else "-",
            iface["mac"] or "-",
            "UP" if iface["up"] else "down",
            "Wi-Fi" if util.is_wireless(iface["name"]) else "Ethernet",
        ])
    util.table(["Interfaz", "IP", "Prefijo", "MAC", "Estado", "Tipo"], rows)

    util.title("Red local")
    gateway = util.get_gateway()
    network = util.local_network()
    util.kv("Puerta de enlace", gateway or "-")
    util.kv("Red local", str(network) if network else "-")
    util.kv("IP local", util.get_local_ip() or "-")
    util.kv("Servidores DNS", ", ".join(util.nameservers()))

    if include_public:
        util.title("Salida a Internet")
        info = isp.public_info()
        if info.get("error"):
            util.warn(f"ERROR IP PUBLIC =/= AVIABLE: {info['error']}")
        else:
            util.kv("IP publica", info.get("ip") or "-")
            util.kv("ISP", info.get("isp") or "-")
            location = ", ".join(filter(None, [info.get("city"), info.get("country")]))
            util.kv("Ubicacion", location or "-")


def _os_name() -> str:
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    import platform

    return platform.platform()


def run_menu() -> None:
    show()
