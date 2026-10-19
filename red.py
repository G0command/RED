#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from netred import (
    bonjour,
    connect,
    dns,
    initial,
    inventory,
    ipcalc,
    isp,
    monitor,
    netinfo,
    netscan,
    ping,
    portscan,
    speedtest,
    traceroute,
    upnp,
    util,
    whois,
    wifi,
    wol,
)

BANNER1 = r"""
████████╗██╗  ██╗███████╗    ███████╗███╗   ██╗██████╗
╚══██╔══╝██║  ██║██╔════╝    ██╔════╝████╗  ██║██╔══██╗
   ██║   ███████║█████╗      █████╗  ██╔██╗ ██║██║  ██║
   ██║   ██╔══██║██╔══╝      ██╔══╝  ██║╚██╗██║██║  ██║
   ██║   ██║  ██║███████╗    ███████╗██║ ╚████║██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚══════╝╚═╝  ╚═══╝╚═════╝
"""
BANNER = r"""
                        .@@@@@@@@@@@@@@.
                        @ ...........  @
                     .  @ @@@@@@@@@@@@ @  .
                  . .@@. .@@@@@@@@@@@@   @@. .
                  @@  @@@@@@@@@@@@@@@@@@@@  @@
              . @@ @@@@@@@@@@@@  @@@@@@@@@@@@ @@ -
             ..@.:@@@@@@@@@+.      .=@@@@@@@@@: @..
            .%@ @@@@@@@@     .*  *.    .@@@@@@@@ @%
            #@ @@@@@@@   .@@@@@  @@@@@   .@@@@@@@ @#
          ..@.@@@@@@@  .@@@@@@@  @@@@@@@.  @@@@@@@ @..
           @ *@@@@@@  @@@@@@@@.   @@@@@@@@  @@@@@@* @
         : @ @@@@@@  :@@@@@@@@#  #@@@@@@@@-  @@@@@@ @.-
          -@ @@@@@@  @@@@@@@@@@-:@@@@@@@@@@  %@@@@@ %=
          %: @@@@@.  @@@@@@@@@@@@@@@@@@@@@@  .@@@@@ :%
         .-@ @@@@@@  @@@@@    @@@@    @@@@@  %@@@@@ %=
       . +@  @@@@@@  :@@     @@@@@@     @@-  @@@@@@ .@* -
      . @ .@@@@@@@@@    @@@@@@@@@@@@@@@@    @@@@@@@@@  @ -
        .@ @@@@@@@     .@@@@@@@@@@@@@@@@      @@@@@@@ @.
         .@ @@@@@@@@@@   .@@@@@@@@@@@@.   @@@@@@@@@@ @
          .@ @@@@@@@@@@@     .*@@*.     @@@@@@@@@@@ @.
          . @ @@@@@@@@@@@@@+        +@@@@@@@@@@@@@ @ .
           . @ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @ .
            . @  .@@  @@@@@@@@@@@@@@@@@@@@  @@.  @ :
             : #    .@@  .@@@@@@@@@@@@.  @@.    # -
                     .  @@@@.      .@@@@  .
"""

_TOOLS = [
    ("Info del equipo/red", netinfo.run_menu),
    ("Watcher (monitor de recursos remotos)", monitor.run_watcher_menu),
    ("Local-Area Network (dispositivos de la red)", netscan.run_lan_menu),
    ("Ping (ICMP / TCP / HTTP)", ping.run_ping_menu),
    ("Traceroute / Visual Traceroute", traceroute.run_menu),
    ("Port scanner (TCP)", portscan.run_menu),
    ("Whois", whois.run_menu),
    ("UPnP scanner (UPnP/DLNA)", upnp.run_menu),
    ("Bonjour browser (mDNS)", bonjour.run_menu),
    ("Wi-Fi scanner", wifi.run_menu),
    ("Speedtest", speedtest.run_menu),
    ("Subnet scanner", netscan.run_subnet_menu),
    ("DNS Lookup (directo e inverso)", dns.run_menu),
    ("Wake on LAN", wol.run_menu),
    ("IP Calculator", ipcalc.run_menu),
    ("Analisis/ubicacion de ISP + conectividad", isp.run_menu),
    ("Conectar a puertos (navegador/SSH/FTP)", connect.run_menu),
    ("Inventario de dispositivos y redes", inventory.run_menu),
    ("Deteccion de intrusos", monitor.run_intruder_menu),
    ("Monitorizacion de red (online/offline)", monitor.run_monitor_menu),
]


def _show_banner() -> None:
    print(util.Style.paint(BANNER, util.Style.WHITE, util.Style.BOLD))
    print(util.Style.paint(BANNER1, util.Style.WHITE, util.Style.BOLD))
    print(util.Style.paint(f"  H  red - v{__import__('netred').__version__}",
                           util.Style.CYAN))


def _prompt(text: str) -> str:
    try:
        return input(util.Style.paint(text, util.Style.BOLD))
    except EOFError:
        return ""


def tools_menu() -> None:
    while True:
        util.title("A Herramientas de red")
        for i, (name, _) in enumerate(_TOOLS, 1):
            print(f"  {i:>2}) {name}")
        print("   0) Volver")
        choice = _prompt("  Opcion: ").strip()
        if choice in ("0", "", "q"):
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(_TOOLS)):
            util.warn("Opcion invalida.")
            continue
        _, func = _TOOLS[int(choice) - 1]
        try:
            util.title(_TOOLS[int(choice) - 1][0])
            func()
        except KeyboardInterrupt:
            print()
            util.warn("OPERATION ERR--")
        except Exception as exc:  # pragma: no cover - salvavidas
            util.err(f"Error: {exc}")


def interactive() -> None:
    _show_banner()
    while True:
        print()
        print(util.Style.paint("ULTIMATE ESCAN", util.Style.BOLD, util.Style.RED))
        print("    [1] inciar escaneo")
        print(util.Style.paint("herramientas", util.Style.BOLD, util.Style.CYAN))
        print("    [2] menu")
        print(util.Style.paint("#" * 20,util.Style.BOLD, util.Style.GREEN))
        print("    [0] EXIT")
        choice = _prompt("  OPTION: ").strip()
        if choice in ("0", "q", ""):
            return
        if choice == "1":
            try:
                initial.run_interactive()
            except KeyboardInterrupt:
                print()
                util.warn("ESCAN ERR-R")
            except Exception as exc:  # pragma: no cover
                util.err(f"Error: {exc}")
        elif choice == "2":
            tools_menu()
        else:
            util.warn("ERR0R")


# CLI

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red.py",
        description="SCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--no-color", action="store_true", help="desactiva el color")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("scan", help="escaneo inicial (apartado 1)")
    p.add_argument("--speed", action="store_true", help="incluir test de velocidad")
    p.add_argument("--hide-mac", action="store_true", help="ocultar las MAC de los dispositivos")
    p.add_argument("--hide-names", action="store_true", help="ocultar los nombres de los dispositivos")
    p.add_argument("--excel", action="store_true", help="registrar dispositivos en un .xlsx nuevo")
    p.add_argument("--excel-dir", metavar="DIR", help="carpeta para el Excel (por defecto, actual)")
    p.add_argument("--excel-file", metavar="ARCHIVO.xlsx", help="ruta concreta del Excel")
    p.add_argument("--export", metavar="ARCHIVO.csv", help="exportar inventario a CSV")

    sub.add_parser("info", help="informacion basica del equipo y la red")
    sub.add_parser("upnp", help="escaneo UPnP/DLNA")
    sub.add_parser("bonjour", help="navegador Bonjour/mDNS")
    p = sub.add_parser("wifi", help="escaneo Wi-Fi")
    p.add_argument("--verify", action="store_true",
                   help="verifica el mapeo frecuencia -> canal/banda")
    sub.add_parser("speedtest", help="medicion de velocidad")
    sub.add_parser("isp", help="analisis del ISP y ubicacion")
    sub.add_parser("connectivity", help="verificador de conectividad a Internet")
    sub.add_parser("intruders", help="deteccion de intrusos")
    sub.add_parser("inventory", help="inventario de dispositivos")

    p = sub.add_parser("lan", help="dispositivos de la red local")
    p.add_argument("-n", "--network", help="red a escanear (ej. 192.168.1.0/24)")

    p = sub.add_parser("subnet", help="escaner de subred")
    p.add_argument("-n", "--network", help="red a escanear")

    p = sub.add_parser("ping", help="ping ICMP/TCP/HTTP")
    p.add_argument("host")
    p.add_argument("-c", "--count", type=int, default=4)
    p.add_argument("--tcp", type=int, metavar="PORT", help="usar ping TCP")
    p.add_argument("--http", action="store_true", help="usar ping HTTP")

    p = sub.add_parser("trace", help="traceroute / traceroute visual")
    p.add_argument("host")
    p.add_argument("-m", "--max-hops", type=int, default=30)
    p.add_argument("--no-visual", action="store_true")

    p = sub.add_parser("portscan", help="escaner de puertos TCP")
    p.add_argument("host")
    p.add_argument("-p", "--ports", help="puertos (ej. 22,80,1-1024)")
    p.add_argument("--banner", action="store_true", help="capturar banner")

    p = sub.add_parser("whois", help="consulta WHOIS")
    p.add_argument("target")

    p = sub.add_parser("dns", help="busqueda DNS directa e inversa")
    p.add_argument("target")
    p.add_argument("-t", "--type", default="A", help="tipo de registro o 'all'")

    p = sub.add_parser("wol", help="Wake on LAN")
    p.add_argument("mac")
    p.add_argument("-b", "--broadcast", help="direccion de broadcast")
    p.add_argument("--port", type=int, default=9)

    p = sub.add_parser("ipcalc", help="calculadora IP")
    p.add_argument("network")
    p.add_argument("--split", type=int, metavar="N", help="dividir en N subredes")

    p = sub.add_parser("watcher", help="monitor continuo de recursos remotos")
    p.add_argument("targets", help="host[:puerto], separados por coma")
    p.add_argument("-i", "--interval", type=float, default=5.0)

    p = sub.add_parser("monitor", help="monitoriza dispositivos online/offline")
    p.add_argument("-n", "--network", help="red a monitorizar")
    p.add_argument("-i", "--interval", type=float, default=15.0)

    p = sub.add_parser("connect", help="conectar a un puerto (navegador/SSH/FTP)")
    p.add_argument("host")
    p.add_argument("--ssh", action="store_true")
    p.add_argument("--ftp", action="store_true")
    p.add_argument("-p", "--port", type=int)
    p.add_argument("-u", "--user")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        util.Style.set_enabled(False)

    if not args.command:
        try:
            interactive()
        except KeyboardInterrupt:
            print()
        return 0

    cmd = args.command
    try:
        if cmd == "scan":
            initial.run(do_speedtest=args.speed, export=args.export,
                        show_mac=not args.hide_mac, show_names=not args.hide_names,
                        excel=args.excel, excel_dir=args.excel_dir,
                        excel_file=args.excel_file)
        elif cmd == "info":
            netinfo.show()
        elif cmd == "upnp":
            upnp.run_menu()
        elif cmd == "bonjour":
            bonjour.run_menu()
        elif cmd == "wifi":
            if args.verify:
                result = wifi.verify_frequency()
                util.table(["Frecuencia (MHz)", "Canal", "Banda", "OK"],
                           [[c["freq"], c["canal"], c["banda"],
                             util.Style.paint("OK", util.Style.GREEN) if c["ok"]
                             else util.Style.paint("ERROR", util.Style.RED)]
                            for c in result["cases"]])
                util.info("Verificacion global: " + ("correcta" if result["ok"] else "con errores"))
            else:
                wifi.run_menu()
        elif cmd == "speedtest":
            speedtest.print_result(speedtest.measure())
        elif cmd == "isp":
            isp.print_info(isp.public_info())
        elif cmd == "connectivity":
            isp.print_connectivity(isp.check_connectivity())
        elif cmd == "intruders":
            monitor.print_intruders(monitor.detect_intruders())
        elif cmd == "inventory":
            inventory.print_inventory()
        elif cmd == "lan":
            import ipaddress

            network = ipaddress.ip_network(args.network, strict=False) if args.network else util.local_network()
            devices = netscan.discover(network)
            netscan.print_devices(devices)
            util.info(f"Total: {len(devices)}")
        elif cmd == "subnet":
            import ipaddress

            network = ipaddress.ip_network(args.network, strict=False) if args.network else util.local_network()
            alive = netscan.ping_sweep(network)
            util.table(["IP", "RTT (ms)"], [[ip, f"{rtt:.2f}" if rtt is not None else "-"]
                                            for ip, rtt in sorted(alive.items())])
        elif cmd == "ping":
            if args.tcp:
                stats = ping.tcp(args.host, args.tcp, count=args.count)
            elif args.http:
                stats = ping.http(args.host, count=args.count)
            else:
                stats = ping.icmp(args.host, count=args.count)
            ping.print_stats(stats)
        elif cmd == "trace":
            hops = traceroute.trace(args.host, max_hops=args.max_hops, resolve=True)
            if args.no_visual:
                util.table(["Salto", "Host", "RTT (ms)"],
                           [[h["hop"], h.get("host") or "*",
                             f"{h['rtt']:.2f}" if h.get("rtt") is not None else "-"] for h in hops])
            else:
                traceroute.visual(hops)
        elif cmd == "portscan":
            ports = portscan.parse_ports(args.ports)
            results = portscan.scan(args.host, ports, banner=args.banner)
            portscan.print_results(args.host, results, banner=args.banner)
        elif cmd == "whois":
            whois.print_whois(args.target, whois.whois(args.target))
        elif cmd == "dns":
            import ipaddress

            try:
                ipaddress.ip_address(args.target)
                dns._print_result(dns.reverse(args.target))
            except ValueError:
                if args.type.lower() == "all":
                    for res in dns.all_records(args.target).values():
                        dns._print_result(res)
                else:
                    dns._print_result(dns.query(args.target, args.type))
        elif cmd == "wol":
            if wol.wake(args.mac, args.broadcast, args.port):
                util.ok(f"Paquete magico enviado a {args.mac}.")
        elif cmd == "ipcalc":
            data = ipcalc.info(args.network)
            ipcalc.print_info(data)
            if args.split:
                subs = ipcalc.split(args.network, args.split)
                util.table([f"Subred ({len(subs)})"], [[s] for s in subs])
        elif cmd == "watcher":
            monitor.watch(monitor.parse_targets(args.targets), interval=args.interval)
        elif cmd == "monitor":
            import ipaddress

            network = ipaddress.ip_network(args.network, strict=False) if args.network else None
            monitor.monitor_network(network, interval=args.interval)
        elif cmd == "connect":
            if args.ssh:
                connect.ssh(args.host, args.user, args.port or 22)
            elif args.ftp:
                connect.ftp(args.host, args.port or 21, args.user or "anonymous")
            else:
                connect.open_browser(f"{args.host}:{args.port or 80}")
        else:
            parser.print_help()
            return 2
    except KeyboardInterrupt:
        print()
        util.warn("interruption")
        return 130
    except Exception as exc:  # pragma: no cover - salvavidas
        util.err(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
