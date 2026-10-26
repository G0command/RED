#Apartado : ESCANEO


#SSID, MAC del AP, canal, banda, seguridad, tecnologia 802.11,
#marca/modelo, fecha/hora, numero de dispositivos, velocidad de bajada/subida,
#ping e intensidad de senal promedio

#Dispositivos: IP, MAC, fabricante, nombre y estado (online/offline)

from __future__ import annotations

from pathlib import Path

from . import inventory, netscan, ping as ping_mod, speedtest, upnp, util, vendor, wifi, xlsx

_NA = "No determinado"

EXCEL_HEADERS = ["IP", "MAC", "Fabricante", "Nombre", "Tipo", "Estado"]


def _ap_model(gateway: str | None, upnp_devices: list[dict] | None = None) -> str | None:
    #obtener marca/modelo del AP via UPnP en la puerta de enlace
    if not gateway:
        return None
    try:
        devices = upnp_devices if upnp_devices is not None else upnp.discover(timeout=2, retries=1)
        for device in devices:
            if device.get("ip") != gateway:
                continue
            brand = device.get("manufacturer") or ""
            model = device.get("model") or device.get("name") or ""
            combo = f"{brand} {model}".strip()
            if combo:
                return combo
    except Exception:
        pass
    return None


def _signal_fallback(iface: str | None) -> float | None:
    # intensidad signal
    if not iface or util.IS_WINDOWS:
        return None
    try:
        with open("/proc/net/wireless") as fh:
            for line in fh.readlines()[2:]:
                if line.strip().startswith(iface):
                    parts = line.replace(":", " ").split()
                    return float(parts[3])
    except (OSError, ValueError, IndexError):
        return None
    return None


def collect(do_speedtest: bool = False, only_with_mac: bool = False,
            monitor: bool = True, rounds: int = 2) -> dict:
    #recopila data
    summary: dict = {"fecha_hora": util.now_str()}

    #Wi-Fi |punto de acceso
    ap = wifi.current()
    iface = util.default_interface()
    if ap:
        summary["ssid"] = ap.get("ssid") or "(oculta)"
        summary["mac_ap"] = ap.get("bssid") or _NA
        summary["canal"] = ap.get("channel") or _NA
        summary["banda"] = ap.get("band") or _NA
        summary["seguridad"] = ap.get("security") or _NA
        summary["tecnologia"] = ap.get("technology") or _NA
        summary["frecuencia_mhz"] = ap.get("freq")
        signal = ap.get("signal_avg")
        if signal is None:
            signal = _signal_fallback(ap.get("iface"))
        summary["senal_dbm"] = signal
        summary["_wifi"] = True
        summary["_wifi_iface"] = ap.get("iface")
    else:
        summary["ssid"] = "No aplica (red cableada)"
        summary["mac_ap"] = _NA
        summary["canal"] = "No aplica"
        summary["banda"] = "No aplica"
        summary["seguridad"] = "No aplica"
        summary["tecnologia"] = _NA
        summary["frecuencia_mhz"] = None
        summary["senal_dbm"] = None
        summary["_wifi"] = False
        summary["_wifi_iface"] = None

    gateway = util.get_gateway()
    # Una sola consulta UPnP sirve para el AP y para enriquecer dispositivos.
    upnp_devices = upnp.discover(timeout=2, retries=1)
    model = _ap_model(gateway, upnp_devices)
    if not model:
        # Fallback
        neigh = netscan.neighbors()
        gw_mac = neigh.get(gateway, {}).get("mac") if gateway else None
        if gw_mac:
            brand = vendor.lookup(gw_mac)
            if brand and brand != "Desconocido":
                model = f"{brand} (modelo no identificado)"
    summary["marca_modelo"] = model or "omitir"

    #Red y dispositivos
    network = util.local_network(iface)
    if monitor:
        devices = netscan.discover_monitored(
            network, ifname=iface, rounds=rounds, upnp_devices=upnp_devices,
        )
    else:
        devices = netscan.discover(network, ifname=iface, resolve=True)
        netscan.enrich_from_upnp(devices, upnp_devices)

    # Filtro: todo (sin cambios) o solo dispositivos con MAC/fabricante.
    if only_with_mac:
        devices = [d for d in devices if (d.get("mac") or "").strip()]

    detection = netscan.summarize_detection(devices)
    summary["red"] = str(network) if network else _NA
    summary["num_dispositivos"] = len(devices)
    summary["dispositivos"] = devices
    summary["monitor"] = monitor
    summary["rounds"] = rounds if monitor else 1
    summary["only_with_mac"] = only_with_mac
    summary["deteccion"] = detection

    #ping


    ping_target = gateway or "1.1.1.1"
    stats = ping_mod.icmp(ping_target, count=3, timeout=2)
    summary["ping_ms"] = stats["avg"]
    summary["ping_target"] = ping_target

    #vel
    if do_speedtest:
        result = speedtest.measure()
        summary["vel_bajada"] = result.get("down_mbps")
        summary["vel_subida"] = result.get("up_mbps")
        if summary["ping_ms"] is None:
            summary["ping_ms"] = result.get("ping_ms")
    else:
        summary["vel_bajada"] = None
        summary["vel_subida"] = None

    return summary


#
#
#TABLA DE IMPRESION DE ESCANEO ULTIMATE
#
def print_summary(summary: dict, show_mac: bool = True) -> None:
    util.title("ESCANEO TOTAL")
    util.kv("AP (SSID)", summary["ssid"])
    mac_ap = summary["mac_ap"]
    if not show_mac:
        mac_ap = util.mask_mac(mac_ap) if mac_ap not in (None, "", _NA, "No aplica") else mac_ap
    util.kv("MAC AP", mac_ap)
    util.kv("Canal", summary["canal"])
    util.kv("Banda", summary["banda"])
    if summary.get("frecuencia_mhz"):
        util.kv("Frecuencia", f"{summary['frecuencia_mhz']:.0f} MHz")
    util.kv("Seguridad", summary["seguridad"])
    util.kv("Tecnologia", summary["tecnologia"])
    util.kv("Marca/Modelo AP", summary["marca_modelo"])
    util.kv("Fecha / Hora", summary["fecha_hora"])
    util.kv("Red", summary["red"])
    util.kv("n dispositivos", summary["num_dispositivos"])
    #det = summary.get("deteccion") or {}
    #if det:
    #    util.kv("Nombres detectados", f"{det.get('named', 0)}/{det.get('total', 0)}")
    #    util.kv("Tipos detectados", f"{det.get('typed', 0)}/{det.get('total', 0)}")
    #if summary.get("monitor"):
    #    util.kv("Monitorizacion", f"{summary.get('rounds', 1)} rondas | "
    #            f"{det.get('online', 0)} online / {det.get('offline', 0)} offline")
    if summary.get("only_with_mac"):
        util.kv("Filtro", "solo dispositivos con MAC/fabricante")
    down = summary.get("vel_bajada")
    up = summary.get("vel_subida")
    util.kv("Velocidad bajada", f"{down} Mbps" if down is not None else "no medida")
    util.kv("Velocidad subida", f"{up} Mbps" if up is not None else "no medida")
    util.kv("Ping", f"{summary['ping_ms']} ms ({summary.get('ping_target')})"
            if summary.get("ping_ms") is not None else "sin respuesta")
    signal = summary.get("senal_dbm")
    util.kv("Intensidad signal (media)", f"{signal} dBm" if signal is not None else "no disponible")


def print_devices(summary: dict, show_mac: bool = True, show_names: bool = True) -> None:
    devices = summary.get("dispositivos", [])
    #util.title(f"Detalles / Dispositivos conectados ({len(devices)})")
    util.title(f"DATA UNIDADES [{len(devices)}] ")
    notes = []
    if not show_mac:
        notes.append("MAC ocultas")
    if not show_names:
        notes.append("nombres ocultos")
    suffix = f" ({', '.join(notes)})" if notes else ""
    #util.info(f"Relacion IP <-> MAC, fabricante, nombre y estado{suffix}:")
    util.info(f"DATA ENCONTRADA{suffix}:")
    netscan.print_devices(devices, show_mac=show_mac, show_names=show_names)
    det = netscan.summarize_detection(devices)
    util.info(f"Deteccion -> nombres {det['named']}/{det['total']} | "
              f"tipos {det['typed']}/{det['total']} | "
              f"online {det['online']} / offline {det['offline']}")


def export_excel(devices: list[dict], directory: str | Path | None = None,
                 prefix: str = "escaneo", path: str | Path | None = None,
                 show_mac: bool = True, show_names: bool = True) -> Path:

    import ipaddress

    if path:
        target = Path(path)
    else:
        target = util.next_numbered_path(directory, prefix=prefix, extension="xlsx")

    def sort_key(device: dict):
        try:
            return ipaddress.ip_address(device.get("ip", "0.0.0.0"))
        except ValueError:
            return ipaddress.ip_address("0.0.0.0")

    rows: list[list[object]] = [EXCEL_HEADERS]
    for d in sorted(devices, key=sort_key):
        mac = d.get("mac") or ""
        # La privacidad pedida se replica en el Excel (solo si se oculto antes).
        if not show_mac and mac:
            mac = util.mask_mac(mac)
        name = d.get("name") or ""
        if not show_names and name:
            name = "██████"
        rows.append([
            d.get("ip") or "",
            mac,
            d.get("vendor") or "",
            name,
            d.get("type") or "",
            d.get("state") or "",
        ])
    return xlsx.write_xlsx(target, rows, sheet_name="Dispositivos")


def run(do_speedtest: bool = False, save_inventory: bool = True,
        export: str | None = None, show_mac: bool = True, show_names: bool = True,
        excel: bool = False, excel_dir: str | Path | None = None,
        excel_file: str | Path | None = None, only_with_mac: bool = False,
        monitor: bool = True, rounds: int = 2) -> dict:
    #Ejecuta el escaneo
    util.info("QUANTIFY DATA...")
    summary = collect(do_speedtest=do_speedtest, only_with_mac=only_with_mac,
                      monitor=monitor, rounds=rounds)
    print_summary(summary, show_mac=show_mac)
    print_devices(summary, show_mac=show_mac, show_names=show_names)

    if save_inventory:
        new_count = inventory.update(summary["dispositivos"], network=summary["red"])
        #util.ok(f"Inventario actualizado ({new_count} nuevos). {inventory.inventory_path()}")
        #Inventario actualizado (N nuevos). /home/usr/.local/share/scp-red/inventory.json
        util.ok(f"Inventario -> [{new_count}] nuevos")

    if excel_file or excel:
        path = export_excel(summary["dispositivos"], directory=excel_dir,
                            path=excel_file, show_mac=show_mac,
                            show_names=show_names)
        util.ok(f"devices in excel: {path}")

    if export:
        inventory.update(summary["dispositivos"], network=summary["red"])
        path = inventory.export_csv(export)
        util.ok(f"Exportado a {path}")

    return summary


def run_interactive() -> dict:
    util.title("Escanear red")
    do_speedtest = _ask_yes_no("prueba de velocidad (bajada/subida)?", False)
    #util.ok("Dato confirmado")
    show_mac = _ask_yes_no("Mostrar MAC?", True)
    #util.ok("Dato confirmado")
    show_names = _ask_yes_no("Mostrar nombres?", True)
    #util.ok("Dato confirmado")

    #filter: todo (sin cambios) o solo dispositivos con MAC/fabricante

	#print("Filtro escaneo profundo/escaneo data important")

    print("[1] Filtro scan profundo (no cambios)")
    print("[2] Filtro important devices  ( MAC/fabricante | exclucion IPs)")
    filtro = input("  Filtro: ").strip() or "1"
    only_with_mac = filtro == "2"
    #util.ok("Dato confirmado")

    #devices online/offline (funcion que incluye IPs ocultas en el escaneo profundo)
    monitor = _ask_yes_no("Mostrar profunda deteccion online/offline?", True)
    #util.ok("Dato confirmado")

    rounds = 2
    if monitor:
        value = input("  Rondas de deteccion [max 2]: ").strip()
        rounds = int(value) if value.isdigit() and int(value) > 0 else 2
        #util.ok("Dato confirmado")

    excel = _ask_yes_no("Registrar Data -> .xlsx?", False)
    excel_dir = None
    if excel:
        excel_dir = input("  Carpeta destino -> [actual] o -> [dar name carpeta]: ").strip() or None
        #util.ok("Dato confirmado")
    return run(do_speedtest=do_speedtest, show_mac=show_mac, show_names=show_names,
               excel=excel, excel_dir=excel_dir, only_with_mac=only_with_mac,
               monitor=monitor, rounds=rounds)


def _ask_yes_no(prompt: str, default: bool) -> bool:
    hint = "[s/n]" if default else "[s/N]"
    answer = input(f"{prompt} {hint}: ").strip().lower()
    if not answer:
        return default
    return answer in ("s", "si", "y", "yes")


if __name__ == "__main__":  # pragma: no cover
    run()
