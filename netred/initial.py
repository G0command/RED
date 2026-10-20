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


def _ap_model(gateway: str | None) -> str | None:
    #obtener marca/modelo del AP via UPnP en la puerta de enlace
    if not gateway:
        return None
    try:
        for device in upnp.discover(timeout=2, retries=1):
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
    if not iface:
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


def collect(do_speedtest: bool = False) -> dict:
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
    model = _ap_model(gateway)
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
    devices = netscan.discover(network, ifname=iface, resolve=True)
    summary["red"] = str(network) if network else _NA
    summary["num_dispositivos"] = len(devices)
    summary["dispositivos"] = devices

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


def print_summary(summary: dict, show_mac: bool = True) -> None:
    util.title("ULTIMATE ESC---")
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
    util.kv("N dispositivos", summary["num_dispositivos"])
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


def export_excel(devices: list[dict], directory: str | Path | None = None,
                 prefix: str = "escaneo", path: str | Path | None = None) -> Path:

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
        rows.append([
            d.get("ip") or "",
            d.get("mac") or "",
            d.get("vendor") or "",
            d.get("name") or "",
            d.get("type") or "",
            d.get("state") or "",
        ])
    return xlsx.write_xlsx(target, rows, sheet_name="Dispositivos")


def run(do_speedtest: bool = False, save_inventory: bool = True,
        export: str | None = None, show_mac: bool = True, show_names: bool = True,
        excel: bool = False, excel_dir: str | Path | None = None,
        excel_file: str | Path | None = None) -> dict:
    #Ejecuta el escaneo
    util.info("QUANTIFY DATA...")
    summary = collect(do_speedtest=do_speedtest)
    print_summary(summary, show_mac=show_mac)
    print_devices(summary, show_mac=show_mac, show_names=show_names)

    if save_inventory:
        new_count = inventory.update(summary["dispositivos"], network=summary["red"])
        #util.ok(f"Inventario actualizado ({new_count} nuevos). {inventory.inventory_path()}")
        #Inventario actualizado (N nuevos). /home/usr/.local/share/scp-red/inventory.json
        util.ok(f"Inventario -> [{new_count}] nuevos")

    if excel_file or excel:
        path = export_excel(summary["dispositivos"], directory=excel_dir,
                            path=excel_file)
        util.ok(f"Dispositivos registrados en Excel: {path}")

    if export:
        inventory.update(summary["dispositivos"], network=summary["red"])
        path = inventory.export_csv(export)
        util.ok(f"Exportado a {path}")

    return summary


def run_interactive() -> dict:
    util.title("Escanear red")
    do_speedtest = _ask_yes_no("prueba de velocidad (bajada/subida)?", False)
    show_mac = _ask_yes_no("Mostrar MAC?", True)
    show_names = _ask_yes_no("Mostrar nombres?", True)
    excel = _ask_yes_no("Registrar Data -> .xlsx?", False)
    excel_dir = None
    if excel:
        excel_dir = input("  Carpeta destino -> [actual] o -> [dar name carpeta]: ").strip() or None
    return run(do_speedtest=do_speedtest, show_mac=show_mac, show_names=show_names,
               excel=excel, excel_dir=excel_dir)


def _ask_yes_no(prompt: str, default: bool) -> bool:
    hint = "[S/n]" if default else "[s/N]"
    answer = input(f"{prompt} {hint}: ").strip().lower()
    if not answer:
        return default
    return answer in ("s", "si", "y", "yes")


if __name__ == "__main__":  # pragma: no cover
    run()
