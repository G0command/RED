

#inventario equipos y redes (uso de jason/csv))
# inventory save in ~/.local/share/scp-red/inventory.json
#programa para detercar intrusosr o equipos ya dtecatados

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from . import util

_DATA_DIR = util.data_dir()
_INV_FILE = _DATA_DIR / "inventory.json"


def inventory_path() -> Path:
    return _INV_FILE


def load() -> dict:
    if not _INV_FILE.exists():
        return {"devices": {}, "networks": {}}
    try:
        with _INV_FILE.open(encoding="utf-8") as fh:
            data = json.load(fh)
        data.setdefault("devices", {})
        data.setdefault("networks", {})
        return data
    except (OSError, json.JSONDecodeError):
        return {"devices": {}, "networks": {}}


def save(data: dict) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _INV_FILE.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def _key(device: dict) -> str:
    return (device.get("mac") or "").lower() or device.get("ip") or "desconocido"


#actualiza los dispositivos al inventory y retorna el n nuevo
def update(devices: list[dict], network: str | None = None) -> int:
    data = load()
    known = data["devices"]
    new_count = 0
    now = util.now_str()
    for device in devices:
        key = _key(device)
        entry = known.get(key, {})
        if not entry:
            new_count += 1
            entry = {"first_seen": now}
        entry.update({
            "ip": device.get("ip"),
            "mac": device.get("mac"),
            "vendor": device.get("vendor"),
            "hostname": device.get("hostname"),
            "netbios": device.get("netbios"),
            "name": device.get("name"),
            "type": device.get("type"),
            "model": device.get("model"),
            "state": device.get("state"),
        })
        # No marcar como "visto ahora" un equipo que solo aparece offline.
        if device.get("state") != "offline":
            entry["last_seen"] = now
        else:
            entry.setdefault("last_seen", entry.get("first_seen", now))
        known[key] = entry
    if network:
        net = data["networks"].setdefault(network, {"first_seen": now})
        net["last_seen"] = now
    save(data)
    return new_count


def list_devices() -> list[dict]:
    data = load()
    return list(data["devices"].values())


def remove(mac_or_ip: str) -> bool:
    data = load()
    target = mac_or_ip.lower()
    for key in list(data["devices"].keys()):
        entry = data["devices"][key]
        if key.lower() == target or (entry.get("ip") or "").lower() == target:
            del data["devices"][key]
            save(data)
            return True
    return False


def export_csv(path: str | None = None) -> Path:
    target = Path(path) if path else _DATA_DIR / "inventory.csv"
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = ["ip", "mac", "vendor", "hostname", "netbios", "name", "type",
              "state", "first_seen", "last_seen"]
    with target.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for device in list_devices():
            writer.writerow(device)
    return target


def print_inventory() -> None:
    devices = list_devices()
    util.title(f"Inventory devices ({len(devices)})")
    rows = []
    for d in devices:
        rows.append([
            d.get("ip") or "-",
            d.get("mac") or "-",
            (d.get("vendor") or "-")[:20],
            (d.get("name") or "-")[:20],
            d.get("type") or "-",
            d.get("last_seen") or "-",
        ])
    util.table(["IP", "MAC", "Fabricante", "Nombre", "Tipo", "Ultima vez"], rows)
    util.info(f"Archivo: {_INV_FILE}")


def run_menu() -> None:
    print("  [1] Ver inventario   [2] Exportar CSV   [3] Eliminar dispositivo")
    option = input("Opcion [1]: ").strip() or "1"
    if option == "2":
        path = export_csv()
        util.ok(f"Exportado a {path}")
    elif option == "3":
        target = input("mac | ip a eliminar: ").strip()
        if remove(target):
            util.ok("RM")
        else:
            util.warn("not found")
    else:
        print_inventory()


def _ask_yes_no(prompt: str, default: bool) -> bool:
    hint = "[S/n]" if default else "[s/N]"
    answer = input(f"{prompt} {hint}: ").strip().lower()
    if not answer:
        return default
    return answer in ("s", "si", "y", "yes")


def _ip_key(device: dict):
    import ipaddress

    try:
        return ipaddress.ip_address(device.get("ip") or "0.0.0.0")
    except ValueError:
        return ipaddress.ip_address("0.0.0.0")

#impresion de mac + nombre + fabricanbte
def print_mac_names(devices: list[dict] | None = None, show_mac: bool = True,
                    show_names: bool = True) -> None:
    devices = list(devices) if devices is not None else list_devices()
    rows = []
    for d in sorted(devices, key=_ip_key):
        mac = d.get("mac") or "-"
        if not show_mac and mac != "-":
            mac = util.mask_mac(mac)
        name = d.get("name") or "-"
        if not show_names and name != "-":
            name = "██████"
        rows.append([mac, name, d.get("vendor") or "-"])
    util.title(f"MAC + Nombre + Fabricante ({len(devices)})")
    util.table(["MAC", "Nombre", "Fabricante"], rows)

#mostrado de mac junto a nombre y fabricante
def run_mac_names_menu() -> None:
    print("  [1] Inventario guardado   [2] Escaneo en vivo")
    source = input("Fuente [1]: ").strip() or "1"
    if source == "2":
        from . import netscan  # noqa: PLC0415

        util.info("escan dispos...")
        devices = netscan.discover(resolve=True)
    else:
        devices = list_devices()
    show_mac = _ask_yes_no("mostrar MAC completas?", True)
    show_names = _ask_yes_no("mostrar nombres?", True)
    print_mac_names(devices, show_mac=show_mac, show_names=show_names)
