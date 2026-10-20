

#inventario equipos y redes (uso de jason/csv))
# inventory save in ~/.local/share/scp-red/inventory.json
#programa para detercar intrusosr o equipos ya dtecatados

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from . import util

_DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "scp-red"
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
            "state": device.get("state"),
            "last_seen": now,
        })
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
