#Identificacion de fabricante

#Estrategia (menor a mayor coste):
#Base OUI local en cache (``~/.cache/scp-red/oui.csv``).
#descarga puntual del registro IEEE si hay Internet
#Tabla reducida embebida con fabricantes



from __future__ import annotations

import csv
import io
import os
import threading
import urllib.request
from pathlib import Path

from . import util

_CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "scp-red"
_OUI_CSV = _CACHE_DIR / "oui.csv"
_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# prefijo (6 hex) -> fabricante
_EMBEDDED = {
    "000C29": "VMware",
    "005056": "VMware",
    "001C14": "VMware",
    "000569": "VMware",
    "080027": "Oracle VirtualBox",
    "0A0027": "Oracle VirtualBox",
    "525400": "QEMU / KVM",
    "00155D": "Microsoft (Hyper-V)",
    "0017FA": "Microsoft",
    "0050F2": "Microsoft",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Trading",
    "E45F01": "Raspberry Pi Trading",
    "2CCF67": "Raspberry Pi Trading",
    "F4F26D": "TP-Link",
    "50C7BF": "TP-Link",
    "A42BB0": "TP-Link",
    "001D0F": "TP-Link",
    "1C61B4": "TP-Link",
    "F0F336": "TP-Link",
    "001D7E": "Cisco-Linksys",
    "C0C1C0": "Cisco-Linksys",
    "0014BF": "Cisco-Linksys",
    "68BDAB": "Cisco",
    "0025B3": "Cisco",
    "1CBFC0": "Cisco",
    "0024B2": "Netgear",
    "204E7F": "Netgear",
    "A040A0": "Netgear",
    "9CD36D": "Netgear",
    "0026F2": "Netgear",
    "2C3033": "Netgear",
    "0018E7": "Apple",
    "F0DBF8": "Apple",
    "9C04EB": "Apple",
    "78CA39": "Apple",
    "5C969D": "Apple",
    "28E14C": "Apple",
    "3C2EF9": "Apple",
    "A4B197": "Apple",
    "DC2B2A": "Apple",
    "F4F15A": "Apple",
    "001E64": "Intel",
    "3C22FB": "Intel",
    "94E6F7": "Intel",
    "9CB6D0": "Intel",
    "E4A471": "Intel",
    "F8E43B": "Intel",
    "001377": "Samsung",
    "002637": "Samsung",
    "2CF0A2": "Samsung",
    "5001BB": "Samsung",
    "8425DB": "Samsung",
    "8C7712": "Samsung",
    "AC3613": "Samsung",
    "F8042E": "Samsung",
    "FCA13E": "Samsung",
    "8C04BA": "Huawei",
    "001882": "Huawei",
    "283152": "Huawei",
    "48DB50": "Huawei",
    "5CB395": "Huawei",
    "88E3AB": "Huawei",
    "D07AB5": "Huawei",
    "44D9E7": "Ubiquiti",
    "788A20": "Ubiquiti",
    "74ACB9": "Ubiquiti",
    "245A4C": "Ubiquiti",
    "0418D6": "Ubiquiti",
    "24A43C": "Ubiquiti",
    "80EA96": "Ubiquiti",
    "00D0F1": "Dell",
    "2C600C": "Dell",
    "B8AC6F": "Dell",
    "1866DA": "Dell",
    "F48E38": "Dell",
    "000D3A": "Microsoft",
    "001E58": "D-Link",
    "0022B0": "D-Link",
    "1CBDB9": "D-Link",
    "340804": "D-Link",
    "74DA88": "D-Link",
    "CCB255": "D-Link",
    "001AA9": "Xiaomi",
    "28E31F": "Xiaomi",
    "64CC2E": "Xiaomi",
    "F0B429": "Xiaomi",
    "0002B3": "Intel",
    "001B63": "Apple",
    "002608": "Apple",
    "A45E60": "Apple",
    "04D3B0": "Intel",
    "0022FB": "Intel",
    "001E67": "Intel",
    "002315": "Intel",
    "9C4E36": "Intel",
    "000FB5": "Netgear",
    "001E2A": "Netgear",
    "E091F5": "Netgear",
    "0024A5": "Buffalo",
    "001601": "Buffalo",
    "000740": "Buffalo",
    "00089F": "SMC Networks",
    "001E8F": "Canon",
    "000496": "Extreme Networks",
    "00E04C": "Realtek",
    "001636": "Vecima",
    "00236C": "Apple",
    "3C0754": "Apple",
    "ACDE48": "Apple",
    "6C709F": "Apple",
    "88C663": "Apple",
    "0026BB": "Apple",
    "F81EDF": "Apple",
    "0017F2": "Apple",
    "0016CB": "Apple",
    "001124": "Apple",
    "BC926B": "Apple",
    "D0E140": "Apple",
    "E0B9BA": "Apple",
}

# no enrutables
_LOCAL_MACS = {
    "000000": "Direccion nula",
    "FFFFFFFF": "Difusion (broadcast)",
}


class _OuiDB:
    def __init__(self) -> None:
        self._table: dict[str, str] = {}
        self._loaded = False
        self._lock = threading.Lock()
        self._download_tried = False

    def _load_cache(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not _OUI_CSV.exists():
            return
        try:
            with _OUI_CSV.open(newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.reader(fh)
                header_skipped = False
                for row in reader:
                    if not header_skipped:
                        header_skipped = True
                        continue
                    if len(row) >= 3:
                        prefix = row[1].strip().upper()
                        name = row[2].strip()
                        if prefix and name:
                            self._table[prefix] = name
        except OSError:
            pass

    def _download(self) -> bool:
        with self._lock:
            if self._download_tried:
                return bool(self._table)
            self._download_tried = True
        try:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(_OUI_URL, headers={"User-Agent": "scp-red"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = resp.read()
            _OUI_CSV.write_bytes(data)
            self._loaded = False
            self._load_cache()
            return bool(self._table)
        except Exception:
            return False

    def ensure_full(self) -> bool:
        self._load_cache()
        if len(self._table) > 1000:
            return True
        return self._download()

    def lookup(self, mac: str) -> str:
        if not mac:
            return "desconocido"
        hexonly = "".join(ch for ch in mac if ch.isalnum()).upper()
        if len(hexonly) < 6:
            return "desconocido"
        prefix = hexonly[:6]
        if prefix in _LOCAL_MACS:
            return _LOCAL_MACS[prefix]
        #bit multicast
        try:
            first_octet = int(hexonly[:2], 16)
            if first_octet & 0x01:
                return "multicast (no fabricante)"
            if first_octet & 0x02:
                return "MAC local/aleatoria (no fabricante)"
        except ValueError:
            pass
        self._load_cache()
        if prefix in self._table:
            return self._table[prefix]
        if prefix in _EMBEDDED:
            return _EMBEDDED[prefix]
        #autocompletar con la base IEEE
        if not self._download_tried:
            util.info("OUI no encontrada...descargando registro IEEE...")
            if self._download() and prefix in self._table:
                return self._table[prefix]
        return "Desconocido"


_DB = _OuiDB()

	#Devuelve el fabricante asociado [MAC]]
def lookup(mac: str) -> str:
    return _DB.lookup(mac)


	#Fuerza la descarga/actualizacion de la base OUI IEEE
def update_database() -> bool:
    return _DB._download()
