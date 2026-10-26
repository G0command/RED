#scaneo wifi y dta del punto de acceso


#iw dev <if> link / iw dev <if> scan
#nmcli [networkmanager]
#iwconfig + /proc/net/wireless

#dado caso de que si i no hay interfaz inalambrica, las funciones devuelven none = lista vacia


from __future__ import annotations

import re
import time

from . import util


def wireless_iface() -> str | None:
    ifaces = util.wireless_interfaces()
    return ifaces[0] if ifaces else None

#DETERMINA LA FRECUENCIA
def band_from_freq(freq_mhz: float | None) -> str:
    if not freq_mhz:
        return "No determinado"
    if freq_mhz < 2500:
        return "2.4 GHz"
    if freq_mhz < 5925:
        return "5 GHz"
    return "6 GHz"

#FUNCION PA CHECAR CCANALES Y RETORNA ESA FRECUENCIA
def channel_from_freq(freq_mhz: float | None) -> int | None:
    if not freq_mhz:
        return None
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return int((freq_mhz - 2407) / 5)
    if 5000 <= freq_mhz <= 5895:
        return int((freq_mhz - 5000) / 5)
    if 5955 <= freq_mhz <= 7115:
        return int((freq_mhz - 5950) / 5)
    return None

#CHECK capas y deduce estandar 802.11
def tech_from_caps(ht: bool, vht: bool, he: bool, eht: bool, band: str) -> str:

    if eht:
        return "802.11be (Wi-Fi 7)"
    if he:
        return "802.11ax (Wi-Fi 6)"
    if vht:
        return "802.11ac (Wi-Fi 5)"
    if ht:
        return "802.11n (Wi-Fi 4)"
    if band.startswith("2.4"):
        return "802.11b/g"
    if band.startswith("5"):
        return "802.11a"
    return "No determinado"


#iw



def _parse_iw_scan(text: str) -> list[dict]:
    aps: list[dict] = []
    current: dict | None = None
    in_ht = in_vht = in_he = in_eht = False
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if line.startswith("BSS "):
            if current:
                aps.append(current)
            bssid = stripped.split()[1].split("(")[0]
            current = {
                "bssid": util.normalize_mac(bssid),
                "ssid": None,
                "freq": None,
                "channel": None,
                "band": "No determinado",
                "signal": None,
                "security": "Abierta",
                "ht": False,
                "vht": False,
                "he": False,
                "eht": False,
            }
            in_ht = in_vht = in_he = in_eht = False
            continue
        if current is None:
            continue
        if stripped.startswith("SSID:"):
            current["ssid"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("freq:"):
            try:
                current["freq"] = float(stripped.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif stripped.startswith("signal:"):
            m = re.search(r"(-?\d+(?:\.\d+)?)", stripped)
            if m:
                current["signal"] = float(m.group(1))
        elif "RSN:" in stripped:
            current["security"] = "WPA2/WPA3"
        elif "WPA:" in stripped and current["security"] == "Abierta":
            current["security"] = "WPA"
        elif stripped.startswith("HT capabilities") or stripped.startswith("HT Capabilities"):
            current["ht"] = True
            in_ht = True
        elif stripped.startswith("VHT capabilities") or stripped.startswith("VHT Capabilities"):
            current["vht"] = True
            in_vht = True
        elif stripped.startswith("HE capabilities") or stripped.startswith("HE Capabilities"):
            current["he"] = True
            in_he = True
        elif stripped.startswith("EHT capabilities") or stripped.startswith("EHT Capabilities"):
            current["eht"] = True
            in_eht = True
        elif stripped.startswith("RSN") and "Authentication suites" in stripped:
            current["security"] = "WPA2/WPA3"
    if current:
        aps.append(current)

    for ap in aps:
        ap["channel"] = channel_from_freq(ap["freq"])
        ap["band"] = band_from_freq(ap["freq"])
        ap["technology"] = tech_from_caps(ap["ht"], ap["vht"], ap["he"], ap["eht"], ap["band"])
        if ap["security"] == "Abierta" and ap["freq"] is None:
            pass
    return aps


def scan_iw(iface: str, timeout: float = 12.0) -> list[dict]:
    if not util.have("iw"):
        return []
    rc, out, errp = util.run(["iw", "dev", iface, "scan"], timeout=timeout)
    if rc != 0 or not out.strip():
        return []
    return _parse_iw_scan(out)


def link_iw(iface: str) -> dict | None:
    if not util.have("iw"):
        return None
    rc, out, _ = util.run(["iw", "dev", iface, "link"], timeout=5)
    if rc != 0 or "Not connected" in out or not out.strip():
        return None
    result: dict = {}
    m = re.search(r"Connected to ([0-9a-fA-F:]{17})", out)
    if m:
        result["bssid"] = util.normalize_mac(m.group(1))
    m = re.search(r"SSID:\s*(.+)", out)
    if m:
        result["ssid"] = m.group(1).strip()
    m = re.search(r"freq:\s*(\d+)", out)
    if m:
        result["freq"] = float(m.group(1))
    m = re.search(r"signal:\s*(-?\d+)\s*dBm", out)
    if m:
        result["signal"] = float(m.group(1))
    m = re.search(r"tx bitrate:\s*([\d.]+)\s*MBit/s", out)
    if m:
        result["rate"] = float(m.group(1))
    m = re.search(r"rx bitrate:\s*([\d.]+)\s*MBit/s", out)
    if m:
        result["rx_rate"] = float(m.group(1))
    return result or None


# nmcli



def _nmcli_multiline(args: list[str], timeout: float = 15.0) -> list[dict]:
    if not util.have("nmcli"):
        return []
    rc, out, _ = util.run(["nmcli", "-m", "multiline", *args], timeout=timeout)
    if rc != 0 or not out.strip():
        return []
    blocks: list[dict] = []
    current: dict = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key in current:
            blocks.append(current)
            current = {}
        current[key] = value
    if current:
        blocks.append(current)
    return blocks


def scan_nmcli() -> list[dict]:
    blocks = _nmcli_multiline(
        ["-f", "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY", "dev", "wifi", "list"],
        timeout=20,
    )
    aps: list[dict] = []
    for b in blocks:
        ssid = b.get("SSID")
        if ssid is None:
            continue
        freq = None
        m = re.search(r"([\d.]+)", b.get("FREQ", ""))
        if m:
            freq = float(m.group(1))
        signal = None
        if b.get("SIGNAL"):
            try:
                signal = float(b["SIGNAL"])
            except ValueError:
                pass
        channel = None
        if b.get("CHAN"):
            try:
                channel = int(b["CHAN"])
            except ValueError:
                pass
        band = band_from_freq(freq)
        bssid = b.get("BSSID", "").replace("\\", "")
        aps.append(
            {
                "ssid": ssid,
                "bssid": util.normalize_mac(bssid) if bssid else None,
                "freq": freq,
                "channel": channel,
                "band": band,
                "signal": signal,
                "security": b.get("SECURITY") or "Abierta",
                "technology": tech_from_caps(freq is not None and freq > 2400, band.startswith("5"), freq is not None and freq >= 5925, False, band),
                "active": b.get("IN-USE") == "*",
            }
        )
    return aps




# Fallback iwconfig



def scan_iwconfig(iface: str) -> list[dict]:
    if not util.have("iwconfig"):
        return []
    rc, out, _ = util.run(["iwconfig", iface], timeout=5)
    if rc != 0:
        return []
    ap: dict = {"ssid": None, "bssid": None, "freq": None, "channel": None,
                "band": "No determinado", "signal": None, "security": "No determinado",
                "technology": "No determinado"}
    m = re.search(r'ESSID:"([^"]*)"', out)
    if m:
        ap["ssid"] = m.group(1)
    m = re.search(r"Access Point: ([0-9a-fA-F:]{17})", out)
    if m:
        ap["bssid"] = util.normalize_mac(m.group(1))
    m = re.search(r"Frequency:([\d.]+)\s*GHz", out)
    if m:
        ap["freq"] = float(m.group(1)) * 1000
    m = re.search(r"Signal level[=:]\s*(-?\d+)", out)
    if m:
        ap["signal"] = float(m.group(1))
    if ap["freq"]:
        ap["band"] = band_from_freq(ap["freq"])
        ap["channel"] = channel_from_freq(ap["freq"])
    return [ap] if ap["ssid"] else []


# Windows: netsh wlan
#convierte canal a frecuencia usando la banda si se conoce
def freq_from_channel(channel: int | None, band: str | None = None) -> float | None:
    if not channel:
        return None
    text = util.fold_text(band or "").replace(",", ".")
    if "2.4" in text or (not text and channel <= 14):
        return 2484.0 if channel == 14 else 2407.0 + 5 * channel
    if "5" in text or (not text and 32 <= channel <= 177):
        return 5000.0 + 5 * channel
    if "6" in text or (not text and channel > 177):
        return 5950.0 + 5 * channel
    return None


def tech_from_radio(radio: str | None) -> str:
    text = util.fold_text(radio or "")
    tail = text.split("802.11", 1)[-1] if "802.11" in text else text
    if "be" in tail:
        return "802.11be (Wi-Fi 7)"
    if "ax" in tail:
        return "802.11ax (Wi-Fi 6)"
    if "ac" in tail:
        return "802.11ac (Wi-Fi 5)"
    if "n" in tail:
        return "802.11n (Wi-Fi 4)"
    if any(ch in tail for ch in ("a", "b", "g")):
        return "802.11a/b/g"
    return "No determinado"


def _percent_to_dbm(percent: float | None) -> float | None:
    if percent is None:
        return None
    try:
        value = max(0.0, min(100.0, float(percent)))
    except (TypeError, ValueError):
        return None
    return round(value / 2.0 - 100.0, 1)


def _is_connected_state(state: str | None) -> bool:
    folded = util.fold_text(state or "").strip()
    return any(
        folded.startswith(word)
        for word in ("connected", "conectado")
    )


def _netsh_value(line: str) -> tuple[str, str] | None:
    if ":" not in line:
        return None
    key, _, value = line.partition(":")
    return util.fold_text(key).strip(), value.strip()

#lee etiquetas localizadas
#netsh wlan show networks mode=bssid
def _parse_netsh_networks(text: str) -> list[dict]:
    aps: list[dict] = []
    current_ssid = "(oculta)"
    pending_auth = "Abierta"
    pending_cipher = ""
    ap: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        ssid_match = re.match(r"(?i)^SSID\s+\d+\s*:\s*(.*)$", line)
        if ssid_match:
            current_ssid = ssid_match.group(1).strip() or "(oculta)"
            pending_auth = "Abierta"
            pending_cipher = ""
            ap = None
            continue
        bssid_match = re.match(
            r"(?i)^BSSID\s+\d+\s*:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line
        )
        if bssid_match:
            ap = {
                "ssid": current_ssid,
                "bssid": util.normalize_mac(bssid_match.group(1)),
                "freq": None,
                "channel": None,
                "band": "No determinado",
                "signal": None,
                "signal_dbm": None,
                "security": pending_auth,
                "cipher": pending_cipher,
                "technology": "No determinado",
            }
            aps.append(ap)
            continue
        parsed = _netsh_value(line)
        if not parsed:
            continue
        key, value = parsed
        if any(k in key for k in ("authentication", "autenticacion")):
            pending_auth = value or "Abierta"
            if ap is not None and not ap.get("security"):
                ap["security"] = pending_auth
            continue
        if any(k in key for k in ("encryption", "cifrado")):
            pending_cipher = value
            if ap is not None:
                ap["cipher"] = value
            continue
        if ap is None:
            continue
        if "signal" in key or "senal" in key:
            match = re.search(r"(\d+)", value)
            if match:
                ap["signal"] = float(match.group(1))
        elif key in ("channel", "canal", "kanal"):
            match = re.search(r"(\d+)", value)
            if match:
                ap["channel"] = int(match.group(1))
        elif key in ("band", "banda"):
            ap["band"] = value or "No determinado"
        elif any(k in key for k in ("radio type", "tipo de radio")):
            ap["technology"] = tech_from_radio(value)

    for ap in aps:
        channel = ap.get("channel")
        band = ap.get("band") or "No determinado"
        if band == "No determinado" and channel:
            if channel <= 14:
                band = "2.4 GHz"
            elif channel <= 177:
                band = "5 GHz"
            else:
                band = "6 GHz"
        freq = freq_from_channel(channel, band)
        if freq is not None:
            ap["freq"] = freq
            ap["band"] = band_from_freq(freq)
        ap["signal_dbm"] = _percent_to_dbm(ap.get("signal"))
        if ap["technology"] == "No determinado" and freq:
            ap["technology"] = tech_from_caps(
                freq > 2400, band.startswith("5"), freq >= 5925, False, ap["band"]
            )
    return aps


def scan_netsh(timeout: float = 15.0) -> list[dict]:
    if not util.have("netsh"):
        return []
    rc, out, _ = util.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=timeout
    )
    if rc != 0 or not out.strip():
        return []
    return _parse_netsh_networks(out)


def _netsh_blocks(text: str) -> list[dict]:
    blocks: list[dict] = []
    current: dict = {}
    for raw in text.splitlines():
        if not raw.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        if ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        key_fold = util.fold_text(key).strip()
        if key_fold:
            current.setdefault(key_fold, value.strip())
    if current:
        blocks.append(current)
    return blocks


def _num(value: str | None) -> float | None:
    if not value:
        return None
    match = re.search(r"[\d.,]+", value)
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", "."))
    except ValueError:
        return None

#
#lee netsh wlan show interfaces
#devuelve el bloque pedido
def _parse_netsh_interface(text: str, iface: str | None = None) -> dict | None:
    blocks = _netsh_blocks(text)
    if not blocks:
        return None

    def block_name(block: dict) -> str:
        for key in ("name", "nombre", "nom"):
            if block.get(key):
                return block[key]
        return ""

    chosen: dict | None = None
    if iface:
        for block in blocks:
            if block_name(block).lower() == iface.lower():
                chosen = block
                break
    if chosen is None:
        for block in blocks:
            state = " ".join(
                block[key] for key in ("state", "estado") if key in block
            )
            if block.get("ssid") and _is_connected_state(state):
                chosen = block
                break
    if chosen is None:
        chosen = next((block for block in blocks if block.get("ssid")), None)
    if chosen is None:
        return None

    info: dict = {"iface": block_name(chosen) or iface}
    if chosen.get("ssid"):
        info["ssid"] = chosen["ssid"]
    if chosen.get("bssid"):
        match = re.search(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", chosen["bssid"])
        if match:
            info["bssid"] = util.normalize_mac(match.group(0))
    for key in ("state", "estado"):
        if chosen.get(key):
            info["state"] = chosen[key]
            break
    radio = ""
    band = ""
    for key, value in chosen.items():
        if any(k in key for k in ("radio type", "tipo de radio", "type de radio",
   )):
            radio = value
        elif key in ("band", "banda", "bande", "frequenzband"):
            band = value
        elif any(k in key for k in ("authentication", "autenticacion",
                                    "authentification", "authentifizierung")):
            info["security"] = value
        elif any(k in key for k in ("cipher", "cifrado", "chiffrement",
                                    "verschlusselung")):
            info["cipher"] = value
        elif key in ("channel", "canal", "kanal"):
            match = re.search(r"(\d+)", value)
            if match:
                info["channel"] = int(match.group(1))
        elif "signal" in key or "senal" in key:
            match = re.search(r"(\d+)", value)
            if match:
                info["signal_percent"] = float(match.group(1))
        elif any(k in key for k in ("receive rate", "velocidad de recepcion",
                                    "taux de reception", "empfangsrate")):
            info["rx_rate"] = _num(value)
        elif any(k in key for k in ("transmit rate", "velocidad de transmision",
                                    "taux de transmission", "ubertragungsrate",
                                    "senderate")):
            info["rate"] = _num(value)

    info["technology"] = tech_from_radio(radio)
    channel = info.get("channel")
    if not band:
        band = "No determinado"
        if channel:
            if channel <= 14:
                band = "2.4 GHz"
            elif channel <= 177:
                band = "5 GHz"
            else:
                band = "6 GHz"
    freq = freq_from_channel(channel, band)
    if freq is not None:
        info["freq"] = freq
        info["band"] = band_from_freq(freq)
        info["channel"] = channel_from_freq(freq) or channel
    else:
        info["band"] = band
    signal_dbm = _percent_to_dbm(info.get("signal_percent"))
    if signal_dbm is not None:
        info["signal"] = signal_dbm
        info["signal_avg"] = signal_dbm
    return info


def link_netsh(iface: str | None = None) -> dict | None:
    if not util.have("netsh"):
        return None
    rc, out, _ = util.run(["netsh", "wlan", "show", "interfaces"], timeout=8)
    if rc != 0 or not out.strip():
        return None
    info = _parse_netsh_interface(out, iface)
    if not info:
        return None
    state = info.get("state", "")
    if info.get("ssid") and (_is_connected_state(state) or not state):
        return info
    return None


# API publica

#SCAN WIFI AVIABLE
def scan() -> list[dict]:

    iface = wireless_iface()
    if util.IS_WINDOWS:
        aps = scan_netsh()
        if not aps:
            # Si el escaneo esta restringido, al menos mostrar el AP conectado.
            for name in util.wireless_interfaces():
                info = link_netsh(name)
                if info:
                    aps.append(info)
                    break
        aps.sort(key=lambda a: (a.get("signal") or -1000), reverse=True)
        return aps
    if not iface:
        return []
    aps = scan_iw(iface)
    if not aps:
        aps = scan_nmcli()
    if not aps:
        aps = scan_iwconfig(iface)
    aps.sort(key=lambda a: (a.get("signal") or -1000), reverse=True)
    return aps


#DATA AP + MEDIA SINGALK
def current(iface: str | None = None) -> dict | None:

    iface = iface or wireless_iface()
    if not iface:
        return None

    if util.IS_WINDOWS:
        info = link_netsh(iface)
        if not info:
            return None
        info.setdefault("iface", iface)
        info.setdefault("band", "No determinado")
        info.setdefault("channel", "No determinado")
        info.setdefault("security", "No determinado")
        info.setdefault("technology", "No determinado")
        if info.get("signal_avg") is None and info.get("signal_percent") is not None:
            info["signal"] = _percent_to_dbm(info["signal_percent"])
            info["signal_avg"] = info["signal"]
        return info

    info: dict = {"iface": iface}
    link = link_iw(iface)
    if link:
        info.update(link)

    #completar con el ap activo que reporta networkmanager
    active_ap: dict | None = None
    if not (info.get("bssid") and info.get("ssid")):
        for ap in scan_nmcli():
            if ap.get("active"):
                active_ap = ap
                break
    if active_ap:
        if not info.get("bssid") and active_ap.get("bssid"):
            info["bssid"] = active_ap["bssid"]
        if not info.get("ssid") and active_ap.get("ssid"):
            info["ssid"] = active_ap["ssid"]
        if info.get("freq") is None and active_ap.get("freq"):
            info["freq"] = active_ap["freq"]
        for key in ("channel", "band", "security"):
            if not info.get(key) or info.get(key) in ("No determinado", "No aplica"):
                if active_ap.get(key) is not None:
                    info[key] = active_ap[key]

    #name de la conexion como ultimo recurso para el SSID
    if not info.get("ssid"):
        wifi_props = _nmcli_multiline(["-f", "GENERAL", "dev", "show", iface], timeout=8)
        if wifi_props:
            info["ssid"] = wifi_props[0].get("GENERAL.CONNECTION") or info.get("ssid")

    if not info.get("ssid"):
        for ap in scan_iwconfig(iface):
            info.update({k: v for k, v in ap.items() if v is not None})

    #canal y banda
    if info.get("freq"):
        info["band"] = band_from_freq(info["freq"])
        info["channel"] = channel_from_freq(info["freq"]) or info.get("channel")
    info.setdefault("band", "No determinado")
    info.setdefault("channel", "No determinado")
    info.setdefault("security", "No determinado")

    # Promedio de intensidad
    samples: list[float] = []
    for _ in range(5):
        got = link_iw(iface)
        if got and got.get("signal") is not None:
            samples.append(got["signal"])
            if info.get("freq") is None and got.get("freq"):
                info["freq"] = got["freq"]
                info["band"] = band_from_freq(got["freq"])
                info["channel"] = channel_from_freq(got["freq"]) or info.get("channel")
        time.sleep(0.2)
    if samples:
        info["signal_avg"] = round(sum(samples) / len(samples), 1)
        info["signal"] = samples[-1]

    # Tecnologia/seguridad: capacidades del escaneo que casen con el ap
    tech = None
    for ap in scan_iw(iface):
        match = (
            (info.get("bssid") and ap.get("bssid") == info.get("bssid"))
            or (not info.get("bssid") and info.get("ssid") and ap.get("ssid") == info.get("ssid"))
        )
        if match:
            tech = ap.get("technology")
            if not info.get("channel") or info.get("channel") == "No determinado":
                info["channel"] = ap.get("channel") or info.get("channel")
            if info.get("freq") is None and ap.get("freq"):
                info["freq"] = ap["freq"]
                info["band"] = band_from_freq(ap["freq"])
            if info.get("security") in (None, "No determinado", "Abierta"):
                info["security"] = ap.get("security")
            break
    info["technology"] = tech or "No determinado"
    return info

#check asignacion frecuencia -> canal/banda con valores conocidos
def verify_frequency() -> dict:
    cases = {
        2412: (1, "2.4 GHz"), 2437: (6, "2.4 GHz"), 2472: (13, "2.4 GHz"),
        2484: (14, "2.4 GHz"), 5180: (36, "5 GHz"), 5500: (100, "5 GHz"),
        5745: (149, "5 GHz"), 5825: (165, "5 GHz"), 5955: (1, "6 GHz"),
    }
    results = []
    for freq, (exp_chan, exp_band) in cases.items():
        chan = channel_from_freq(freq)
        band = band_from_freq(freq)
        results.append({
            "freq": freq,
            "canal": chan,
            "banda": band,
            "ok": chan == exp_chan and band == exp_band,
        })
    return {"cases": results, "ok": all(r["ok"] for r in results)}



def print_scan(aps: list[dict]) -> None:
    rows = []
    for ap in aps:
        sig = ap.get("signal")
        if sig is None:
            sig_txt = "-"
        elif sig < 0:
            sig_txt = f"{sig:.0f} dBm"
        else:
            sig_txt = f"{sig:.0f}%"
        rows.append(
            [
                ap.get("ssid") or "(oculta)",
                ap.get("bssid") or "-",
                ap.get("channel") or "-",
                ap.get("band") or "-",
                ap.get("security") or "-",
                ap.get("technology") or "-",
                sig_txt,
            ]
        )
    util.table(["SSID", "BSSID", "Canal", "Banda", "Seguridad", "Tecnologia", "Senal"], rows)

#wifi sacn - red aviable y data ap
def run_menu() -> None:
    iface = wireless_iface()
    if not iface:
        util.warn(" INTERFAZ INALAMBRICA NO DISPONIBLE")
        return
    util.info(f"SCAN WIFI en {iface} ...")
    aps = scan()
    util.title(f"Redes Wi-Fi detectadas ({len(aps)})")
    print_scan(aps)

    util.title("Punto de acceso conectado")
    current_ap = current(iface)
    if not current_ap:
        util.warn("NO CONECTADO A NINGUNA RED")
        return
    util.kv("SSID", current_ap.get("ssid") or "-")
    util.kv("BSSID", current_ap.get("bssid") or "-")
    util.kv("Canal", current_ap.get("channel") or "-")
    util.kv("Banda", current_ap.get("band") or "-")
    util.kv("Seguridad", current_ap.get("security") or "-")
    util.kv("Tecnologia", current_ap.get("technology") or "-")
    signal = current_ap.get("signal_avg")
    util.kv("SIGNAL media", f"{signal} dBm" if signal is not None else "-")
    if current_ap.get("rate"):
        util.kv("Velocidad enlace", f"{current_ap['rate']} Mbit/s")
