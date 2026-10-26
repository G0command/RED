#CONEXION a puertos  web, SSH y FTP


from __future__ import annotations

import ftplib
import subprocess

from . import util


def open_browser(url: str) -> bool:
    if "://" not in url:
        url = "http://" + url
    if util.open_url(url):
        util.ok(f"open {url} en el browser...")
        return True
    util.warn("browser not found")
    return False


def ssh(host: str, user: str | None = None, port: int = 22) -> None:
    if not util.have("ssh"):
        util.err("Cliente ssh no esta instalado")
        return
    target = f"{user}@{host}" if user else host
    cmd = ["ssh", "-p", str(port), target]
    util.info(f"Conectando por SSH a {target}:{port} ...")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        pass


def ftp(host: str, port: int = 21, user: str = "anonymous",
        password: str = "anonymous@") -> None:
    util.info(f"Conectando por FTP a {host}:{port} ...")
    client = ftplib.FTP()
    try:
        client.connect(host, port, timeout=8)
        client.login(user, password)
        util.ok(client.getwelcome())
        client.set_pasv(True)
        print(util.Style.paint("Directorio raiz:", util.Style.BOLD))
        entries: list[str] = []
        client.retrlines("LIST", entries.append)
        for entry in entries:
            print("  " + entry)
    except (ftplib.all_errors, OSError) as exc:
        util.err(f"Error FTP: {exc}")
    finally:
        try:
            client.quit()
        except Exception:
            client.close()


def run_menu() -> None:
    host = input("Host o IP: ").strip()
    if not host:
        return
    print("  [1] Navegador web   [2] SSH   [3] FTP")
    kind = input("Tipo [1]: ").strip() or "1"
    if kind == "1":
        port = input("Puerto [80]: ").strip() or "80"
        scheme = "https" if port in ("443", "8443") else "http"
        open_browser(f"{scheme}://{host}:{port}")
    elif kind == "2":
        user = input("Usuario (vacio = actual): ").strip() or None
        port = input("Puerto [22]: ").strip() or "22"
        ssh(host, user, int(port) if port.isdigit() else 22)
    elif kind == "3":
        port = input("Puerto [21]: ").strip() or "21"
        user = input("Usuario [anonymous]: ").strip() or "anonymous"
        password = input("Contrasena [anonymous@]: ").strip() or "anonymous@"
        ftp(host, int(port) if port.isdigit() else 21, user, password)
