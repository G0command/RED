<h1 align="center" id="title">RED</h1>

<p align="center">
  <b>NETWORK TOOLS</b><br>
  herramientas de red
</p>

<p align="center">
	<img src='assets/logo.png' height="200"/>
</p>

[![python version](https://img.shields.io/badge/Python-3.10%2B-brightgreen)](https://www.python.org/downloads/)

# **ACERCA DE RED**
**Phunter is a tool a very useful tool for finding information about a phone number**
**RED es una herramienta para **

**Escaneo Ultimate:**
```
- AP (SSID)
- MAC AP
- Canal
- Banda
- Seguridad
- Tecnología (802.11 -- si no se puede identificar, indicar "No determinado")
- Marca/Modelo del acces point(si se puede identificar; si no, indicar omitir)
- Fecha / Hora en que se realizo el escaneo
- Nº de dispositivos conectados
- Velocidad Bajada (Mbps)
- Velocidad Subida (Mbps)
- Ping (ms)
- Intensidad señal (dBm) — valor promedio


```

## **Installation**

- [Python 3](https://www.python.org/downloads/)
- [Git](https://git-scm.com/downloads)

```
$ git clone https://github.com/G0command/RED.git
$ cd ./RED
$ python3 red.py
```

## **uso y ejemplos**

```
usage: red.py [-h] [--no-color] {scan,info,upnp,bonjour,wifi,speedtest,isp,connectivity,intruders,inventory,macs,lan,subnet,ping,trace,portscan,whois,dns,wol,ipcalc,watcher,monitor,connect} ...

$ python3 red.py 

$ python3 red.py scan --excel --excel-dir ~/escaneos
$ python3 red.py scan --hide-mac --hide-names --excel-file reporte.xlsx
$ python3 red.py wifi --verify
$ python3 red.py scan --speed
$ python3 red.py ping 1.1.1.1 --tcp 443
$ python3 red.py portscan 192.168.1.1 -p 22,80,443
$ python3 red.py --help
```



### Example results:
![](assets/example.png)



### **IMPORTANTE**

**Herramienta dise;ada para propositos educacionales**

