#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║                     N E T B O M B                             ║
║              Advanced Network Enumeration Tool                ║
╚═══════════════════════════════════════════════════════════════╝
  Requires: pip install python-nmap scapy requests colorama
"""

import sys
import os
import socket
import subprocess
import threading
import time
import ipaddress
import json
import struct
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── dependency check ──────────────────────────────────────────────────────────
def check_and_install(pkg, import_name=None):
    import_name = import_name or pkg
    try:
        __import__(import_name)
    except ImportError:
        print(f"  Installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

for p, i in [("colorama","colorama"),("python-nmap","nmap"),("requests","requests")]:
    check_and_install(p, i)

import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# ── colour palette ─────────────────────────────────────────────────────────────
C = {
    "banner":   Fore.CYAN + Style.BRIGHT,
    "header":   Fore.BLUE + Style.BRIGHT,
    "ok":       Fore.GREEN + Style.BRIGHT,
    "warn":     Fore.YELLOW + Style.BRIGHT,
    "err":      Fore.RED + Style.BRIGHT,
    "info":     Fore.WHITE,
    "dim":      Fore.WHITE + Style.DIM,
    "port":     Fore.GREEN,
    "closed":   Fore.RED + Style.DIM,
    "service":  Fore.CYAN,
    "os":       Fore.MAGENTA + Style.BRIGHT,
    "host":     Fore.YELLOW + Style.BRIGHT,
    "section":  Fore.BLUE,
    "reset":    Style.RESET_ALL,
    "highlight":Fore.WHITE + Style.BRIGHT,
}

# ── well-known port → (service, protocol) ─────────────────────────────────────
PORT_DB = {
    20: ("FTP Data","TCP"), 21: ("FTP Control","TCP"), 22: ("SSH","TCP"),
    23: ("Telnet","TCP"), 25: ("SMTP","TCP"), 53: ("DNS","TCP/UDP"),
    67: ("DHCP Server","UDP"), 68: ("DHCP Client","UDP"), 69: ("TFTP","UDP"),
    80: ("HTTP","TCP"), 88: ("Kerberos","TCP"), 110: ("POP3","TCP"),
    111: ("RPC","TCP/UDP"), 119: ("NNTP","TCP"), 123: ("NTP","UDP"),
    135: ("MSRPC","TCP"), 137: ("NetBIOS-NS","UDP"), 138: ("NetBIOS-DGM","UDP"),
    139: ("NetBIOS-SSN","TCP"), 143: ("IMAP","TCP"), 161: ("SNMP","UDP"),
    162: ("SNMP Trap","UDP"), 179: ("BGP","TCP"), 194: ("IRC","TCP"),
    389: ("LDAP","TCP"), 443: ("HTTPS","TCP"), 445: ("SMB/CIFS","TCP"),
    465: ("SMTPS","TCP"), 500: ("IKE/IPSec","UDP"), 512: ("rexec","TCP"),
    513: ("rlogin","TCP"), 514: ("Syslog/rsh","TCP/UDP"), 515: ("LPD Print","TCP"),
    548: ("AFP","TCP"), 554: ("RTSP","TCP"), 587: ("SMTP Submit","TCP"),
    631: ("IPP/CUPS","TCP"), 636: ("LDAPS","TCP"), 873: ("rsync","TCP"),
    902: ("VMware Auth","TCP"), 993: ("IMAPS","TCP"), 995: ("POP3S","TCP"),
    1080: ("SOCKS Proxy","TCP"), 1194: ("OpenVPN","UDP"), 1433: ("MSSQL","TCP"),
    1434: ("MSSQL Browser","UDP"), 1521: ("Oracle DB","TCP"), 1723: ("PPTP","TCP"),
    1900: ("SSDP/UPnP","UDP"), 2049: ("NFS","TCP"), 2082: ("cPanel","TCP"),
    2083: ("cPanel SSL","TCP"), 2181: ("Zookeeper","TCP"), 2375: ("Docker","TCP"),
    2376: ("Docker TLS","TCP"), 3000: ("Dev Server","TCP"), 3306: ("MySQL","TCP"),
    3389: ("RDP","TCP"), 3690: ("SVN","TCP"), 4000: ("ICQ","TCP"),
    4369: ("RabbitMQ","TCP"), 4444: ("Alt-SSH/Metasploit","TCP"),
    4848: ("GlassFish","TCP"), 5000: ("Flask/Dev","TCP"), 5432: ("PostgreSQL","TCP"),
    5672: ("AMQP/RabbitMQ","TCP"), 5900: ("VNC","TCP"), 5985: ("WinRM HTTP","TCP"),
    5986: ("WinRM HTTPS","TCP"), 6379: ("Redis","TCP"), 6443: ("K8s API","TCP"),
    6666: ("IRC Alt","TCP"), 7001: ("WebLogic","TCP"), 7070: ("RTSP Alt","TCP"),
    8000: ("HTTP Alt","TCP"), 8008: ("HTTP Alt","TCP"), 8080: ("HTTP Proxy","TCP"),
    8081: ("HTTP Alt","TCP"), 8443: ("HTTPS Alt","TCP"), 8888: ("Jupyter","TCP"),
    9000: ("PHP-FPM/SonarQube","TCP"), 9090: ("Prometheus","TCP"),
    9200: ("Elasticsearch","TCP"), 9300: ("Elasticsearch Cluster","TCP"),
    10000: ("Webmin","TCP"), 10250: ("Kubelet","TCP"), 11211: ("Memcached","TCP"),
    27017: ("MongoDB","TCP"), 27018: ("MongoDB Shard","TCP"),
    50000: ("SAP","TCP"), 50070: ("Hadoop HDFS","TCP"),
}

# high-number ports worth extra attention
HIGH_PORTS_OF_INTEREST = [
    1234,1337,2222,2323,4321,4444,4545,5555,6060,6868,7070,7777,
    8000,8008,8080,8081,8082,8083,8084,8085,8086,8088,8090,8443,
    8800,8888,8989,9000,9001,9002,9090,9100,9443,9999,10000,
    12345,31337,55555,65535
]

# ── animated spinner ───────────────────────────────────────────────────────────
class Spinner:
    FRAMES = ["⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷"]
    def __init__(self, msg=""):
        self.msg = msg
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)
    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            sys.stdout.write(f"\r  {C['warn']}{frame}{C['reset']}  {C['dim']}{self.msg}{C['reset']}  ")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1
    def start(self): self._thread.start(); return self
    def stop(self, final=""):
        self._stop.set()
        self._thread.join()
        sys.stdout.write(f"\r  {C['ok']}✔{C['reset']}  {final or self.msg}\n")
        sys.stdout.flush()

# ── ASCII banner ───────────────────────────────────────────────────────────────
BANNER = r"""
  ███╗   ██╗███████╗████████╗██████╗  ██████╗ ███╗   ███╗██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗████╗ ████║██╔══██╗
  ██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██╔████╔██║██████╔╝
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██║   ██║██║╚██╔╝██║██╔══██╗
  ██║ ╚████║███████╗   ██║   ██████╔╝╚██████╔╝██║ ╚═╝ ██║██████╔╝
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═════╝
"""

def print_banner():
    os.system("clear" if os.name != "nt" else "cls")
    print(C["banner"] + BANNER)
    print(C["dim"] + "  " + "─"*62)
    print(C["highlight"] + "          Advanced Network Enumeration & Fingerprinting Tool")
    print(C["dim"] + "  " + "─"*62 + C["reset"])
    print()
    print(C["err"] + "  ╔" + "═"*58 + "╗")
    print(C["err"] + "  ║" + C["warn"] + "  ⚠  DISCLAIMER — READ BEFORE USE" + " "*25 + C["err"] + "║")
    print(C["err"] + "  ║" + C["dim"] + "  This tool is strictly for authorized use only.        " + C["err"] + "║")
    print(C["err"] + "  ║" + C["dim"] + "  Only scan networks and devices you own or have         " + C["err"] + "║")
    print(C["err"] + "  ║" + C["dim"] + "  explicit written permission to test. Unauthorized      " + C["err"] + "║")
    print(C["err"] + "  ║" + C["dim"] + "  scanning may be illegal. Use at your own risk.         " + C["err"] + "║")
    print(C["err"] + "  ╚" + "═"*58 + "╝" + C["reset"])
    print()

def section(title):
    w = 60
    print()
    print(C["section"] + "  ╔" + "═"*(w-2) + "╗")
    pad = (w - 2 - len(title)) // 2
    print(C["section"] + "  ║" + " "*pad + C["highlight"] + title + C["section"] + " "*(w-2-pad-len(title)) + "║")
    print(C["section"] + "  ╚" + "═"*(w-2) + "╝" + C["reset"])

def hr():
    print(C["dim"] + "  " + "─"*60 + C["reset"])

# ── progress bar ───────────────────────────────────────────────────────────────
def progress_bar(current, total, width=40, label=""):
    pct = current / max(total, 1)
    filled = int(width * pct)
    bar = C["ok"] + "█"*filled + C["dim"] + "░"*(width-filled)
    pct_str = f"{pct*100:5.1f}%"
    sys.stdout.write(f"\r  {bar}{C['reset']}  {C['highlight']}{pct_str}{C['reset']}  {C['dim']}{label}{C['reset']}  ")
    sys.stdout.flush()
    if current >= total:
        print()

# ── network utilities ──────────────────────────────────────────────────────────
def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def ping_host(ip, timeout=1):
    """Fast ICMP ping using system ping."""
    flag = "-n" if os.name == "nt" else "-c"
    w_flag = ["-w", "1000"] if os.name == "nt" else ["-W", str(timeout)]
    try:
        result = subprocess.run(
            ["ping", flag, "1"] + w_flag + [str(ip)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False

def tcp_connect(ip, port, timeout=1.0):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except Exception:
        return False

def banner_grab(ip, port, timeout=2.0):
    """Grab banner / HTTP title from a port."""
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as s:
            s.settimeout(timeout)
            # HTTP probe
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + str(ip).encode() + b"\r\n\r\n")
                data = s.recv(1024).decode("utf-8", errors="replace")
                # extract Server header
                m = re.search(r"Server:\s*(.+)", data, re.I)
                if m:
                    return ("HTTP", m.group(1).strip()[:80])
                if data.startswith("HTTP"):
                    return ("HTTP", data.split("\r\n")[0].strip()[:80])
            except Exception:
                pass
            # raw banner
            try:
                s.sendall(b"\r\n")
                raw = s.recv(256).decode("utf-8", errors="replace").strip()
                if raw:
                    return ("RAW", raw[:80])
            except Exception:
                pass
    except Exception:
        pass
    return None

def get_service_name(port):
    if port in PORT_DB:
        return PORT_DB[port]
    try:
        name = socket.getservbyport(port)
        return (name.upper(), "TCP")
    except Exception:
        return ("Unknown", "TCP")

# ── OS fingerprinting (nmap TTL heuristic fallback) ───────────────────────────
def ttl_os_guess(ip):
    """Estimate OS from ping TTL."""
    flag = "-n" if os.name == "nt" else "-c"
    w_flag = ["-w","1000"] if os.name == "nt" else ["-W","1"]
    try:
        out = subprocess.check_output(
            ["ping", flag, "1"] + w_flag + [str(ip)],
            stderr=subprocess.DEVNULL, timeout=3
        ).decode()
        m = re.search(r"ttl[= ](\d+)", out, re.I)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:   return f"Linux/Unix/Android  (TTL={ttl})"
            if ttl <= 128:  return f"Windows             (TTL={ttl})"
            if ttl <= 255:  return f"Cisco/Network Device(TTL={ttl})"
    except Exception:
        pass
    return None

def nmap_os_fingerprint(ip):
    if not NMAP_AVAILABLE:
        return None
    try:
        nm = nmap.PortScanner()
        nm.scan(str(ip), arguments="-O --osscan-guess -T4 --max-retries 1", timeout=30)
        if str(ip) in nm.all_hosts():
            h = nm[str(ip)]
            if "osmatch" in h and h["osmatch"]:
                m = h["osmatch"][0]
                return f"{m['name']} (accuracy {m['accuracy']}%)"
    except Exception:
        pass
    return None

def nmap_service_version(ip, ports):
    """Use nmap -sV on found open ports for detailed service versions."""
    if not NMAP_AVAILABLE or not ports:
        return {}
    try:
        port_str = ",".join(str(p) for p in ports[:50])
        nm = nmap.PortScanner()
        nm.scan(str(ip), ports=port_str, arguments="-sV -T4 --max-retries 1 --version-intensity 5", timeout=60)
        results = {}
        if str(ip) in nm.all_hosts():
            for proto in nm[str(ip)].all_protocols():
                for port, info in nm[str(ip)][proto].items():
                    svc = info.get("name","")
                    prod = info.get("product","")
                    ver  = info.get("version","")
                    extra= info.get("extrainfo","")
                    label = " ".join(filter(None,[prod,ver,extra])).strip()
                    if label:
                        results[port] = label
        return results
    except Exception:
        return {}

# ── host scanner ──────────────────────────────────────────────────────────────
def discover_hosts(network):
    """Ping-sweep a network range."""
    hosts = list(ipaddress.ip_network(network, strict=False).hosts())
    live  = []
    lock  = threading.Lock()

    def check(ip):
        if ping_host(ip):
            with lock:
                live.append(str(ip))

    print(f"\n  {C['info']}Sweeping {C['highlight']}{len(hosts)}{C['info']} addresses...{C['reset']}")
    done = [0]
    with ThreadPoolExecutor(max_workers=100) as ex:
        futs = {ex.submit(check, ip): ip for ip in hosts}
        for f in as_completed(futs):
            done[0] += 1
            progress_bar(done[0], len(hosts), label=str(futs[f]))
    return sorted(live, key=lambda x: ipaddress.ip_address(x))

# ── port scanner ──────────────────────────────────────────────────────────────
COMMON_PORTS = sorted(set(list(PORT_DB.keys()) + HIGH_PORTS_OF_INTEREST))

def scan_ports(ip, port_list, workers=200, timeout=0.8):
    open_ports = []
    lock = threading.Lock()
    done = [0]

    def check(p):
        if tcp_connect(ip, p, timeout):
            with lock:
                open_ports.append(p)
        done[0] += 1
        progress_bar(done[0], len(port_list), label=f"port {p}")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(as_completed([ex.submit(check, p) for p in port_list]))

    return sorted(open_ports)

# ── host report ───────────────────────────────────────────────────────────────
def analyse_host(ip, full_scan=False):
    section(f"  HOST  {ip}")

    # reverse DNS
    spin = Spinner("Reverse DNS lookup...").start()
    rdns = reverse_dns(ip)
    spin.stop(f"Hostname: {C['host']}{rdns or 'n/a'}{C['reset']}")

    # OS fingerprint
    spin = Spinner("OS fingerprinting...").start()
    os_guess = nmap_os_fingerprint(ip) or ttl_os_guess(ip) or "Unknown"
    spin.stop(f"OS Guess: {C['os']}{os_guess}{C['reset']}")

    # port scan
    ports_to_scan = (
        list(range(1, 65536)) if full_scan
        else COMMON_PORTS + list(range(1024, 2000))
    )
    ports_to_scan = sorted(set(ports_to_scan))

    print(f"\n  {C['info']}Scanning {C['highlight']}{len(ports_to_scan)}{C['info']} ports...{C['reset']}")
    open_ports = scan_ports(ip, ports_to_scan)

    if not open_ports:
        print(f"\n  {C['warn']}No open TCP ports found.{C['reset']}")
        return {"ip": ip, "rdns": rdns, "os": os_guess, "ports": []}

    # service version detection via nmap
    spin = Spinner("Detecting service versions (nmap -sV)...").start()
    svc_versions = nmap_service_version(ip, open_ports)
    spin.stop(f"Service version scan complete ({len(svc_versions)} identified).")

    # banner grab for high-number unknowns + any open port
    results = []
    print(f"\n  {C['info']}Banner grabbing {C['highlight']}{len(open_ports)}{C['info']} open port(s)...{C['reset']}")
    for idx, port in enumerate(open_ports):
        progress_bar(idx+1, len(open_ports), label=f":{port}")
        svc_name, proto = get_service_name(port)
        banner = banner_grab(ip, port)
        nmap_ver = svc_versions.get(port, "")
        results.append({
            "port": port, "service": svc_name, "proto": proto,
            "banner": banner, "nmap_version": nmap_ver
        })

    # ── print port table ──────────────────────────────────────────────────────
    print()
    hr()
    hdr = f"  {'PORT':<8} {'PROTO':<6} {'SERVICE':<22} {'VERSION / BANNER'}"
    print(C["header"] + hdr + C["reset"])
    hr()
    for r in results:
        p     = r["port"]
        proto = r["proto"]
        svc   = r["service"]
        ver   = r["nmap_version"]
        ban   = r["banner"]

        # build detail string
        detail = ver
        if ban and not ver:
            btype, btext = ban
            detail = f"[{btype}] {btext}"
        elif ban and ver:
            _, btext = ban
            detail = f"{ver}  ·  {btext}"

        # colour port by risk
        if p in (22,23,80,443,3389,5900,21):
            port_col = C["warn"]
        elif p > 1024 and p not in PORT_DB:
            port_col = C["err"]
        else:
            port_col = C["port"]

        print(
            f"  {port_col}{p:<8}{C['reset']}"
            f"{C['dim']}{proto:<6}{C['reset']}"
            f"{C['service']}{svc:<22}{C['reset']}"
            f"{C['highlight']}{detail[:60]}{C['reset']}"
        )
    hr()

    return {"ip": ip, "rdns": rdns, "os": os_guess, "ports": results}

# ── save results ──────────────────────────────────────────────────────────────
def save_report(all_results):
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.expanduser(f"~/netbomb_{ts}.json")
    with open(path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n  {C['ok']}Report saved → {C['highlight']}{path}{C['reset']}")

    # human-readable txt
    txt_path = os.path.expanduser(f"~/netbomb_{ts}.txt")
    with open(txt_path, "w") as f:
        f.write(f"NETBOMB REPORT  {datetime.now()}\n{'='*64}\n")
        for host in all_results:
            f.write(f"\nHOST: {host['ip']}  ({host.get('rdns','n/a')})\n")
            f.write(f"OS:   {host.get('os','Unknown')}\n")
            f.write(f"{'PORT':<8}{'PROTO':<8}{'SERVICE':<22}{'DETAIL'}\n")
            f.write("-"*64+"\n")
            for r in host.get("ports", []):
                detail = r.get("nmap_version","")
                ban = r.get("banner")
                if ban and not detail:
                    detail = f"[{ban[0]}] {ban[1]}"
                f.write(f"{r['port']:<8}{r['proto']:<8}{r['service']:<22}{detail[:50]}\n")
    print(f"  {C['ok']}Text report  → {C['highlight']}{txt_path}{C['reset']}")

# ── input helpers ─────────────────────────────────────────────────────────────
def prompt(msg, default=None):
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  {C['warn']}▶{C['reset']}  {msg}{C['dim']}{suffix}{C['reset']} : ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return val or default or ""

def yn(msg, default="y"):
    val = prompt(msg + " (y/n)", default).lower()
    return val.startswith("y")

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    print_banner()

    if os.geteuid() != 0:
        print(f"  {C['warn']}⚠  Running without root.  OS fingerprinting & raw scans work best as root.{C['reset']}\n")

    # ── target input ──────────────────────────────────────────────────────────
    print(f"  {C['info']}Enter a single IP, hostname, or CIDR range (e.g. 192.168.1.0/24){C['reset']}\n")
    raw_target = prompt("Target IP / CIDR / hostname")

    if not raw_target:
        print(f"  {C['err']}No target provided. Exiting.{C['reset']}")
        sys.exit(1)

    # resolve hostname or validate range
    try:
        network = ipaddress.ip_network(raw_target, strict=False)
        targets = [str(h) for h in network.hosts()] if network.num_addresses > 1 else [str(network.network_address)]
        is_range = network.num_addresses > 2
    except ValueError:
        ip = resolve_host(raw_target)
        if not ip:
            print(f"  {C['err']}Cannot resolve {raw_target}{C['reset']}")
            sys.exit(1)
        targets = [ip]
        is_range = False

    # ── scan options ──────────────────────────────────────────────────────────
    print()
    full_port = yn("Full port scan (1-65535)?  [slower, more thorough]", "n")
    save      = yn("Save report to disk?", "y")

    # ── host discovery for ranges ─────────────────────────────────────────────
    if is_range:
        section("HOST DISCOVERY  (ICMP Ping Sweep)")
        live_hosts = discover_hosts(raw_target)
        print(f"\n  {C['ok']}{len(live_hosts)} live host(s) found.{C['reset']}")
        if not live_hosts:
            print(f"  {C['warn']}No hosts responded to ping. They may block ICMP.{C['reset']}")
            if yn("  Scan all hosts anyway?", "n"):
                live_hosts = targets
            else:
                sys.exit(0)
    else:
        live_hosts = targets

    # ── per-host analysis ─────────────────────────────────────────────────────
    all_results = []
    for ip in live_hosts:
        result = analyse_host(ip, full_scan=full_port)
        all_results.append(result)

    # ── summary table ─────────────────────────────────────────────────────────
    section("SCAN SUMMARY")
    print(f"\n  {'IP ADDRESS':<20}{'HOSTNAME':<35}{'OPEN PORTS':<12}{'OS'}")
    hr()
    for h in all_results:
        ports_str = ",".join(str(r["port"]) for r in h["ports"][:8])
        if len(h["ports"]) > 8:
            ports_str += f"…+{len(h['ports'])-8}"
        print(
            f"  {C['host']}{h['ip']:<20}{C['reset']}"
            f"{C['dim']}{(h.get('rdns') or 'n/a')[:33]:<35}{C['reset']}"
            f"{C['ok']}{ports_str:<12}{C['reset']}"
            f"{C['os']}{(h.get('os') or 'Unknown')[:40]}{C['reset']}"
        )
    hr()
    print(f"\n  {C['ok']}✔  Scan complete.  Hosts scanned: {len(all_results)}{C['reset']}\n")

    if save:
        save_report(all_results)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C['warn']}Scan interrupted by user.{C['reset']}\n")
        sys.exit(0)
