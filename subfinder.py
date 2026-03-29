#!/usr/bin/env python3
import requests
import argparse
import concurrent.futures
import socket
import re
import sys
import signal
from colors import *

found = set()
resolved = set()
args = None

# =========================
# Ctrl + C Handler
# =========================
def ctrl_handler(sig, frame):
    print(f"\n[{y}STOP{rs}] Scan dihentikan oleh user (Ctrl+C)")
    print(f"[{g}INFO{rs}] Total ditemukan: {len(found)} subdomain")

    if args and args.output:
        try:
            with open(args.output, "w") as f:
                for sub in sorted(found):
                    f.write(sub + "\n")
            print(f"[{g}INFO{rs}] Hasil otomatis disimpan ke: {args.output}")
        except:
            pass

    sys.exit(0)

# =========================
# Passive Sources
# =========================
def crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        data = requests.get(url, timeout=10).json()

        for entry in data:
            names = entry.get("name_value", "")
            for sub in names.split("\n"):
                if domain in sub:
                    found.add(sub.strip())
    except:
        pass


def alienvault(domain):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        data = requests.get(url, timeout=10).json()

        for item in data.get("passive_dns", []):
            sub = item.get("hostname")
            if sub and domain in sub:
                found.add(sub.strip())
    except:
        pass


def hackertarget(domain):
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = requests.get(url, timeout=10).text.split("\n")

        for line in r:
            if "," in line:
                sub = line.split(",")[0]
                if domain in sub:
                    found.add(sub.strip())
    except:
        pass


# =========================
# Crawler
# =========================
def crawler(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        links = re.findall(r"https?://([a-zA-Z0-9.-]+)", r.text)

        for link in links:
            if domain in link:
                found.add(link)
    except:
        pass


# =========================
# Resolver
# =========================
def resolve(sub):
    try:
        socket.gethostbyname(sub)
        resolved.add(sub)
    except:
        pass


# =========================
# Recursive discovery
# =========================
def recursive(domain):
    subs = list(found)

    for sub in subs:
        parts = sub.split(".")
        if len(parts) > 2:
            base = ".".join(parts[1:])
            crtsh(base)


# =========================
# Main
# =========================
def main():
    global args

    signal.signal(signal.SIGINT, ctrl_handler)

    parser = argparse.ArgumentParser(
        description="Subfinder menggunakan Python",
        epilog="""
Contoh:
python subfinder.py -d target.com
python subfinder.py -d target.com --resolve
python subfinder.py -d target.com --threads 200
python subfinder.py -d target.com -o hasil.txt
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-d", "--domain", help="Domain target")
    parser.add_argument("--threads", type=int, default=100, help="Thread scan")
    parser.add_argument("--resolve", action="store_true", help="Validasi DNS aktif")
    parser.add_argument("-o", "--output", help="Simpan hasil ke file txt")

    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        return

    domain = args.domain

    print(r"""
   _____       __    _____           __
  / ___/__  __/ /_  / __(_)___  ____/ /
  \__ \/ / / / __ \/ /_/ / __ \/ __  / 
 ___/ / /_/ / /_/ / __/ / / / / /_/ /   v 1.2
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/   
                                       
                     Created Bang yog
""")

    print(f"[{g}INFO{rs}] Passive discovery...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        ex.submit(crtsh, domain)
        ex.submit(alienvault, domain)
        ex.submit(hackertarget, domain)
        ex.submit(crawler, domain)

    recursive(domain)

    print(f"\n[{g}INFO{rs}] {len(found)} subdomain ditemukan\n")

    results = []

    if args.resolve:
        print(f"[{g}INFO{rs}] Resolving subdomain...\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            ex.map(resolve, found)

        print(f"[{g}INFO{rs}] {len(resolved)} subdomain valid\n")
        results = sorted(resolved)
    else:
        results = sorted(found)

    for sub in results:
        print(sub)

    # =========================
    # Save Output
    # =========================
    if args.output:
        try:
            with open(args.output, "w") as f:
                for sub in results:
                    f.write(sub + "\n")
            print(f"\n[{g}INFO{rs}] Hasil disimpan ke: {args.output}")
        except Exception as e:
            print(f"[{r}ERROR{rs}] Gagal menyimpan file: {e}")


if __name__ == "__main__":
    main()