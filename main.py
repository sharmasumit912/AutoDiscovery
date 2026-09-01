import subprocess

import os
import time
from rich import print as cprint

# ===========================
# Banner
# ===========================

logo = r"""
    ___         __             ____  _
   /   | __  __/ /_____       / __ \(_)___________ _   _____  _______  __
  / /| |/ / / / __/ __ \     / / / / ___/ ___/ __ \ | / / _ \/ ___/ / / /
 / ___ / /_/ / /_/ /_/ /    / /_/ / (__  ) /__/ /_/ / |/ /  __/ /  / /_/ /
/_/  |_\__,_/\__/\____/    /_____/_/____/\___/\____/|___/\___/_/   \__, /
                                                                  /____/
"""

print(logo)

# ===========================
# Create Output Folder
# ===========================

OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

SUBDOMAIN_FILE = os.path.join(OUTPUT_DIR, "subdomains.txt")
ALIVE_FILE = os.path.join(OUTPUT_DIR, "alive.txt")

start = time.time()

# ===========================
# Input Domain
# ===========================

domain = input("Enter Domain: ").strip()

# ===========================
# Run Subfinder
# ===========================

cprint("[cyan][+] Running Subfinder...[/cyan]")

subfinder = subprocess.run(
    [
        "subfinder",
        "-d",
        domain,
        "-silent",
        "-o",
        SUBDOMAIN_FILE,
    ],
    capture_output=True,
    text=True,
)

if subfinder.returncode != 0:
    cprint("[red]Subfinder failed.[/red]")
    print(subfinder.stderr)
    exit()

if not os.path.exists(SUBDOMAIN_FILE):
    cprint("[red]subdomains.txt not created.[/red]")
    exit()

with open(SUBDOMAIN_FILE) as f:
    subdomains = [x.strip() for x in f if x.strip()]

cprint(f"[green][+] {len(subdomains)} Subdomains Found[/green]")

if len(subdomains) == 0:
    cprint("[red]No subdomains found.[/red]")
    exit()

# ===========================
# Run HTTPX
# ===========================

cprint("[cyan][+] Checking Alive Hosts...[/cyan]")

httpx = subprocess.run(
    [
        "/home/kali/go/bin/httpx",
        "-l",

        SUBDOMAIN_FILE,
        "-silent",
        "-threads",
        "100",
        "-timeout",
        "5",
        "-retries",
        "1",
        "-o",
        ALIVE_FILE,
    ],
    capture_output=True,
    text=True,
)

if httpx.returncode != 0:
    cprint("[red]HTTPX failed.[/red]")
    print(httpx.stderr)
    exit()

if not os.path.exists(ALIVE_FILE):
    cprint("[red]alive.txt not created.[/red]")
    exit()

with open(ALIVE_FILE) as f:
    alive_hosts = [x.strip() for x in f if x.strip()]

cprint(f"[green][+] {len(alive_hosts)} Alive Hosts Found[/green]")

if len(alive_hosts) == 0:
    cprint("[yellow]No alive hosts found.[/yellow]")
    exit()

# ===========================
# FFUF Scan
# ===========================

cprint("[cyan][+] Starting FFUF Scan...[/cyan]")

WORDLIST = "/usr/share/wordlists/dirb/common.txt"

for host in alive_hosts:

    print(f"\nScanning {host}")

    filename = (
        host.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
    )

    output_json = os.path.join(
        OUTPUT_DIR,
        filename + "_ffuf.json",
    )

    subprocess.run(
        [
            "ffuf",
            "-u",
            f"{host}/FUZZ",
            "-w",
            WORDLIST,
            "-mc",
            "200,204,301,302,307,401,403",
            "-t",
            "100",
            "-c",
            "-of",
            "json",
            "-o",
            output_json,
        ]
    )

# ===========================
# Summary
# ===========================

elapsed = time.time() - start

print()

cprint("[bold green]==============================[/bold green]")
cprint("[bold green]Scan Completed Successfully[/bold green]")
cprint(f"[green]Subdomains : {len(subdomains)}[/green]")
cprint(f"[green]Alive Hosts: {len(alive_hosts)}[/green]")
cprint(f"[green]Results    : {OUTPUT_DIR}/[/green]")
cprint(f"[green]Time Taken : {elapsed:.2f} seconds[/green]")
cprint("[bold green]==============================[/bold green]")
