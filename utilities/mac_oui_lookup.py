#!/usr/bin/env python3

import os
import urllib.request
import re
import time
import sys
import ipaddress
import random

OUI_URL = "https://standards-oui.ieee.org/oui.txt"  # Fixed to use HTTPS
OUI_FILENAME = "oui.txt"
CACHE_EXPIRY_SECONDS = 30 * 24 * 3600  # 30 days

# ANSI color codes
BLUE = "\033[94m"
WHITE = "\033[97m"
YELLOW = "\033[93m"
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def color_print(text, color=WHITE):
    print(f"{color}{text}{RESET}")

def download_oui_file():
    color_print("Downloading OUI database from IEEE...", BLUE)
    try:
        urllib.request.urlretrieve(OUI_URL, OUI_FILENAME)
        color_print(f"Downloaded and saved to {OUI_FILENAME}", GREEN)
    except Exception as e:
        color_print(f"Failed to download OUI database: {e}", RED)

def is_cache_expired():
    if not os.path.isfile(OUI_FILENAME):
        return True
    try:
        last_mod = os.path.getmtime(OUI_FILENAME)
        return (time.time() - last_mod) > CACHE_EXPIRY_SECONDS
    except Exception as e:
        color_print(f"Error checking OUI cache file: {e}", RED)
        return True

def parse_oui_file():
    if is_cache_expired():
        download_oui_file()

    if not os.path.isfile(OUI_FILENAME):
        color_print(f"Error: OUI file '{OUI_FILENAME}' not found after download attempt.", RED)
        sys.exit(1)

    oui_dict = {}
    pattern = re.compile(
        r"^(?P<oui>([0-9A-Fa-f]{2}-){2}[0-9A-Fa-f]{2})\s+\((?:hex|base 16)\)\s+(?P<vendor>.+)$"
    )

    try:
        with open(OUI_FILENAME, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                match = pattern.match(line)
                if match:
                    oui_raw = match.group("oui")
                    oui = oui_raw.replace("-", "").upper()
                    vendor = match.group("vendor").strip()
                    oui_dict[oui] = vendor
    except Exception as e:
        color_print(f"Error reading/parsing OUI file: {e}", RED)
        sys.exit(1)

    return oui_dict

def normalize_mac(mac):
    if not mac:
        return None
    mac = mac.upper().replace('.', '').replace(':', '').replace('-', '')
    if len(mac) != 12 or any(c not in "0123456789ABCDEF" for c in mac):
        return None
    return mac

def lookup_vendor(mac, oui_dict):
    mac_norm = normalize_mac(mac)
    if not mac_norm:
        return None
    oui = mac_norm[:6]
    return [oui_dict.get(oui, "Unknown Vendor")]

def print_results(mac, vendors):
    mac_norm = normalize_mac(mac)
    mac_colon = ':'.join(mac_norm[i:i+2] for i in range(0, 12, 2)) if mac_norm else mac
    separator = "=" * 30
    color_print(separator, YELLOW)
    color_print("Lookup Result:", GREEN)
    color_print(separator, YELLOW)
    color_print(f"MAC Address: {mac_colon}", BLUE)
    if not vendors:
        color_print("Invalid MAC address format.\n", RED)
    elif len(vendors) == 1:
        color_print(f"Vendor: {vendors[0]}\n", WHITE)
    else:
        color_print("Possible vendors (partial match):", YELLOW)
        for v in vendors:
            color_print(f" - {v}", WHITE)
    color_print(separator + "\n", YELLOW)

def lookup_by_vendor_name(oui_dict):
    clear_screen()
    color_print("Lookup by Vendor Name\n", GREEN)
    color_print("Enter full or partial vendor name to search.\n", YELLOW)
    search_name = input("Vendor Name: ").strip().lower()
    if not search_name:
        color_print("No input entered.\n", RED)
        return

    matches = [(k, v) for k, v in oui_dict.items() if search_name in v.lower()]
    if not matches:
        color_print(f"No vendors found matching '{search_name}'.\n", RED)
        return

    color_print(f"Found {len(matches)} vendor(s) matching '{search_name}':\n", WHITE)
    for oui, vendor in matches:
        mac_formatted = ':'.join(oui[i:i+2] for i in range(0, 6, 2))
        color_print(f"{mac_formatted} - {vendor}", BLUE)
    print()

def mac_from_eui64(ipv6_addr_str):
    """
    Extract MAC from an IPv6 address assuming it uses EUI-64 format
    EUI-64 inserts fffe in the middle of the MAC and flips the 7th bit of the first byte
    """
    try:
        ip = ipaddress.IPv6Address(ipv6_addr_str)
    except ipaddress.AddressValueError:
        return None

    interface_id = ip.packed[-8:]
    if interface_id[3] != 0xFF or interface_id[4] != 0xFE:
        return None  # Not a standard EUI-64

    mac_bytes = bytearray(6)
    mac_bytes[0] = interface_id[0] ^ 0x02  # Flip the universal/local bit back
    mac_bytes[1] = interface_id[1]
    mac_bytes[2] = interface_id[2]
    mac_bytes[3] = interface_id[5]
    mac_bytes[4] = interface_id[6]
    mac_bytes[5] = interface_id[7]

    mac_str = ''.join(f"{b:02X}" for b in mac_bytes)
    return mac_str

def ipv6_lookup(oui_dict):
    clear_screen()
    color_print("Option 4: Extract MAC from IPv6 EUI-64\n", GREEN)
    color_print("IPv6 EUI-64 addresses embed the MAC address within the lower 64 bits.\n"
                "This tool attempts to extract it if the address is EUI-64 formatted.\n"
                "If not EUI-64, it may be a global or randomly generated address.\n", YELLOW)
    ipv6 = input("Enter IPv6 address with embedded MAC (EUI-64): ").strip()
    mac = mac_from_eui64(ipv6)
    if not mac:
        color_print("Could not extract a valid EUI-64 MAC address from the IPv6 input.\n"
                    "This address is likely not using EUI-64 format.\n", RED)
        return
    vendors = lookup_vendor(mac, oui_dict)
    color_print(f"Extracted MAC from IPv6: {':'.join(mac[i:i+2] for i in range(0,12,2))}", BLUE)
    print_results(mac, vendors)

def generate_random_global_prefix():
    # First hextet: global unicast range 0x2000 - 0x3FFF (2000::/3)
    first = random.randint(0x2000, 0x3FFF)
    # Next three hextets randomly generated
    others = [random.randint(0x0000, 0xFFFF) for _ in range(3)]
    return f"{first:04x}:{others[0]:04x}:{others[1]:04x}:{others[2]:04x}"

def eui64_menu():
    clear_screen()
    color_print("Option 5: Generate IPv6 Addresses from MAC (EUI-64)\n", GREEN)
    color_print("This generates both a Link-Local and Global IPv6 address from a MAC using EUI-64 format.\n"
                "EUI-64 inserts 'fffe' in the middle of the MAC and flips the 7th bit of the first byte.\n", YELLOW)
    mac = input("Enter MAC address (leave blank to use a sample MAC): ").strip()
    if not mac:
        mac = "00:11:22:33:44:55"
        color_print(f"Using sample MAC: {mac}", BLUE)
    mac_norm = normalize_mac(mac)
    if not mac_norm:
        color_print("Invalid MAC address format.\n", RED)
        return

    mac_bytes = bytearray.fromhex(mac_norm)
    mac_bytes[0] ^= 0x02  # Flip universal/local bit

    eui64_bytes = mac_bytes[:3] + b'\xff\xfe' + mac_bytes[3:]
    eui64_str = ':'.join(f"{eui64_bytes[i]:02x}{eui64_bytes[i+1]:02x}" for i in range(0,8,2))

    # Fixed: Use single colon to join prefix and interface ID
    link_local = f"fe80:0000:0000:0000:{eui64_str}"
    global_prefix = generate_random_global_prefix()
    global_addr = f"{global_prefix}:{eui64_str}"

    color_print(f"Link-Local IPv6: {link_local}", BLUE)
    color_print(f"Global IPv6:     {global_addr}\n", WHITE)

def generate_random_ipv6():
    clear_screen()
    color_print("Option 6: Generate Random IPv6 Address (non-EUI-64)\n", GREEN)
    color_print("This creates a link-local and global IPv6 address using independently generated random 64-bit interface IDs.\n"
                "This is often used instead of EUI-64 for privacy or simplicity.\n", YELLOW)

    # Generate two different interface IDs (64 bits each)
    interface_id_link_local = ':'.join(f"{random.getrandbits(16):04x}" for _ in range(4))
    interface_id_global = ':'.join(f"{random.getrandbits(16):04x}" for _ in range(4))

    # Fixed: Use single colon to join prefix and interface ID
    link_local = f"fe80:0000:0000:0000:{interface_id_link_local}"
    global_prefix = generate_random_global_prefix()
    global_addr = f"{global_prefix}:{interface_id_global}"

    color_print(f"Link-Local IPv6: {link_local}", BLUE)
    color_print(f"Global IPv6:     {global_addr}\n", WHITE)

def lookup_interactive(oui_dict):
    try:
        while True:
            clear_screen()
            color_print("MAC Address Vendor Lookup Tool", GREEN)
            color_print("Select an option. Type 0 to exit.\n", YELLOW)

            color_print("MAC Lookup Options:", BLUE)
            color_print(" 1. Lookup a single MAC address", WHITE)
            color_print(" 2. Bulk lookup from a file", WHITE)
            color_print(" 3. Lookup by Vendor Name", WHITE)

            color_print("\nIPv6 EUI-64 Generation/Extraction:", BLUE)
            color_print(" 4. Extract MAC from EUI-64 IPv6", WHITE)
            color_print(" 5. Generate IPv6 from MAC (EUI-64)", WHITE)
            color_print(" 6. Generate random IPv6 (non-EUI-64)", WHITE)
            color_print(" 0. Quit", WHITE)

            choice = input(f"{BLUE}Enter choice [0-6]: {RESET}").strip()
            if choice == "0":
                color_print("Goodbye!", GREEN)
                break
            elif choice == "1":
                clear_screen()
                mac = input("Enter MAC Address: ").strip()
                vendors = lookup_vendor(mac, oui_dict)
                print_results(mac, vendors)
                input("Press Enter to return to menu...")
            elif choice == "2":
                clear_screen()
                bulk_file = input("Enter filename with MAC addresses: ").strip()
                if not os.path.isfile(bulk_file):
                    color_print("File not found.\n", RED)
                    input("Press Enter to return to menu...")
                    continue
                try:
                    with open(bulk_file, 'r', encoding='utf-8', errors='ignore') as bf:
                        for line in bf:
                            line = line.strip()
                            if line:
                                vendors = lookup_vendor(line, oui_dict)
                                print_results(line, vendors)
                except Exception as e:
                    color_print(f"Error reading bulk file: {e}\n", RED)
                input("Press Enter to return to menu...")
            elif choice == "3":
                lookup_by_vendor_name(oui_dict)
                input("Press Enter to return to menu...")
            elif choice == "4":
                ipv6_lookup(oui_dict)
                input("Press Enter to return to menu...")
            elif choice == "5":
                eui64_menu()
                input("Press Enter to return to menu...")
            elif choice == "6":
                generate_random_ipv6()
                input("Press Enter to return to menu...")
            else:
                color_print("Invalid choice. Please enter a number between 0 and 6.\n", RED)
                input("Press Enter to return to menu...")
    except KeyboardInterrupt:
        color_print("\nExiting on user interrupt. Goodbye!", GREEN)

def main():
    oui_dict = parse_oui_file()
    lookup_interactive(oui_dict)

if __name__ == "__main__":
    main()
