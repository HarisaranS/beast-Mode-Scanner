# beastscanner/views.py
from django.shortcuts import render
from .db import collection
import nmap
from mac_vendor_lookup import MacLookup
import subprocess
import re
from colorama import init
from .mongo_utils import save_scan_result
from django.shortcuts import render
from pymongo import MongoClient

init(autoreset=True)

def get_mac(ip):
    try:
        subprocess.call(["ping", "-n", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        arp_cmd = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.DEVNULL).decode()
        mac = re.search(r"(([a-fA-F0-9]{2}[-:]){5}[a-fA-F0-9]{2})", arp_cmd)
        return mac.group(0).lower() if mac else "MAC Not Found"
    except:
        return "MAC Not Found"

def get_mac_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except:
        return "Unknown Vendor"

def smart_os_detection(host_info, mac_vendor):
    os_guesses = []
    for match in host_info.get('osmatch', []):
        name = match.get('name', 'Unknown OS')
        acc = match.get('accuracy', '0')
        if int(acc) >= 90:
            os_guesses.append(f"{name} (Accuracy: {acc}%)")

    if not os_guesses and 'osmatch' in host_info and host_info['osmatch']:
        fallback = host_info['osmatch'][0]
        os_guesses.append(f"{fallback.get('name')} (Accuracy: {fallback.get('accuracy')}%) ")

    os_info = "\n".join(os_guesses[:3]) if os_guesses else "OS Detection Uncertain"

    vendor_lower = mac_vendor.lower()
    if "android" not in os_info.lower() and any(v in vendor_lower for v in ["samsung", "huawei", "xiaomi", "oneplus", "oppo", "realme", "vivo", "nokia", "redmi"]):
        os_info += "\n(Guess: Android based on Vendor)"
    elif any(v in vendor_lower for v in ["apple", "foxconn", "pegatron"]):
        os_info += "\n(Guess: iOS based on Vendor)"

    return os_info

def scan_target(ip):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(ip, arguments="-T5 -O --osscan-guess --version-all --top-ports 1000 --script vulners")

        if ip not in scanner.all_hosts():
            return {
                "ip": ip,
                "mac": "Host unreachable",
                "vendor": "Possibly Firewalled",
                "os": "-",
                "ports": "-",
                "vulnerabilities": "-"
            }

        host_info = scanner[ip]

        mac = get_mac(ip)
        vendor = get_mac_vendor(mac) if mac != "MAC Not Found" else "Unknown Vendor"
        os = smart_os_detection(host_info, vendor)

        ports = []
        if 'tcp' in host_info:
            ports.extend([f"{port}/{host_info['tcp'][port]['state']}" for port in sorted(host_info['tcp'])])
        if 'udp' in host_info:
            ports.extend([f"{port}/{host_info['udp'][port]['state']}" for port in sorted(host_info['udp'])])
        open_ports = ', '.join(ports) if ports else "No Open Ports"

        vuln = []
        for script in host_info.get('hostscript', []):
            if "vulners" in script.get('id', ''):
                vuln.append(script.get('output', ''))
        vulnerabilities = '\n'.join(vuln[:1]) if vuln else "None"

        result = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "os": os,
            "ports": open_ports,
            "vulnerabilities": vulnerabilities
        }

        # Store the result in MongoDB
        collection.insert_one(result)

        return result

    except Exception as e:
        return {
            "ip": ip,
            "mac": "Error",
            "vendor": "Error",
            "os": "Error",
            "ports": "Error",
            "vulnerabilities": "Error"
        }

def home(request):
    results = []
    if request.method == "POST":
        target = request.POST.get("target", "")
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments="-sn")
        live_hosts = scanner.all_hosts()
        for ip in live_hosts:
            result = scan_target(ip)
            results.append(result)
    return render(request, 'beastscanner/home.html', {'results': results})

def scan_results_view(request):
    client = MongoClient("mongodb://localhost:27017/")
    db = client["beastmode_db"]
    collection = db["scan_results"]
    results = list(collection.find().sort("scanned_at", -1))  # Newest first
    return render(request, 'beastscanner/results.html', {'results': results})

