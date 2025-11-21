#!/usr/bin/env python3
"""
header_analysis.py
Usage:
    python header_analysis.py header.txt

Now includes:
    run_analysis(path) → returns full analysis as a text string
"""

import re
import sys
import socket
from email import policy
from email.parser import BytesParser
import dns.resolver
import whois
from io import StringIO

IP_RE = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"


def dns_txt(domain):
    """Fetch TXT records using dnspython."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        return "; ".join([txt.to_text().strip('"') for txt in answers])
    except:
        return "N/A"


def ptr_lookup(ip):
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"


def whois_lookup(ip):
    """WHOIS using python-whois."""
    try:
        data = whois.whois(ip)
        return f"Org: {data.get('org')} | Country: {data.get('country')}"
    except:
        return "N/A"


def load_message(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def extract_basic_meta(msg):
    fields = ["From", "To", "Subject", "Date", "Message-ID"]
    return {f: msg.get(f, "N/A") for f in fields}


def extract_received(msg):
    recs = msg.get_all("Received", []) or []
    return list(reversed(recs))  # oldest → newest


def parse_received_line(line):
    ts = line.split(";")[-1].strip() if ";" in line else ""
    ips = re.findall(IP_RE, line)
    helo = "Unknown"
    m = re.search(r"from\s+([^\s\(\;]+)", line)
    if m:
        helo = m.group(1)
    return {"raw": line.strip(), "timestamp": ts, "ips": ips, "helo": helo}


# ============================================================
# NEW FUNCTION: RETURNS FULL REPORT AS STRING (no printing)
# ============================================================

def run_analysis(path):
    """Runs the full analysis and returns the output as text."""
    out = StringIO()

    msg = load_message(path)
    meta = extract_basic_meta(msg)
    recs = extract_received(msg)

    out.write("\n=== BASIC METADATA ===\n")
    for k, v in meta.items():
        out.write(f"{k}: {v}\n")

    out.write("\n=== HOP TIMELINE (origin → destination) ===\n")
    parsed = [parse_received_line(r) for r in recs]

    if not parsed:
        out.write("No Received headers found.\n")
    else:
        for i, hop in enumerate(parsed, 1):
            out.write(f"\nHop {i}:\n")
            out.write(f" Timestamp: {hop['timestamp']}\n")
            out.write(f" HELO     : {hop['helo']}\n")
            out.write(f" IPs      : {', '.join(hop['ips']) if hop['ips'] else 'None'}\n")

            if hop["ips"]:
                ip = hop["ips"][0]
                out.write(f" PTR      : {ptr_lookup(ip)}\n")
                out.write(f" WHOIS    : {whois_lookup(ip)}\n")

    out.write("\n=== AUTH CHECKS (SPF / DKIM / DMARC) ===\n")
    frm = meta.get("From", "")
    m = re.search(r"@([A-Za-z0-9\.-]+)", frm)
    domain = m.group(1) if m else None

    if not domain:
        out.write("Could not extract sender domain.\n")
    else:
        out.write(f"Domain: {domain}\n")
        out.write(f"SPF TXT: {dns_txt(domain)}\n")
        out.write(f"DMARC TXT: {dns_txt(f'_dmarc.{domain}')}\n")

        dkim = msg.get("DKIM-Signature")
        if dkim:
            s = re.search(r"s=([^;]+)", dkim)
            sel = s.group(1) if s else None
            if sel:
                out.write(f"DKIM selector: {sel}\n")
                out.write(f"DKIM TXT: {dns_txt(f'{sel}._domainkey.{domain}')}\n")
            else:
                out.write("DKIM-Signature present but selector missing.\n")
        else:
            out.write("No DKIM-Signature header found.\n")

    out.write("\n=== END ===\n")

    return out.getvalue()


# ============================================================
# ORIGINAL CLI EXECUTION (still works)
# ============================================================

def main(path):
    text = run_analysis(path)
    print(text)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python header_analysis.py header.txt")
        sys.exit(1)
    main(sys.argv[1])
