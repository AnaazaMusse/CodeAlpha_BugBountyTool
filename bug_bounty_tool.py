#!/usr/bin/env python3
"""
CodeAlpha Bug Bounty Tool
Task 1: Vulnerability Scanner

import requests
import socket
import threading
import argparse
import time
from urllib.parse import urljoin, urlparse
import re
import json
from datetime import datetime

class BugBountyTool:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []
        
    def check_sql_injection(self):
        """Check for SQL injection vulnerabilities"""
        print("[*] Testing for SQL Injection...")
        
        test_urls = [
            f"http://{self.target}/product?id=1",
            f"http://{self.target}/user?id=1"
        ]
        
        for url in test_urls:
            try:
                payload = "' OR '1'='1"
                test_url = f"{url}{payload}"
                response = requests.get(test_url, timeout=5)
                
                error_patterns = ["sql syntax", "mysql_fetch", "ora-"]
                
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.vulnerabilities.append({
                            "type": "SQL Injection",
                            "url": test_url,
                            "severity": "High"
                        })
                        print(f"[!] SQL Injection found: {test_url}")
                        break
            except Exception:
                continue

    def check_xss(self):
        """Check for XSS vulnerabilities"""
        print("[*] Testing for XSS...")
        
        test_urls = [
            f"http://{self.target}/search?q=test",
            f"http://{self.target}/contact?name=test"
        ]
        
        for url in test_urls:
            try:
                payload = "<script>alert('XSS')</script>"
                test_url = f"{url}{payload}"
                response = requests.get(test_url, timeout=5)
                
                if payload in response.text:
                    self.vulnerabilities.append({
                        "type": "XSS",
                        "url": test_url,
                        "severity": "Medium"
                    })
                    print(f"[!] XSS vulnerability found: {test_url}")
            except Exception:
                continue

    def port_scan(self):
        """Basic port scanning"""
        print("[*] Scanning common ports...")
        
        common_ports = [21, 22, 80, 443, 3306, 3389]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    print(f"[+] Port {port} is open")
                sock.close()
            except Exception:
                pass

    def generate_report(self):
        """Generate vulnerability report"""
        print("\n" + "="*50)
        print("BUG BOUNTY SCAN REPORT")
        print("="*50)
        print(f"Target: {self.target}")
        print(f"Scan Date: {datetime.now()}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\nVULNERABILITIES:")
            for vuln in self.vulnerabilities:
                print(f"[{vuln['severity']}] {vuln['type']} - {vuln['url']}")
        else:
            print("\nNo vulnerabilities found.")
        
        print("="*50)

    def run_scan(self):
        """Run all scans"""
        print(f"[*] Starting bug bounty scan for: {self.target}")
        
        self.check_sql_injection()
        self.check_xss()
        self.port_scan()
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Bug Bounty Tool")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    
    args = parser.parse_args()
    
    print("CODEALPHA BUG BOUNTY TOOL")
    print("Cybersecurity Internship Task 1\n")
    
    scanner = BugBountyTool(args.target)
    
    try:
        scanner.run_scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")

if __name__ == "__main__":
    main()
