#!/usr/bin/env python
"""
Cyberscope-AI - Professional Web Vulnerability Scanner

A comprehensive web vulnerability assessment tool for security professionals
and developers. Detects XSS, SQL Injection, CSRF, and other security issues.

Usage:
    python Cyberscope-AI.py

Author: Cyberscope-AI Contributors
License: MIT
Version: 2.0.0
"""

from scanner import Scanner
from models.scan_result import ScanResult
from models.vulnerability import Severity
from config.logging_config import setup_logging
from reporters import CSVReporter, HTMLReporter, JSONReporter
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
import logging
import sys
import re

# Setup logging
logger = setup_logging(log_level="INFO")


def display_banner() -> None:
    """Display the Cyberscope-AI welcome banner."""
    banner = r"""
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ███████╗ ██████╗  █████╗ ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔══██╗██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║     ██║   ██║██████╔╝█████╗   ███████║██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝   ██╔══██║██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║╚██████╗╚██████╔╝██║     ███████╗ ██║  ██║██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝ ╚═╝  ╚═╝╚═╝

                              >>> Cyberscope-AI | by Shivansh Gupta <<<
    
  🔍 Professional Web Vulnerability Scanner v2.0
  🛡️  Multiple Detection Engines (XSS, SQLi, CSRF)
  📊 Multiple Report Formats (JSON, CSV, HTML)
  ⚡ Concurrent Scanning Support
  🔐 Security Header Analysis
    
    """
    print(banner)


def get_target_url() -> str:
    """
    Prompt and validate target URL.
    
    Returns:
        Validated target URL
    """
    while True:
        try:
            url: str = input("Enter the target URL (e.g., http://example.com): ").strip()
            
            if not url:
                print("[!] Error: URL cannot be empty")
                continue
            
            if not url.startswith(('http://', 'https://')):
                print("[!] Error: URL must start with http:// or https://")
                continue
            
            logger.info(f"Target URL: {url}")
            return url
            
        except KeyboardInterrupt:
            print("\n[!] Cancelled by user")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Invalid input: {e}")
            continue


def get_ignore_links() -> List[str]:
    """Prompt for URLs to ignore."""
    try:
        ignore_choice: str = input("Ignore certain links? (y/n): ").lower().strip()
        
        if ignore_choice != 'y':
            return []
        
        ignore_input: str = input(
            "Enter URLs to ignore (comma-separated, e.g., /logout, /profile): "
        ).strip()
        
        if not ignore_input:
            return []
        
        ignore_links: List[str] = [
            link.strip() for link in ignore_input.split(",") if link.strip()
        ]
        
        logger.info(f"Ignoring {len(ignore_links)} URL patterns")
        return ignore_links
        
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        return []


def get_authentication_info() -> Optional[Dict[str, str]]:
    """Prompt for authentication credentials if needed."""
    try:
        login_required: str = input("Does target require login? (y/n): ").lower().strip()
        
        if login_required != 'y':
            return None
        
        login_url: str = input("Enter login URL: ").strip()
        username: str = input("Enter username: ").strip()
        password: str = input("Enter password: ").strip()
        
        if not all([login_url, username, password]):
            print("[!] Warning: Incomplete credentials")
        
        logger.info(f"Authentication configured for {login_url}")
        
        return {
            "login_url": login_url,
            "username": username,
            "password": password
        }
        
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error: {e}")
        return None


def perform_login(scanner: Scanner, auth_info: Dict[str, str]) -> bool:
    """
    Perform login to target site.
    
    Args:
        scanner: Scanner instance
        auth_info: Authentication credentials
        
    Returns:
        True if successful
    """
    try:
        print("[*] Authenticating...")
        logger.info(f"Login attempt to {auth_info['login_url']}")
        
        login_data: Dict[str, str] = {
            "username": auth_info["username"],
            "password": auth_info["password"],
            "Login": "submit"
        }
        
        response = scanner.session.post(
            auth_info["login_url"],
            data=login_data,
            timeout=10
        )
        
        if response.status_code == 200:
            print("[+] Authentication successful!")
            logger.info("Login successful")
            return True
        else:
            print(f"[!] Authentication may have failed (Status: {response.status_code})")
            logger.warning(f"Login returned {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[!] Authentication failed: {e}")
        logger.error(f"Auth error: {e}")
        return False


def print_summary(scan_result: ScanResult) -> None:
    """
    Print detailed scan summary.
    
    Args:
        scan_result: ScanResult object with findings
    """
    severity_dist = scan_result.get_severity_distribution()
    type_dist = scan_result.count_by_type()
    
    print("\n" + "="*70)
    print(" "*15 + "SCAN SUMMARY")
    print("="*70)
    print(f"Target: {scan_result.target_url}")
    print(f"Endpoints Discovered: {scan_result.endpoints_discovered}")
    print(f"Endpoints Scanned: {scan_result.endpoints_scanned}")
    print(f"Scan Duration: {scan_result.scan_duration:.2f}s")
    
    print("\n" + "-"*70)
    print("VULNERABILITY SUMMARY")
    print("-"*70)
    
    # Color codes for severity (if terminal supports it)
    severity_colors = {
        Severity.CRITICAL: "[!!!]",
        Severity.HIGH: "[!!]",
        Severity.MEDIUM: "[*]",
        Severity.LOW: "[+]",
        Severity.INFO: "[i]",
    }
    
    for severity in Severity.LEVELS:
        count = severity_dist.get(severity, 0)
        if count > 0:
            marker = severity_colors.get(severity, "[*]")
            print(f"{marker} {severity.upper()}: {count}")
    
    print(f"\n{'[+]'} TOTAL: {len(scan_result.vulnerabilities)}")
    
    if type_dist:
        print("\n" + "-"*70)
        print("BREAKDOWN BY VULNERABILITY TYPE")
        print("-"*70)
        for vuln_type, count in sorted(type_dist.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {vuln_type}: {count}")
    
    # List critical/high vulnerabilities
    if severity_dist.get(Severity.CRITICAL, 0) > 0 or severity_dist.get(Severity.HIGH, 0) > 0:
        print("\n" + "-"*70)
        print("CRITICAL/HIGH VULNERABILITIES")
        print("-"*70)
        
        critical = scan_result.get_critical_vulnerabilities()
        high = scan_result.get_high_vulnerabilities()
        
        for i, vuln in enumerate(critical + high, 1):
            if i > 10:  # Limit to top 10
                print(f"... and {len(critical) + len(high) - 10} more")
                break
            print(f"  {i}. [{vuln.severity.upper()}] {vuln.vuln_type}")
            print(f"     URL: {vuln.url}")
            if vuln.parameter:
                print(f"     Parameter: {vuln.parameter}")
            print(f"     Impact: {vuln.impact or vuln.get_impact()}")
            print(f"     Fix: {vuln.remediation or vuln.get_remediation()}")
            print()
    
    print("="*70 + "\n")


def _default_report_path(target_url: str, report_format: str) -> str:
    """Build a safe default report path for the selected format."""
    safe_target = re.sub(r"[^A-Za-z0-9]+", "_", target_url).strip("_").lower()
    safe_target = safe_target[:60] or "scan"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(Path("reports") / f"cyberscope_{safe_target}_{timestamp}.{report_format}")


def export_report(scan_result: ScanResult, report_format: str, output_file: str) -> str:
    """
    Export scan results in the selected report format.

    Args:
        scan_result: Completed scan result
        report_format: json, csv, or html
        output_file: Destination file path

    Returns:
        Path to saved report
    """
    reporter_map = {
        "json": JSONReporter,
        "csv": CSVReporter,
        "html": HTMLReporter,
    }

    reporter_cls = reporter_map.get(report_format)
    if not reporter_cls:
        raise ValueError(f"Unsupported report format: {report_format}")

    reporter = reporter_cls(scan_result, output_file)
    return reporter.save()


def prompt_report_export(scan_result: ScanResult) -> None:
    """Ask the user whether to export a report and save it."""
    try:
        export_choice = input("Export report? (y/n): ").lower().strip()
        if export_choice != "y":
            print("[*] Report export skipped")
            return

        valid_formats = {"json", "csv", "html"}
        while True:
            report_format = input("Choose report format (json/csv/html): ").lower().strip()
            if report_format in valid_formats:
                break
            print("[!] Please choose json, csv, or html")

        default_path = _default_report_path(scan_result.target_url, report_format)
        output_file = input(f"Output file [{default_path}]: ").strip() or default_path

        saved_path = export_report(scan_result, report_format, output_file)
        print(f"[+] {report_format.upper()} report exported: {saved_path}")
        logger.info("Report exported to %s", saved_path)

    except KeyboardInterrupt:
        print("\n[!] Report export cancelled")
    except Exception as e:
        print(f"[!] Report export failed: {e}")
        logger.error("Report export failed: %s", e, exc_info=True)


def main() -> None:
    """Main entry point."""
    try:
        # Display banner
        display_banner()
        
        # Get target URL
        target_url: str = get_target_url()
        
        # Get ignore list
        links_to_ignore: List[str] = get_ignore_links()
        
        # Get authentication info
        auth_info: Optional[Dict[str, str]] = get_authentication_info()
        
        # Initialize scanner
        logger.info("Initializing scanner...")
        print("\n[*] Initializing scanner...")
        
        scanner: Scanner = Scanner(target_url, links_to_ignore)
        
        # Perform login if needed
        if auth_info:
            success: bool = perform_login(scanner, auth_info)
            if not success:
                print("[!] Continuing without authentication...")
                logger.warning("Continuing without successful auth")
        
        # Start crawling
        print("[*] Starting web crawl to discover endpoints...")
        logger.info("Crawl phase starting")
        scanner.crawl()
        
        if not scanner.target_links:
            print("[!] No extra endpoints discovered. Scanning the target page only...")
            logger.warning("No additional endpoints discovered; scanning target URL")
            scanner.target_links.append(scanner.target_url)
        
        # Run vulnerability scan
        print(f"\n[*] Discovered {len(scanner.target_links)} endpoints")
        print("[*] Starting vulnerability assessment...")
        logger.info("Scan phase starting")
        
        scan_result: ScanResult = scanner.run_scanner()
        
        # Print summary
        print_summary(scan_result)
        
        # Export results
        prompt_report_export(scan_result)
        logger.info("Scan completed successfully")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        logger.warning("Interrupted by user (Ctrl+C)")
        sys.exit(0)
    except ValueError as e:
        print(f"[!] Input error: {e}")
        logger.error(f"Input validation error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
