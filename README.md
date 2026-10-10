# CYB-333_Team_Project
CYB333 Security Automation Project

Automated Network Port and Vulnerability Assessment Tool

This program uses Nmap and Python to scan an authorized
IP address or hostname. It checks for open ports and services
that may need additional security review and creates a report.

This program should only be used on systems that you own
or have permission to scan.
"""

import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import socket
from datetime import datetime
import os


# ----------------------------------------------------------
# Security rules
# ----------------------------------------------------------
# These are some common services that I want the program
# to flag when they are found during the Nmap scan.

SECURITY_RULES = {

    21: {
        "service": "FTP",
        "severity": "HIGH",
        "risk": "FTP may send usernames, passwords, and data without encryption.",
        "recommendation": "Verify FTP is needed and consider using SFTP instead."
    },

    23: {
        "service": "Telnet",
        "severity": "CRITICAL",
        "risk": "Telnet sends network communication without encryption.",
        "recommendation": "Disable Telnet if possible and use SSH instead."
    },

    445: {
        "service": "SMB",
        "severity": "HIGH",
        "risk": "An exposed SMB service can increase the attack surface of a system.",
        "recommendation": "Verify SMB is required and restrict access to trusted systems."
    },

    3389: {
        "service": "RDP",
        "severity": "HIGH",
        "risk": "Remote Desktop provides remote access to the computer.",
        "recommendation": "Restrict RDP access and use strong authentication."
    },

    3306: {
        "service": "MySQL",
        "severity": "MEDIUM",
        "risk": "A database service was found and may be accessible over the network.",
        "recommendation": "Make sure MySQL is only accessible by authorized systems."
    },

    1433: {
        "service": "Microsoft SQL Server",
        "severity": "MEDIUM",
        "risk": "Microsoft SQL Server was detected on the network.",
        "recommendation": "Restrict database access to authorized systems."
    },

    5432: {
        "service": "PostgreSQL",
        "severity": "MEDIUM",
        "risk": "PostgreSQL was detected and may be accessible over the network.",
        "recommendation": "Limit PostgreSQL access to authorized systems."
    },

    27017: {
        "service": "MongoDB",
        "severity": "MEDIUM",
        "risk": "MongoDB was detected and may be accessible over the network.",
        "recommendation": "Verify authentication and restrict unnecessary access."
    }
}


# ----------------------------------------------------------
# Check the target
# ----------------------------------------------------------

def validate_target(target):

    # First check if the user entered an IP address.
    try:
        ipaddress.ip_address(target)
        return True

    except ValueError:
        pass

    # If it is not an IP address, try resolving it as a hostname.
    try:
        socket.gethostbyname(target)
        return True

    except socket.gaierror:
        return False


# ----------------------------------------------------------
# Run Nmap
# ----------------------------------------------------------

def run_scan(target):

    # Create a timestamp so each scan has a different filename.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_file = "nmap_" + timestamp + ".xml"

    # -sV tells Nmap to try to identify the service/version.
    # -T3 uses normal/moderate scan timing.
    # -oX saves the results as XML so Python can read them.

    command = [
        "nmap",
        "-sV",
        "-T3",
        "-oX",
        xml_file,
        target
    ]

    print("\nStarting Nmap scan...")
    print("Target:", target)
    print("Please wait for the scan to finish.\n")

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:

            print("Nmap returned an error.")

            if result.stderr:
                print(result.stderr)

            return None

        print("Nmap scan completed.")

        return xml_file

    except FileNotFoundError:

        print("\nERROR: Nmap could not be found.")
        print("Make sure Nmap is installed and added to PATH.")

        return None


# ----------------------------------------------------------
# Read the Nmap XML file
# ----------------------------------------------------------

def read_scan_results(xml_file):

    scan_results = []

    try:

        tree = ET.parse(xml_file)
        root = tree.getroot()

        # Go through each host that Nmap found.
        for host in root.findall("host"):

            address = host.find("address")

            if address is not None:
                host_ip = address.get("addr")
            else:
                host_ip = "Unknown"

            ports = host.find("ports")

            if ports is None:
                continue

            # Look at each port found by Nmap.
            for port in ports.findall("port"):

                port_number = int(port.get("portid"))
                protocol = port.get("protocol")

                state = port.find("state")

                # Only save ports that are open.
                if state is None:
                    continue

                if state.get("state") != "open":
                    continue

                service = port.find("service")

                service_name = "unknown"
                product = ""
                version = ""

                if service is not None:

                    service_name = service.get("name", "unknown")
                    product = service.get("product", "")
                    version = service.get("version", "")

                # Save the information in a dictionary.
                scan_results.append({
                    "host": host_ip,
                    "port": port_number,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version
                })

        return scan_results

    except ET.ParseError:

        print("There was a problem reading the Nmap XML file.")
        return []

    except FileNotFoundError:

        print("The Nmap XML file could not be found.")
        return []


# ----------------------------------------------------------
# Check for possible security concerns
# ----------------------------------------------------------

def check_security_risks(scan_results):

    findings = []

    # Go through all of the open ports found by Nmap.
    for result in scan_results:

        port = result["port"]

        # Check if the port is one that we want to flag.
        if port in SECURITY_RULES:

            rule = SECURITY_RULES[port]

            finding = {
                "host": result["host"],
                "port": port,
                "protocol": result["protocol"],
                "detected_service": result["service"],
                "product": result["product"],
                "version": result["version"],
                "service": rule["service"],
                "severity": rule["severity"],
                "risk": rule["risk"],
                "recommendation": rule["recommendation"]
            }

            findings.append(finding)

    return findings


# ----------------------------------------------------------
# Display results on the screen
# ----------------------------------------------------------

def display_results(scan_results, findings):

    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)

    if len(scan_results) == 0:

        print("No open ports were found.")

    else:

        for result in scan_results:

            print(
                str(result["port"]) + "/" +
                result["protocol"] +
                "  " +
                result["service"]
            )

    print("\n" + "=" * 60)
    print("SECURITY FINDINGS")
    print("=" * 60)

    if len(findings) == 0:

        print("No ports matched the security rules.")

    else:

        for finding in findings:

            print("\nService:", finding["service"])
            print("Port:", finding["port"])
            print("Severity:", finding["severity"])
            print("Risk:", finding["risk"])


# ----------------------------------------------------------
# Create the report
# ----------------------------------------------------------

def create_report(target, scan_results, findings):

    # Create the reports folder if it does not already exist.
    if not os.path.exists("reports"):
        os.mkdir("reports")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_name = os.path.join(
        "reports",
        "assessment_" + timestamp + ".txt"
    )

    # Count findings by severity.
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:

        if finding["severity"] == "CRITICAL":
            critical_count += 1

        elif finding["severity"] == "HIGH":
            high_count += 1

        elif finding["severity"] == "MEDIUM":
            medium_count += 1

        elif finding["severity"] == "LOW":
            low_count += 1

    # Write the results to the text file.
    with open(report_name, "w", encoding="utf-8") as report:

        report.write("=" * 60 + "\n")
        report.write("NETWORK PORT AND VULNERABILITY ASSESSMENT\n")
        report.write("=" * 60 + "\n")

        report.write("\nTarget: " + target + "\n")

        report.write(
            "Scan Date: " +
            datetime.now().strftime("%Y-%m-%d %H:%M:%S") +
            "\n"
        )

        # Open ports section
        report.write("\nOPEN PORTS\n")
        report.write("-" * 60 + "\n")

        if len(scan_results) == 0:

            report.write("No open ports were found.\n")

        else:

            for result in scan_results:

                report.write(
                    str(result["port"]) +
                    "/" +
                    result["protocol"] +
                    "  " +
                    result["service"]
                )

                if result["product"]:
                    report.write("  " + result["product"])

                if result["version"]:
                    report.write(" " + result["version"])

                report.write("\n")

        # Security findings section
        report.write("\nSECURITY FINDINGS\n")
        report.write("-" * 60 + "\n")

        if len(findings) == 0:

            report.write(
                "No services matched the predefined security rules.\n"
            )

        else:

            finding_number = 1

            for finding in findings:

                report.write(
                    "\nFinding #" +
                    str(finding_number) +
                    "\n"
                )

                report.write(
                    "Service: " +
                    finding["service"] +
                    "\n"
                )

                report.write(
                    "Port: " +
                    str(finding["port"]) +
                    "/" +
                    finding["protocol"] +
                    "\n"
                )

                report.write(
                    "Severity: " +
                    finding["severity"] +
                    "\n"
                )

                if finding["product"]:

                    report.write(
                        "Product: " +
                        finding["product"] +
                        "\n"
                    )

                if finding["version"]:

                    report.write(
                        "Version: " +
                        finding["version"] +
                        "\n"
                    )

                report.write(
                    "Security Concern: " +
                    finding["risk"] +
                    "\n"
                )

                report.write(
                    "Recommendation: " +
                    finding["recommendation"] +
                    "\n"
                )

                finding_number += 1

        # Summary section
        report.write("\n" + "=" * 60 + "\n")
        report.write("SUMMARY\n")
        report.write("=" * 60 + "\n")

        report.write(
            "Critical Findings: " +
            str(critical_count) +
            "\n"
        )

        report.write(
            "High Findings: " +
            str(high_count) +
            "\n"
        )

        report.write(
            "Medium Findings: " +
            str(medium_count) +
            "\n"
        )

        report.write(
            "Low Findings: " +
            str(low_count) +
            "\n"
        )

        report.write(
            "Total Findings: " +
            str(len(findings)) +
            "\n"
        )

        report.write("\nNOTE:\n")

        report.write(
            "An open port does not automatically mean that a "
            "vulnerability exists. These findings identify services "
            "that may require additional security review.\n"
        )

    return report_name


# ----------------------------------------------------------
# Main program
# ----------------------------------------------------------

def main():

    print("=" * 60)
    print("AUTOMATED NETWORK PORT AND VULNERABILITY ASSESSMENT TOOL")
    print("=" * 60)

    print(
        "\nOnly use this program against systems that you own "
        "or have permission to scan."
    )

    # Ask the user what system they want to scan.
    target = input(
        "\nEnter an authorized IP address or hostname: "
    ).strip()

    # Make sure the target is valid.
    if not validate_target(target):

        print("\nThe IP address or hostname is not valid.")
        return

    # Ask the user to confirm authorization.
    authorization = input(
        "Do you have permission to scan this system? (yes/no): "
    ).strip().lower()

    if authorization != "yes" and authorization != "y":

        print("\nScan cancelled.")
        return

    # Run Nmap.
    xml_file = run_scan(target)

    if xml_file is None:
        return

    # Read the Nmap results.
    scan_results = read_scan_results(xml_file)

    print(
        "\nOpen ports found:",
        len(scan_results)
    )

    # Check the results against our security rules.
    findings = check_security_risks(scan_results)

    print(
        "Potential security concerns found:",
        len(findings)
    )

    # Show some of the results on screen.
    display_results(scan_results, findings)

    # Generate the final report.
    report_name = create_report(
        target,
        scan_results,
        findings
    )

    print("\n" + "=" * 60)
    print("Assessment complete.")
    print("Report saved to:", report_name)
    print("=" * 60)


# This starts the program.
if __name__ == "__main__":
    main()
