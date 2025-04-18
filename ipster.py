import ipinfo
import os
import requests
from dotenv import load_dotenv
import json
import logging
from typing import Dict, Optional
import socket
import re
from pyfiglet import Figlet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

access_token = os.getenv("IPINFO_TOKEN")
if access_token is None:
    raise ValueError("IPINFO_TOKEN is missing. Check your .env file.")


class IPInfo:
    def __init__(self, access_token: str):
        """Initialize IPInfo handler with the API access token."""
        self.handler = ipinfo.getHandler(access_token)
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate if the given string is a valid IP address."""
        # Regular expressions for IPv4 and IPv6
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'

        if re.match(ipv4_pattern, ip):
            # Validate IPv4 address
            try:
                socket.inet_pton(socket.AF_INET, ip)
                return True
            except socket.error:
                return False
        elif re.match(ipv6_pattern, ip):
            # Validate IPv6 address
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
        return False

    def get_ip_info(self, ip: str) -> Optional[Dict]:
        """Get information about an IP address.

        Args:
            ip (str): The IP address to look up

        Returns:
            Optional[Dict]: Dictionary containing IP information or None
        """
        if not self.is_valid_ip(ip):
            self.logger.error(f"Invalid IP address format: {ip}")
            return None

        try:
            details = self.handler.getDetails(ip)
            self.logger.info(
                f"Successfully retrieved information for IP: {ip}")
            return details.all
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching IP info: {e}")
            return None
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")
            return None

    def write_ip_info_to_json(self, ip: str, filename: str) -> bool:
        """Write IP information to a JSON file."""
        details = self.get_ip_info(ip)
        if not details:
            return False

        try:
            with open(filename, "w") as file:
                json.dump(details, file, indent=4)
            self.logger.info(
                f"Successfully wrote IP info to JSON file: {filename}")
            return True
        except IOError as e:
            self.logger.error(f"Error writing to JSON file {filename}: {e}")
            return False

    def batch_process(self, ips: list[str], output_dir: str) -> Dict[str, bool]:
        """Process multiple IP addresses and save results to individual files."""
        os.makedirs(output_dir, exist_ok=True)
        results = {}

        for ip in ips:
            if not self.is_valid_ip(ip):
                self.logger.warning(f"Skipping invalid IP: {ip}")
                results[ip] = False
                continue

            filename = os.path.join(output_dir, f"{ip.replace(':', '_')}.json")
            results[ip] = self.write_ip_info_to_json(ip, filename)

        return results

    def format_output(self, ip_info: Dict) -> str:
        """Format IP information into a readable string.

        Args:
            ip_info (Dict): Dictionary containing IP information
            location_info (Optional[Dict[str, str]]): Dictionary containing location information

        Returns:
            str: Formatted string containing IP information
        """
        output = []
        output.append("=" * 50)
        output.append("IP Information Summary")
        output.append("=" * 50)

        # Basic IP info
        output.append(f"IP Address: {ip_info.get('ip', 'Unknown')}")
        output.append(f"Hostname: {ip_info.get('hostname', 'Unknown')}")
        output.append(f"Organization: {ip_info.get('org', 'Unknown')}")

        # Location information
        output.append("\nLocation Details:")
        output.append(f"City: {ip_info.get('city', 'Unknown')}")
        output.append(f"Region: {ip_info.get('region', 'Unknown')}")
        output.append(f"Country: {ip_info.get('country', 'Unknown')}")
        output.append(f"Location: {ip_info.get('loc', 'Unknown')}")
        output.append(f"Timezone: {ip_info.get('timezone', 'Unknown')}")

        # Additional details if available
        if ip_info.get('postal'):
            output.append(f"Postal Code: {ip_info['postal']}")
        if ip_info.get('asn'):
            output.append(f"ASN: {ip_info['asn']}")

        output.append("=" * 50)
        return "\n".join(output)


if __name__ == "__main__":
    # Create ASCII art title
    fig = Figlet(font='slant')
    print(fig.renderText('ipster v1.0'))
    print("=" * 55)
    print("Created by @nicoleman0")

    ipinfo_client = IPInfo(access_token)
    print("Enter an IP address to get detailed information (or 'quit' to exit)")

    while True:
        ip = input("\nip > ")
        if ip.lower() == 'quit' or ip.lower() == 'exit' or ip.lower() == 'q':
            print("Exiting...")
            break

        if not ipinfo_client.is_valid_ip(ip):
            print("Invalid IP address format.")
            continue

        result = ipinfo_client.get_ip_info(ip)
        if result:
            formatted_output = ipinfo_client.format_output(result)
            print(formatted_output)

            # Ask if user wants to save to JSON
            save_option = input(
                "\nWould you like to save this information to a JSON file? (y/n): ")
            if save_option.lower() == 'y':
                filename = input("Enter filename (e.g., ip_info.json): ")
                if not filename.endswith('.json'):
                    filename += '.json'
                if ipinfo_client.write_ip_info_to_json(ip, filename):
                    print(f"✅ Successfully saved to {filename}")
                else:
                    print("Failed to save JSON file")
        else:
            print("Failed to retrieve IP information.")
