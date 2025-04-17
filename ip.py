import ipinfo
import os
import requests
from dotenv import load_dotenv
import json
import logging
from typing import Dict, Optional
import socket
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

access_token = os.getenv("IPINFO_TOKEN")
if access_token is None:
    raise ValueError("IPINFO_TOKEN is not set in the environment variables.")


class IPInfo:
    def __init__(self, access_token: str):
        """Initialize IPInfo handler with the API access token.

        Args:
            access_token (str): IPInfo API access token
        """
        self.handler = ipinfo.getHandler(access_token)
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Validate if the given string is a valid IP address.

        Args:
            ip (str): IP address to validate

        Returns:
            bool: True if valid IP address, False otherwise
        """
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # IPv6 pattern
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
            Optional[Dict]: Dictionary containing IP information or None if error occurs
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

    def write_ip_info_to_file(self, ip: str, filename: str) -> bool:
        """Write IP information to a text file.

        Args:
            ip (str): The IP address to look up
            filename (str): The file to write the information to

        Returns:
            bool: True if successful, False otherwise
        """
        details = self.get_ip_info(ip)
        if not details:
            return False

        try:
            with open(filename, "w") as file:
                for key, value in details.items():
                    file.write(f"{key}: {value}\n")
            self.logger.info(f"Successfully wrote IP info to file: {filename}")
            return True
        except IOError as e:
            self.logger.error(f"Error writing to file {filename}: {e}")
            return False

    def write_ip_info_to_json(self, ip: str, filename: str) -> bool:
        """Write IP information to a JSON file.

        Args:
            ip (str): The IP address to look up
            filename (str): The JSON file to write the information to

        Returns:
            bool: True if successful, False otherwise
        """
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

    def get_location(self, ip: str) -> Optional[Dict[str, str]]:
        """Get location information for an IP address.

        Args:
            ip (str): The IP address to look up

        Returns:
            Optional[Dict[str, str]]: Dictionary containing location information or None if error occurs
        """
        details = self.get_ip_info(ip)
        if not details:
            return None

        return {
            'city': details.get('city', 'Unknown'),
            'region': details.get('region', 'Unknown'),
            'country': details.get('country', 'Unknown'),
            'loc': details.get('loc', 'Unknown'),
            'timezone': details.get('timezone', 'Unknown')
        }

    def batch_process(self, ips: list[str], output_dir: str) -> Dict[str, bool]:
        """Process multiple IP addresses and save results to individual files.

        Args:
            ips (list[str]): List of IP addresses to process
            output_dir (str): Directory to save the output files

        Returns:
            Dict[str, bool]: Dictionary mapping IP addresses to processing success status
        """
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


if __name__ == "__main__":
    ipinfo_client = IPInfo(access_token)

    while True:
        ip = input("Enter the IP address (or 'quit' to exit): ")
        if ip.lower() == 'quit':
            break

        if not ipinfo_client.is_valid_ip(ip):
            print("Invalid IP address format.")
            continue

        result = ipinfo_client.get_ip_info(ip)
        if result:
            print("\nIP Information:")
            print(json.dumps(result, indent=2))

            # Also show location details
            location = ipinfo_client.get_location(ip)
            if location:
                print("\nLocation Details:")
                print(json.dumps(location, indent=2))
        else:
            print("Failed to retrieve IP information.")
