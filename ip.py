import ipinfo
import os
import requests
from dotenv import load_dotenv
import json

load_dotenv()

access_token = os.getenv("IPINFO_TOKEN")
if access_token is None:
    raise ValueError("IPINFO_TOKEN is not set in the environment variables.")


class IPInfo:
    def __init__(self, access_token: str):
        self.handler = ipinfo.getHandler(access_token)

    def get_ip_info(self, ip: str):
        try:
            details = self.handler.getDetails(ip)
            return details.all
        except requests.exceptions.RequestException as e:
            print(f"Error fetching IP info: {e}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None

    def write_ip_info_to_file(self, ip: str, filename: str):
        details = self.get_ip_info(ip)
        if details:
            with open(filename, "w") as file:
                for key, value in details.items():
                    file.write(f"{key}: {value}\n")

    def write_ip_info_to_json(self, ip: str, filename: str):
        details = self.get_ip_info(ip)
        if details:
            with open(filename, "w") as file:
                json.dump(details, file, indent=4)


if __name__ == "__main__":
    ipinfo = IPInfo(access_token)
    ip = input("Enter the IP address: ")
    r = ipinfo.get_ip_info(ip)
    print(r)
