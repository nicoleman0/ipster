# IPInfoScan

A Python tool for retrieving and analyzing IP address information using the ipinfo.io API.

## Features

- Validate IPv4 and IPv6 addresses
- Retrieve detailed information about IP addresses including location, organization, and timezone
- Save IP information to JSON files
- Batch process multiple IP addresses

## Prerequisites

- Python 3.x
- ipinfo.io API token

## Installation

1. Clone the repository

1. Install required packages:

```bash
pip install ipinfo python-dotenv pyfiglet requests
```

1. Create a `.env` file in the project root and add your IPInfo API token:

```plaintext
IPINFO_TOKEN=your_token_here
```

## Usage

Run the script:

```bash
python ip.py
```

The interactive CLI will prompt you to enter IP addresses and provide options to view and save the information.

## License

See the [LICENSE](LICENSE) file for details.