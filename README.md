# ipster

ipster - is a Python tool for retrieving and analyzing basic IP address information using the ipinfo.io API.

It's like a fast and simple version of whois.

## Features

- Validate IPv4 and IPv6 addresses
- Retrieve detailed information about IP addresses including location, organization, and timezone
- Save IP information to JSON files
- Batch process multiple IP addresses

## Prerequisites

- Python 3.x
- [ipinfo.io API token](https://ipinfo.io/developers) (free)

## Installation

1. Clone or download the repository

2. Install the required packages:

```bash
pip install ipinfo python-dotenv pyfiglet requests
```

You *must* create a `.env` file in the **project root**, then add your IPInfo API token:

```plaintext
IPINFO_TOKEN=your_token_here
```

## Usage

Run the script with:

```bash
python3 ipster.py
```

The scanner will prompt you to enter IP addresses you wish to scan and provide options to view and save the information afterwards.

## License

See the [LICENSE](LICENSE) file.
