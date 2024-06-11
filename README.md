# DNS Kraken

DNS Kraken is a CLI tool designed to perform various DNS enumeration tasks, including checking for zone transfers, enumerating DNS records, performing SRV record enumeration, expanding TLDs, checking for wildcard resolution, brute forcing subdomains, performing PTR lookups, and checking DNS server cached records.

## Features

- Checks all NS Records for Zone Transfers.
- Enumerates general DNS Records for a given domain (MX, SOA, NS, A, AAAA, SPF, and TXT).
- Performs common SRV Record enumeration.
- Top Level Domain (TLD) expansion.
- Checks for Wildcard resolution.
- Brute forces subdomains and host A and AAAA records given a domain and a wordlist.
- Performs PTR record lookup for a given IP Range or CIDR.
- Checks a DNS server’s cached records for A, AAAA, and CNAME.
- Records provided a list of host records in a text file to check.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/uniias/DNS_Kraken.git
    cd DNS_Kraken
    ```

2. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```
# Contributing
Feel free to submit issues or pull requests to enhance the tool.

# License
This project is licensed under the MIT License - see the LICENSE file for details.

# Disclaimer
This tool is designed for educational and authorized use only. It is not intended for malicious activities or unauthorized access.
