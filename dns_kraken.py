import dns.resolver
import dns.zone
import dns.query
import dns.reversename
import argparse
import sys
from typing import List

def check_zone_transfer(domain: str):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_address = str(dns.resolver.resolve(ns.target, 'A')[0])
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_address, domain))
                print(f"Zone transfer successful for {ns.target} ({ns_address})")
                for name, node in zone.nodes.items():
                    print(zone[name].to_text(name))
            except Exception as e:
                print(f"Zone transfer failed for {ns.target} ({ns_address}): {e}")
    except Exception as e:
        print(f"Failed to resolve NS records for {domain}: {e}")

def enumerate_records(domain: str):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'SPF', 'TXT']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                print(f"{record_type} record for {domain}: {rdata}")
        except dns.resolver.NoAnswer:
            print(f"No {record_type} record found for {domain}")
        except Exception as e:
            print(f"Failed to query {record_type} records for {domain}: {e}")

def enumerate_srv_records(domain: str):
    srv_records = [
        '_sip._tcp', '_sip._udp', '_xmpp-server._tcp', '_xmpp-client._tcp',
        '_http._tcp', '_ldap._tcp', '_ftp._tcp'
    ]
    for srv in srv_records:
        try:
            answers = dns.resolver.resolve(f"{srv}.{domain}", 'SRV')
            for rdata in answers:
                print(f"SRV record {srv}.{domain}: {rdata}")
        except dns.resolver.NoAnswer:
            print(f"No SRV record found for {srv}.{domain}")
        except Exception as e:
            print(f"Failed to query SRV records for {srv}.{domain}: {e}")

def check_wildcard(domain: str):
    try:
        answers = dns.resolver.resolve(f"*.{domain}", 'A')
        for rdata in answers:
            print(f"Wildcard A record for {domain}: {rdata}")
    except dns.resolver.NoAnswer:
        print(f"No wildcard A record found for {domain}")
    except Exception as e:
        print(f"Failed to query wildcard A records for {domain}: {e}")

def brute_force_subdomains(domain: str, wordlist: List[str]):
    for word in wordlist:
        subdomain = f"{word.strip()}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            for rdata in answers:
                print(f"A record for {subdomain}: {rdata}")
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            print(f"Failed to query A records for {subdomain}: {e}")

def ptr_lookup(cidr: str):
    try:
        network = dns.reversename.from_address(cidr)
        answers = dns.resolver.resolve(network, 'PTR')
        for rdata in answers:
            print(f"PTR record for {cidr}: {rdata}")
    except Exception as e:
        print(f"Failed to query PTR records for {cidr}: {e}")

def check_cached(domain: str):
    record_types = ['A', 'AAAA', 'CNAME']
    for record_type in record_types:
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.use_edns(0, dns.flags.DO, 4096)
            resolver.nameservers = ['8.8.8.8']  # change to any server
            answers = resolver.resolve(domain, record_type)
            for rdata in answers:
                print(f"Cached {record_type} record for {domain}: {rdata}")
        except Exception as e:
            print(f"Failed to query cached {record_type} records for {domain}: {e}")

def check_from_file(file_path: str):
    try:
        with open(file_path, 'r') as file:
            domains = file.readlines()
            for domain in domains:
                domain = domain.strip()
                enumerate_records(domain)
    except Exception as e:
        print(f"Failed to read file {file_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description='DNS Kraken - A DNS Enumeration Tool')
    subparsers = parser.add_subparsers(dest='command')

    parser_zonetransfer = subparsers.add_parser('zonetransfer', help='Check zone transfer')
    parser_zonetransfer.add_argument('domain', type=str, help='Domain to check')

    parser_enumerate = subparsers.add_parser('enumerate', help='Enumerate DNS records')
    parser_enumerate.add_argument('domain', type=str, help='Domain to enumerate')

    parser_srv = subparsers.add_parser('srv', help='Enumerate SRV records')
    parser_srv.add_argument('domain', type=str, help='Domain to enumerate SRV records')

    parser_wildcard = subparsers.add_parser('wildcard', help='Check for wildcard resolution')
    parser_wildcard.add_argument('domain', type=str, help='Domain to check wildcard')

    parser_bruteforce = subparsers.add_parser('bruteforce', help='Brute force subdomains')
    parser_bruteforce.add_argument('domain', type=str, help='Domain to brute force')
    parser_bruteforce.add_argument('-w', '--wordlist', type=str, required=True, help='Wordlist for brute forcing')

    parser_ptr = subparsers.add_parser('ptr', help='Perform PTR lookup')
    parser_ptr.add_argument('cidr', type=str, help='CIDR or IP range for PTR lookup')

    parser_cached = subparsers.add_parser('cached', help='Check cached DNS records')
    parser_cached.add_argument('domain', type=str, help='Domain to check cached records')

    parser_file = subparsers.add_parser('file', help='Check records from file')
    parser_file.add_argument('file_path', type=str, help='File path with list of domains')

    args = parser.parse_args()

    if args.command == 'zonetransfer':
        check_zone_transfer(args.domain)
    elif args.command == 'enumerate':
        enumerate_records(args.domain)
    elif args.command == 'srv':
        enumerate_srv_records(args.domain)
    elif args.command == 'wildcard':
        check_wildcard(args.domain)
    elif args.command == 'bruteforce':
        try:
            with open(args.wordlist, 'r') as file:
                wordlist = file.readlines()
                brute_force_subdomains(args.domain, wordlist)
        except Exception as e:
            print(f"Failed to read wordlist {args.wordlist}: {e}")
    elif args.command == 'ptr':
        ptr_lookup(args.cidr)
    elif args.command == 'cached':
        check_cached(args.domain)
    elif args.command == 'file':
        check_from_file(args.file_path)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
