import re
import signal
import subprocess
import sys
from argparse import ArgumentParser
from ipwhois import IPWhois
from prettytable import PrettyTable

IP_PATTERN = r'(?:\d{1,3}\.){3}\d{1,3}'


def handle_signal(*args):
    sys.exit(0)


def get_ip_details(ip_addr):
    ip_data = {'ip': ip_addr}
    try:
        whois_result = IPWhois(ip_addr).lookup_rdap()
    except Exception:
        whois_result = {}

    ip_data.update({
        'asn': whois_result.get('asn', '-'),
        'country': whois_result.get('asn_country_code', '-'),
        'isp': whois_result.get('network', {}).get('name', '-')
    })
    return ip_data


def run_traceroute(target_host):
    return subprocess.run(
        f'tracert -d -w 50 {target_host}',
        capture_output=True,
        text=True
    ).stdout


def create_parser():
    parser = ArgumentParser()
    parser.add_argument('host', help='Target hostname or IP address')
    return parser


def main():
    signal.signal(signal.SIGINT, handle_signal)
    cli_args = create_parser().parse_args()

    trace_output = run_traceroute(cli_args.host)
    found_ips = re.findall(IP_PATTERN, trace_output)[1:]

    results = []
    for ip_addr in found_ips:
        results.append(get_ip_details(ip_addr))

    report_table = PrettyTable(['Hop', 'IP Address', 'ASN', 'Country', 'ISP'])
    for idx, hop_data in enumerate(results, 1):
        report_table.add_row([
            idx,
            hop_data['ip'],
            hop_data['asn'],
            hop_data['country'],
            hop_data['isp']
        ])

    print(f'\nTracing route to {cli_args.host}:\n')
    print(report_table)
    print('\nTrace complete.')


if __name__ == '__main__':
    main()