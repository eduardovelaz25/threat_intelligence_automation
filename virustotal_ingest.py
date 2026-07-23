import requests
import json
import ipaddress
import re
from urllib.parse import urlparse
import base64
import os
import sys
# from api_keys import virustotal_api_key
# Replace with your own VirusTotal API key
API_KEY = os.environ['VIRUSTOTAL_API_KEY']
test_key = "amNhbXBsZWtleTIwMjZzZWNyZXR0ZXN0aW5nc3RyaW5n"
BASE_URL = 'https://www.virustotal.com/api/v3/'

# Headers for VirusTotal API authentication
headers = {
    'x-apikey': API_KEY
}


# Function to retrieve the reputation for a URL
def get_url_reputation(url):
    #url_id = requests.utils.quote(url)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(BASE_URL + f'urls/{url_id}', headers=headers)

    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            print("Threat Intel Report for", url)
            attributes = data['data']['attributes']
            print(f"Reputation for URL {url}:")
            # print(f"    Total Scans: {attributes['last_analysis_stats']['total']}")
            print(f"    Malicious: {attributes['last_analysis_stats']['malicious']}")
            print(f"    Suspicious: {attributes['last_analysis_stats']['suspicious']}")
            print(f"    Undetected: {attributes['last_analysis_stats']['undetected']}")
        else:
            print(f"Error fetching URL reputation for {url}")
    else:
        print(f"Error fetching URL: {response.status_code}")


# Function to retrieve the reputation for an IP address
def get_ip_reputation(ip):
    response = requests.get(BASE_URL + f'ip_addresses/{ip}', headers=headers)

    if response.status_code == 200:
        data = response.json()
        # print(json.dumps(data, indent=2))
        attributes = data['data']['attributes']
        # print(attributes['last_analysis_results'])
        engine_results = attributes['last_analysis_results']
        engine_results_items = engine_results.items()
        # print(engine_results_items)
        # for key, pair in engine_results_items:
        #     print(f"Engine name: {key}")
        #     print(f"Method: {pair['method']}")
        #     print(f"Category: {pair['category']}")
        #     print(f"Result: {pair['result']}")
        #     print('\n\n')
        if 'data' in data:
            print("Threat Intel Report for", ip)
            # attributes = data['data']['attributes']
            print(f"Reputation for IP {ip}:")
            # print(f"    Total Scans: {attributes['last_analysis_stats']['total']}")
            print(f"    Malicious: {attributes['last_analysis_stats']['malicious']}")
            print(f"    Suspicious: {attributes['last_analysis_stats']['suspicious']}")
            print(f"    Undetected: {attributes['last_analysis_stats']['undetected']}")

        else:
            print(f"Error fetching IP reputation for {ip}")
    else:
        print(f"Error fetching IP: {response.status_code}")


# Function to retrieve the reputation for a domain
def get_domain_reputation(domain):
    response = requests.get(BASE_URL + f'domains/{domain}', headers=headers)

    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            print("Threat Intel Report for", domain)
            attributes = data['data']['attributes']
            print(f"Reputation for Domain {domain}:")
            # print(f"    Total Scans: {attributes['last_analysis_stats']['total']}")
            print(f"    Malicious: {attributes['last_analysis_stats']['malicious']}")
            print(f"    Suspicious: {attributes['last_analysis_stats']['suspicious']}")
            print(f"    Undetected: {attributes['last_analysis_stats']['undetected']}")
        else:
            print(f"Error fetching Domain reputation for {domain}")
    else:
        print(f"Error fetching Domain: {response.status_code}")

def get_hash_reputation(hash):
    response = requests.get(BASE_URL + f'files/{hash}', headers=headers)
    # print(response)
    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            # print(json.dumps(data, indent=2))
            print("Threat Intel Report for", hash)
            attributes = data['data']['attributes']
            print(f"    Reputation for hash:{attributes['reputation']}")
            # print(f"    Names for hash: {attributes['names']}")
            # if attributes['popular_threat_classification']['suggested_threat_label']:
            #     print(f"    Suggested Threat Label: {attributes['popular_threat_classification']['suggested_threat_label']}")
            # crowdsource_yara = attributes['crowdsourced_yara_results']
            # print(f"    Crowdsourced Yara Results:{json.dumps(crowdsource_yara, indent=2)}")
        else:
            print(f"Error fetching hash reputation for {domain}")
    else:
        print(f"Error fetching hash: {response.status_code}")
def get_attack_technique(attack_id):
    response = requests.get(BASE_URL + f'attack_techniques/{attack_id}', headers=headers)
    attack_technique_data = response.json()
    print(attack_technique_data)
    attack_attr = attack_technique_data['data']['attributes']
    #print(json.dumps(attack_technique_data, indent=2))
    print(f"Attack Technique ID: {attack_technique_data['data']['id']}")
    print(f"\nAttack Technique Name: {attack_attr['name']}")
    print(f"\nTechnique Summary:\n{attack_attr['description']}\n")
    operating_systems = attack_attr['info']['x_mitre_platforms']
    print(f"Systems that an adversary can be operating within:")
    for i in operating_systems:
        print("\t", i)
    print(f"\nFor more information please visit:{attack_technique_data['data']['links']['self']}")

def raw_attack_technique(attack_id):
    response = requests.get(BASE_URL + f'attack_techniques/{attack_id}', headers=headers)
    attack_technique_data = response.json()
    attack_attr = attack_technique_data['data']['attributes']
    id = f"Attack Technique ID: {attack_technique_data['data']['id']}\n"
    attack_name = f"Attack Technique Name: {attack_attr['name']}\n"
    attack_summary = f"Technique Summary:{attack_attr['description']}"
    brief = id + attack_name + attack_summary
    return brief

def get_ioc_type(ioc):
    """Return the IOC type: ip, url, domain, hash, or unknown."""

    # IP Address
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    # URL
    parsed = urlparse(ioc)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return "url"

    # File Hash (MD5/SHA1/SHA256)
    if re.fullmatch(r"[A-Fa-f0-9]{32}", ioc):
        return "md5"

    if re.fullmatch(r"[A-Fa-f0-9]{40}", ioc):
        return "sha1"

    if re.fullmatch(r"[A-Fa-f0-9]{64}", ioc):
        return "sha256"

    # Domain
    domain_regex = (
        r"^(?=.{1,253}$)"
        r"(?!-)(?:[A-Za-z0-9-]{1,63}\.)+"
        r"[A-Za-z]{2,63}$"
    )

    if re.fullmatch(domain_regex, ioc):
        return "domain"

    return "unknown"

def ioc_reputation_check(ioc):
    ioc_type = get_ioc_type(ioc)
    print("The IOC type for '"+ioc+"' is:",ioc_type)
    if ioc_type == "ip":
        return get_ip_reputation(ioc)

    elif ioc_type == "url":
        return get_url_reputation(ioc)

    elif ioc_type == "domain":
        return get_domain_reputation(ioc)

    elif ioc_type in ("md5", "sha1", "sha256"):
        return get_hash_reputation(ioc)

    else:
        raise ValueError(f"Unsupported IOC type: {ioc}")

# ioc_reputation_check("117.72.181.104")
# ioc_reputation_check("0rlxki7g.bordbett10.com")
# ioc_reputation_check("http://microsoft.windows.search/")
# ioc_reputation_check("04dcae7c2f31870f4a59ed6faec513a5e252491d911ae9e62b9c3026ccf598cd")

if __name__ == "__main__":
    #ioc = input("Enter IOC: ")
    raw_results = ioc_reputation_check(os.environ['IOC'])
    # ip = "183.96.224.3"  # Example IP address (Google DNS)
    # url = "http://www.ianfette.org/"  # Example URL
    # domain = "example.com"  # Example domain
    # # get_hash_reputation("aedf930f08b6f91f5762aaab686d143cd519ea6c0bf4c648337a98e56e14e8a8")
    # # get_hash_reputation("9cdf74b41b17660ec399b23534fcb5659c1fb1507eac5a55d4310362a3d6bc29")
    # get_ip_reputation("117.72.181.104")
    # get_url_reputation(url)
    # get_domain_reputation(domain)
# raw_data = raw_attack_technique("T1087")
# print(raw_data)

# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Usage: python your_script.py <IOC>")
#         sys.exit(1)
#
#     ioc = sys.argv[1]
#     ioc_reputation_check(ioc)