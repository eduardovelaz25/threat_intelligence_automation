import requests
import json
import os
# from api_keys import alienvault_api_key

API_KEY = os.environ['ALIENVAULT_API_KEY']
aws_key = "AIzaSyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q"
BASE_URL = "https://otx.alienvault.com/api/v1"

headers = {
    "X-OTX-API-KEY": API_KEY
}

def get_ip_info(ip):
    url = f"{BASE_URL}/indicators/IPv4/{ip}/general"

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return f"Error: {response.status_code}/n {response.text}"
        # return response.text
        # return

    data = response.json()
    formatted_data = json.dumps(data, indent=2)
    return formatted_data
    # print(f"IP Address: {ip}")
    # print(f"Country: {data.get('country_name')}")
    # print(f"ASN: {data.get('asn')}")
    # print(f"Reputation: {data.get('reputation')}")
    #
    # pulses = data.get("pulse_info", {}).get("pulses", [])
    #
    # print(f"\nAssociated Pulses: {len(pulses)}")
    #
    # for pulse in pulses:
    #     print("-" * 40)
    #     print(f"Name: {pulse.get('name')}")
    #     print(f"Author: {pulse.get('author_name')}")
    #     print(f"Created: {pulse.get('created')}")
    #     print(f"Tags: {', '.join(pulse.get('tags', []))}")
    #

def get_domain_info(domain):
    url = f"{BASE_URL}/indicators/domain/{domain}/general"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return f"Error: {response.status_code}\n{response.text}"

    data = response.json()
    return json.dumps(data, indent=2)

    # data = response.json()
    #
    # print(f"Domain: {domain}")
    # print(f"Reputation: {data.get('reputation')}")
    #
    # pulses = data.get("pulse_info", {}).get("pulses", [])
    #
    # print(f"Found in {len(pulses)} threat pulses.")

def get_url_info(url_to_check):
    from urllib.parse import quote

    encoded = quote(url_to_check, safe="")
    url = f"{BASE_URL}/indicators/url/{encoded}/general"

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return response.text

    data = response.json()
    return json.dumps(data, indent=2)

def get_hash_info(file_hash):
    url = f"{BASE_URL}/indicators/file/{file_hash}/general"

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return response.text

    data = response.json()
    return json.dumps(data, indent=2)

if __name__ == "__main__":
    #get_domain_info("4dgamers.com")
    #get_url_info("lifehealthsanfrancisco2015.com")
    # get_hash_info("aedf930f08b6f91f5762aaab686d143cd519ea6c0bf4c648337a98e56e14e8a8")
    # get_hash_info("028c9a1619f96dbfd29ca64199f4acde")
    get_ip_info("180.244.187.179")