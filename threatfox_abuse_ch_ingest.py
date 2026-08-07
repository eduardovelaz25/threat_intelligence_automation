import os

import requests
import json

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def lookup_ioc(ioc):
    payload = {
        "query": "search_ioc",
        "search_term": ioc
    }

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "ThreatIntelAutomation/1.0",
        "Auth-Key": os.environ['THREATFOX_ABUSE_API_KEY']
    }

    try:
        response = requests.post(
            THREATFOX_API,
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()

        data = response.json()

        if data["query_status"] == "ok":
            return data["data"]
        else:
            print(f"No results found: {data['query_status']}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"API Error: {e}")
        return None


def format_results(results):
    if not results:
        return ""

    output = []
    for item in results:
        output.append("=" * 60)
        output.append(f"IOC:              {item.get('ioc')}")
        output.append(f"IOC Type:         {item.get('ioc_type')}")
        output.append(f"Malware Family:   {item.get('malware')}")
        output.append(f"Threat Type:      {item.get('threat_type')}")
        output.append(f"Confidence:       {item.get('confidence_level')}")
        output.append(f"First Seen:       {item.get('first_seen')}")
        output.append(f"Last Seen:        {item.get('last_seen')}")
        output.append(f"Reporter:         {item.get('reporter')}")
        output.append(f"Tags:             {item.get('tags', [])}")
        output.append(f"Reference:        {item.get('reference')}")
        output.append("=" * 60)
    return "\n".join(output)
# def parse_results(results):
#     if not results:
#         return []
#
#     parsed_results = []
#
#     for item in results:
#         parsed_results.append({
#             "ioc": item.get("ioc"),
#             "ioc_type": item.get("ioc_type"),
#             "malware_family": item.get("malware"),
#             "threat_type": item.get("threat_type"),
#             "confidence": item.get("confidence_level"),
#             "first_seen": item.get("first_seen"),
#             "last_seen": item.get("last_seen"),
#             "reporter": item.get("reporter"),
#             "tags": item.get("tags", []),
#             "reference": item.get("reference"),
#         })
#
#     return parsed_results

# ioc = input("Enter IOC: ")
# raw_results = lookup_ioc(ioc)
# print_results(raw_results)
# formatted_results = parse_results(raw_results)
# print(formatted_results)
# def threatfox_main():
#     ioc = input("Enter IOC: ")
#     results = lookup_ioc(ioc)
#     print_results(results)
if __name__ == "__main__":
    ioc = input("Enter IOC: ")
    results = lookup_ioc(ioc)
    output = format_results(results)
    if output:
        print(output)
