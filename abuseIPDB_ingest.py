import requests
import json
import os
# from api_keys import abuseIPDB_api_key
# Defining the api-endpoint
url = 'https://api.abuseipdb.com/api/v2/reports'

# querystring = {
#     'ipAddress': '220.246.42.212',
#     'maxAgeInDays': '9'
# }
# ip_Addr = querystring['ipAddress']
headers = {
    'Accept': 'application/json',
    'Key': os.environ['ABUSEIPDB_API_KEY']
}

# response = requests.request(method='GET', url=url, headers=headers, params=querystring)
# Formatted output
def print_results(ip):
    querystring = {
        'ipAddress': f"{ip}",
        'maxAgeInDays': '9'
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    decodedResponse = json.loads(response.text)
    results = decodedResponse["data"]["results"]
    if not results:
        return "No results found"
    # print(json.dumps(decodedResponse, sort_keys=True, indent=4))
    else:
        # print("--------LATEST RESULTS FOR:", ip,"-----------")
        results = json.dumps(results, indent=2)
        return results


if __name__ == "__main__":
    print(print_results("180.244.187.179"))