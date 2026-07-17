import requests
import json
from api_keys import hyrid_analysis_api_key

API_KEY = hyrid_analysis_api_key

BASE_URL = "https://hybrid-analysis.com/api/v2"

HEADERS = {
    "api-key": API_KEY,
    "User-Agent": "Falcon Sandbox",
    "accept": "application/json"
}
def ha_hash_lookup(file_hash):
    url = f"{BASE_URL}/overview/{file_hash}"

    params = {
        "hash": file_hash
    }

    response = requests.get(
        url,
        headers=HEADERS,
        params=params,
        timeout=30
    )

    if response.status_code != 200:
        print(response.text)
        return None

    data = response.json()
    print(json.dumps(data, indent=2))
    if not data:
        return None

    # sample = data[0]
    #
    # return {
    #     "sha256": sample.get("sha256"),
    #     "sha1": sample.get("sha1"),
    #     "md5": sample.get("md5"),
    #     "family": sample.get("vx_family"),
    #     "threat_score": sample.get("threat_score"),
    #     "av_detect": sample.get("av_detect"),
    #     "verdict": sample.get("verdict"),
    #     "type": sample.get("type_short"),
    #     "size": sample.get("size"),
    #     "mitre": sample.get("mitre_attcks", []),
    #     "domains": sample.get("domains", []),
    #     "hosts": sample.get("hosts", [])
    #}
def ha_ip_lookup(ip):
    # url = f"{BASE_URL}/search/terms"
    #
    # body = {
    #     "query": f"{ip}"
    # }
    #
    # response = requests.post(
    #     url,
    #     headers=HEADERS,
    #     json=body,
    #     timeout=30
    # )
    #
    # if response.status_code != 200:
    #     print(response.text)
    #     return None

    url = f"{BASE_URL}/search/terms"

    headers = HEADERS.copy()
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    response = requests.post(
        url,
        headers=headers,
        data={
            "host": ip
        },
        timeout=30
    )

    json_format = response.json()
    print(json.dumps(json_format, indent=2))
    # print(response.text)

    # return response.json()
def ha_domain_lookup(domain):
    url = f"{BASE_URL}/search/terms"

    body = {
        "query": f"domain:{domain}"
    }

    response = requests.post(
        url,
        headers=HEADERS,
        json=body,
        timeout=30
    )

    if response.status_code != 200:
        print(response.text)
        return None

    return response.json()
def ha_filename_lookup(filename):
    url = f"{BASE_URL}/search/terms"

    body = {
        "query": f"filename:{filename}"
    }

    response = requests.post(
        url,
        headers=HEADERS,
        json=body,
        timeout=30
    )

    if response.status_code != 200:
        # print(response.text)
        json_format = response.json()
        print(json.dumps(json_format, indent=2))
        return None

    return response.json()
def ha_url_lookup(url_ioc):
    url = f"{BASE_URL}/search/terms"

    headers = HEADERS.copy()
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    response = requests.post(
        url,
        headers=headers,
        data={
            "url": url_ioc
        }
    )

    #print(response.status_code)
    # print(response.text)
    json_format = response.json()
    print(json.dumps(json_format, indent=2))
def hybrid_lookup(ioc, ioc_type):

    if ioc_type == "hash":
        return ha_hash_lookup(ioc)

    elif ioc_type == "ip":
        return ha_ip_lookup(ioc)

    elif ioc_type == "domain":
        return ha_domain_lookup(ioc)
    elif ioc_type == 'url':
        return ha_url_lookup(ioc)
    else:
        return {
            "error": f"Hybrid Analysis lookup not implemented for {ioc_type}"
        }

if __name__ == "__main__":
    #hybrid_lookup("04dcae7c2f31870f4a59ed6faec513a5e252491d911ae9e62b9c3026ccf598cd", "hash")
    hybrid_lookup("http://222.141.81.195:50923/bin.sh", "url")
    hybrid_lookup("42.225.228.53", "ip")