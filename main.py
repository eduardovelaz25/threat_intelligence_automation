from concurrent.futures import ThreadPoolExecutor, as_completed

from virustotal_ingest import (
    get_ioc_type,
    get_ip_reputation,
    get_domain_reputation,
    get_url_reputation,
    get_hash_reputation,
)

from abuseIPDB_ingest import print_results as abuseipdb_lookup

from threatfox_abuse_ch_ingest import (
    lookup_ioc as threatfox_lookup,
    print_results as threatfox_print,
)

from alienvault_ingest import (
    get_ip_info,
    get_domain_info,
    get_url_info,
    get_hash_info,
)

from hybrid_analysis import hybrid_lookup
from googleGemini import analyze_threat_intel


LOOKUPS = {
    "ip": [
        ("VirusTotal", get_ip_reputation),
        ("AbuseIPDB", abuseipdb_lookup),
        ("ThreatFox", threatfox_lookup),
        ("AlienVault OTX", get_ip_info),
        ("Hybrid Analysis", lambda x: hybrid_lookup(x, "ip")),
    ],

    "domain": [
        ("VirusTotal", get_domain_reputation),
        ("ThreatFox", threatfox_lookup),
        ("AlienVault OTX", get_domain_info),
        ("Hybrid Analysis", lambda x: hybrid_lookup(x, "domain")),
    ],

    "url": [
        ("VirusTotal", get_url_reputation),
        ("ThreatFox", threatfox_lookup),
        ("AlienVault OTX", get_url_info),
        ("Hybrid Analysis", lambda x: hybrid_lookup(x, "url")),
    ],

    "sha256": [
        ("VirusTotal", get_hash_reputation),
        ("ThreatFox", threatfox_lookup),
        ("AlienVault OTX", get_hash_info),
        ("Hybrid Analysis", lambda x: hybrid_lookup(x, "hash")),
    ],

    "sha1": [
        ("VirusTotal", get_hash_reputation),
        ("ThreatFox", threatfox_lookup),
        ("AlienVault OTX", get_hash_info),
        ("Hybrid Analysis", lambda x: hybrid_lookup(x, "hash")),
    ],

    "md5": [
        ("VirusTotal", get_hash_reputation),
        ("ThreatFox", threatfox_lookup),
        ("AlienVault OTX", get_hash_info),
        ("Hybrid Analysis", lambda x: hybrid_lookup(x, "hash")),
    ],
}


def run_lookup(name, func, ioc):
    print("\n" + "=" * 70)
    print(f" {name}")
    print("=" * 70)

    try:
        result = func(ioc)

        # ThreatFox returns raw data
        if name == "ThreatFox":
            if result:
                threatfox_print(result)
            else:
                print("No results found.")

        elif result is None:
            print("No results found.")

        elif not isinstance(result, (dict, list)):
            print(result)

        print("=" * 70)

        return name, result

    except Exception as e:
        print(f"Error: {e}")
        print("=" * 70)
        return name, {"error": str(e)}


def main():

    ioc = input("IOC: ").strip()

    ioc_type = get_ioc_type(ioc)

    if ioc_type == "unknown":
        print("Unknown IOC type")
        return

    print(f"\nDetected IOC Type: {ioc_type}")

    lookups = LOOKUPS.get(ioc_type, [])

    all_results = {}

    with ThreadPoolExecutor(max_workers=len(lookups)) as executor:

        futures = [
            executor.submit(run_lookup, name, func, ioc)
            for name, func in lookups
        ]

        for future in as_completed(futures):
            name, result = future.result()

            if result not in (None, "", [], {}):
                all_results[name] = result

    print("\n" + "=" * 70)
    print(" Gemini Threat Intelligence Assessment ")
    print("=" * 70)

    try:
        summary = analyze_threat_intel(ioc, all_results)
        print(summary)

    except Exception as e:
        print(f"Gemini analysis failed: {e}")


if __name__ == "__main__":
    main()