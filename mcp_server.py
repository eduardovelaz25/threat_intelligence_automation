from dotenv import load_dotenv
from mcp.server import MCPServer

import virustotal_ingest
import abuseIPDB_ingest
import alienvault_ingest
import threatfox_abuse_ch_ingest
import hybrid_analysis


mcp = MCPServer("Threat Intelligence")


@mcp.tool()
def identify_ioc_type(ioc: str) -> dict:
    """
    Determine whether an IOC is an IP address, domain, URL,
    MD5, SHA1, SHA256, or unknown.
    """

    return {
        "ioc": ioc,
        "type": virustotal_ingest.get_ioc_type(ioc)
    }


@mcp.tool()
def virustotal_lookup(ioc: str) -> dict:
    """
    Look up an IP, domain, URL, or file hash in VirusTotal.
    """

    return virustotal_ingest.ioc_reputation_check(ioc)


@mcp.tool()
def abuseipdb_lookup(ip: str) -> dict:
    """
    Look up an IP address in AbuseIPDB.
    """

    return abuseIPDB_ingest.lookup_ip(ip)


@mcp.tool()
def threatfox_lookup(ioc: str) -> dict:
    """
    Search ThreatFox for an IOC.
    """

    return threatfox_abuse_ch_ingest.lookup_ioc(ioc)


@mcp.tool()
def alienvault_lookup(ioc: str, ioc_type: str) -> dict:
    """
    Look up an IOC in AlienVault OTX.

    Supported IOC types:
    ip, domain, url, md5, sha1, sha256
    """

    if ioc_type == "ip":
        return alienvault_ingest.get_ip_info(ioc)

    if ioc_type == "domain":
        return alienvault_ingest.get_domain_info(ioc)

    if ioc_type == "url":
        return alienvault_ingest.get_url_info(ioc)

    if ioc_type in ("md5", "sha1", "sha256"):
        return alienvault_ingest.get_hash_info(ioc)

    return {
        "ioc": ioc,
        "source": "AlienVault OTX",
        "error": f"Unsupported IOC type: {ioc_type}"
    }


@mcp.tool()
def hybrid_analysis_lookup(ioc: str, ioc_type: str) -> dict:
    """
    Look up an IOC in Hybrid Analysis.

    Supported IOC types:
    ip, domain, url, md5, sha1, sha256
    """

    return hybrid_analysis.hybrid_lookup(ioc, ioc_type)


if __name__ == "__main__":
    mcp.run()