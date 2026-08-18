
import json
import google.generativeai as genai
import os
# from api_keys import gemini_api_key
gemini_api_key = os.environ.get('GEMINI_API_KEY', '')

genai.configure(api_key=gemini_api_key)

model = genai.GenerativeModel("gemini-2.5-flash")


def analyze_threat_intel(ioc, results):
    """
    Analyze aggregated threat intelligence from multiple providers.

    Args:
        ioc (str): IOC being analyzed.
        results (dict): Dictionary containing results from all providers.

    Returns:
        str: Gemini summary.
    """

    prompt = f"""
You are a senior cyber threat intelligence analyst.

The following threat intelligence was collected for the IOC:

IOC:
{ioc}

Threat Intelligence:
{json.dumps(results, indent=2)}

Please provide:

1. Executive summary (2-3 sentences)
2. Overall maliciousness assessment (High/Medium/Low)
3. Key findings from each threat intelligence source
4. Malware families (if any)
5. MITRE ATT&CK techniques observed
6. Infrastructure observations (IPs, domains, URLs)
7. Confidence level in the intelligence
8. Recommended SOC actions
9. Recommended detection opportunities
10. Any conflicting information between sources

Do not simply repeat the JSON. Summarize the intelligence like a professional threat intelligence analyst.
"""

    response = model.generate_content(prompt)

    return response.text

