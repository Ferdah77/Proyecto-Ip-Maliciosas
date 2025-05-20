import requests

API_KEY = "63157249fda09b784e99670295cb550d6d90b65ed25b0c2c9c1864f6386ad2fcd68b95ebee874c08"

def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Key": API_KEY, "Accept": "application/json"}
        response = requests.get(url, headers=headers, params=params)
        data = response.json()["data"]
        return {
            "score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "last_report": data["lastReportedAt"]
        }
    except Exception as e:
        return {"error": str(e)}
