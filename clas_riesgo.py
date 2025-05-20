
# Archivo subido por Franco - verificación de IPs con AbuseIPDB

import requests

# Coloca aquí tu API key de AbuseIPDB
API_KEY = "9208ee9d4a318846921fb6f633ba3568c05f42f209b5780403076a26e079aefa70e12f33c30401f9"

def consultar_abuseipdb(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "")
        }
    else:
        print(f"[!] Error {response.status_code}: {response.text}")
        return {"score": 0}

def clasifica_riesgo(geo, whois_data, dnsbl, abuse, puertos):
    score = 0

    abuse_score = abuse.get("score", 0)
    if isinstance(abuse_score, (int, float)) and abuse_score > 50:
        score += 2

    if isinstance(dnsbl, dict) and any(bool(valor) for valor in dnsbl.values()):
        score += 2

    if isinstance(puertos, list):
        puertos_validos = [p for p in puertos if isinstance(p, int) and 1 <= p <= 65535]
        if len(puertos_validos) > 5:
            score += 1

    if score >= 4:
        return "ALTO"
    elif score >= 2:
        return "MEDIO"
    else:
        return "BAJO"

if __name__ == "__main__":
    ip = input("Introduce una IP para analizar: ").strip()
    abuse = consultar_abuseipdb(ip, API_KEY)

    # Simulación de otros datos (puedes integrar APIs reales si lo deseas)
    dnsbl = {
        "dnsbl.sorbs.net": False,
        "bl.spamcop.net": False
    }
    geo = {}
    whois_data = {}
    puertos = [22, 80, 443]  # Puedes modificar o pedir al usuario

    riesgo = clasifica_riesgo(geo, whois_data, dnsbl, abuse, puertos)
    print(f"\n[Riesgo] La IP {ip} tiene un nivel de riesgo: {riesgo}")
    print(f"[Detalles] Score de AbuseIPDB: {abuse['score']} / País: {abuse.get('country', 'Desconocido')}")
