import requests

def geolocalizar_ip(ip, token=None):
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.RequestException as e:
        print(f"Error al consultar la IP: {e}")
        return None
