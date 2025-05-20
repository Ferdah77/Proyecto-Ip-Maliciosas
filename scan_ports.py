import requests
from datetime import datetime

API_KEY = "zDiLA6GqbYPgjVAJoP97DU8ijf0mTpcNWoyJrSZvXzuQ2SO8t6M5IzdSEbSj"
BASE_URL = "https://api.criminalip.io/v1/asset/ip/report"

def obtener_info_puertos(ip):
    """
    Consulta la API Criminal IP para obtener puertos abiertos de una IP.
    Retorna lista de diccionarios con información relevante y limpia de cada puerto.
    """
    headers = {
        "x-api-key": API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ip": ip,
        "full": "true"
    }
    try:
        response = requests.get(BASE_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        puertos_info = []
        # ACCESO CORREGIDO:
        port_data = data.get("port", {}).get("data", [])
        # Diccionario para agrupar puertos únicos (manteniendo el más reciente)
        puertos_unicos = {}
        for puerto in port_data:
            if puerto.get("port_status", "").lower() == "open":
                port_num = puerto.get("open_port_no")
                current_date = puerto.get("confirmed_time", "")
                # Si es la primera vez que vemos este puerto o es más reciente
                if port_num not in puertos_unicos or (
                    current_date > puertos_unicos[port_num].get("confirmed_time", "")
                ):
                    puertos_unicos[port_num] = puerto
        # Procesar los puertos únicos
        for port_num, puerto in puertos_unicos.items():
            info_puerto = {
                "numero": port_num,
                "protocolo": puerto.get("socket", "tcp"),
                "servicio": puerto.get("app_name", "Desconocido"),
                "version": puerto.get("app_version", "N/A"),
                "estado": puerto.get("port_status", "").capitalize(),
                "vulnerable": puerto.get("is_vulnerability", False),
                "ultima_deteccion": puerto.get("confirmed_time", "N/A"),
                "banner": (puerto.get("banner", "")[:100] + "...") if puerto.get("banner") else "N/A"
            }
            puertos_info.append(info_puerto)
        return puertos_info
    except requests.HTTPError as e:
        print(f"Error HTTP al consultar Criminal IP API: {e.response.status_code}")
        if e.response.status_code == 400:
            print("Posible IP inválida o parámetros incorrectos")
        elif e.response.status_code == 401:
            print("API Key inválida o no autorizada")
        elif e.response.status_code == 429:
            print("Límite de tasa excedido")
        return []
    except Exception as e:
        print(f"Error al consultar la API: {str(e)}")
        return []
