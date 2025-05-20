import whois

def consulta_whois(dominio):
    """
    Realiza una consulta WHOIS simple para un dominio o IP.
    Retorna: dict con información relevante o mensaje de error.
    """
    try:
        resultado = whois.whois(dominio)
        info = {
            "domain_name": resultado.domain_name,
            "registrar": resultado.registrar,
            "whois_server": resultado.whois_server,
            "creation_date": str(resultado.creation_date),
            "expiration_date": str(resultado.expiration_date),
            "name_servers": resultado.name_servers,
            "status": resultado.status,
            "emails": resultado.emails
        }
        return info
    except Exception as e:
        return {"error": f"No se pudo obtener WHOIS: {e}"}