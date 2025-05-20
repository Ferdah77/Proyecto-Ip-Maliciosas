import dns.resolver

dnsbls = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org"
]

def check_blacklist(ip):
    reversed_ip = '.'.join(reversed(ip.split('.')))
    resultados = {}
    print(f"\nVerificando IP: {ip} en listas negras...\n")
    for dnsbl in dnsbls:
        query = f"{reversed_ip}.{dnsbl}"
        try:
            dns.resolver.resolve(query, "A")
            print(f"⚠️ La IP está en la lista negra: {dnsbl}")
            resultados[dnsbl] = True
        except dns.resolver.NXDOMAIN:
            print(f"✅ No está en la lista negra: {dnsbl}")
            resultados[dnsbl] = False
        except Exception as e:
            print(f"❓ Error consultando {dnsbl}: {e}")
            resultados[dnsbl] = False
    return resultados
