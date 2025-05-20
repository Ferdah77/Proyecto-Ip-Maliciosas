import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

from abuseipdb import check_abuseipdb
from get_geo import geolocalizar_ip
from dnsbl import check_blacklist
from show_whois import consulta_whois
from clas_riesgo import clasifica_riesgo
from scan_ports import obtener_info_puertos

def pedir_ip():
    while True:
        ip = input("\nIngrese la dirección IP a analizar: ").strip()
        if ip:
            return ip
        print("IP inválida, intente nuevamente.")

def pedir_correo():
    while True:
        correo = input("\nIngrese el correo donde enviar el reporte: ").strip()
        if "@" in correo and "." in correo:
            return correo
        print("Correo inválido, intente nuevamente.")

def generar_recomendaciones(riesgo, puertos_abiertos, abuse_score, en_listas_negras=False):
    recomendaciones = []
    
    # Recomendaciones generales por nivel de riesgo
    if riesgo == "Crítico":
        recomendaciones.append("● [URGENTE] Aislar inmediatamente la IP en firewalls, routers y sistemas de red")
        recomendaciones.append("● Desconectar dispositivos comprometidos de la red")
        recomendaciones.append("● Escanear toda la red con herramientas como Malwarebytes o ClamAV")
        recomendaciones.append("● Reportar a CERT nacional o equipo de seguridad de la organización")
    elif riesgo == "Alto":
        recomendaciones.append("● Bloquear la IP en firewalls y sistemas de seguridad perimetral")
        recomendaciones.append("● Implementar reglas de bloqueo temporal (ej: 24-48 horas)")
        recomendaciones.append("● Revisar logs de firewall, servidores y dispositivos de red")
    elif riesgo == "Medio":
        recomendaciones.append("● Restringir acceso desde esta IP solo a servicios esenciales")
        recomendaciones.append("● Configurar alertas para actividad sospechosa desde esta IP")
        recomendaciones.append("● Considerar implementar autenticación de dos factores para accesos")
    else:
        recomendaciones.append("● Mantener monitoreo básico con herramientas como AbuseIPDB")
        recomendaciones.append("● Revisar configuración de seguridad periódicamente")

    # Recomendaciones específicas si está en listas negras
    if en_listas_negras:
        recomendaciones.append("\n● [LISTAS NEGRAS] Contactar al ISP/proveedor de internet para:")
        recomendaciones.append("  - Solicitar una nueva IP pública (la mayoría ofrece esto gratis por seguridad)")
        recomendaciones.append("  - Reportar el problema para que ellos gestionen el deslistado")
        recomendaciones.append("  - Preguntar si hay reportes previos de actividad maliciosa desde tu red")
        recomendaciones.append("● Verificar dispositivos IoT (cámaras, routers) que puedan estar comprometidos")
        recomendaciones.append("● Cambiar contraseñas de todos los dispositivos de red (router, NAS, servidores)")

    # Recomendaciones para puertos sensibles
    if puertos_abiertos:
        puertos_riesgo = [p for p in puertos_abiertos if p in [21, 22, 23, 80, 443, 3389, 3306]]
        if puertos_riesgo:
            recomendaciones.append("\n● [PUERTOS SENSIBLES] Acciones recomendadas:")
            recomendaciones.append(f"  - Cerrar puertos no esenciales ({', '.join(map(str, puertos_riesgo))})")
            recomendaciones.append("  - Usar VPN para acceder a servicios internos en lugar de exponer puertos")
            recomendaciones.append("  - Implementar fail2ban para protección contra ataques de fuerza bruta")
            if 22 in puertos_riesgo:
                recomendaciones.append("  - Para SSH: Cambiar a autenticación por claves y desactivar login root")
            if 3389 in puertos_riesgo:
                recomendaciones.append("  - Para RDP: Usar NLA (Network Level Authentication) y limitar IPs de acceso")

    # Recomendaciones basadas en AbuseIPDB score
    if abuse_score > 75:
        recomendaciones.append("\n● [ABUSEIPDB CRÍTICO] Acciones inmediatas:")
        recomendaciones.append("  - Realizar análisis forense básico (registros de conexiones, procesos sospechosos)")
        recomendaciones.append("  - Considerar restablecer dispositivos de red a configuración de fábrica")
        recomendaciones.append("  - Reportar falso positivo en AbuseIPDB si es un error")
    elif abuse_score > 50:
        recomendaciones.append("\n● [ABUSEIPDB ALTO] Recomendaciones:")
        recomendaciones.append("  - Monitorear tráfico desde esta IP con Wireshark o tcpdump")
        recomendaciones.append("  - Verificar si algún servicio está siendo usado para ataques (ej: servidor mail no seguro)")

    # Recomendación final genérica
    recomendaciones.append("\n● [MEJORAS PREVENTIVAS] Para todos los casos:")
    recomendaciones.append("  - Actualizar firmware de routers y dispositivos de red")
    recomendaciones.append("  - Usar contraseñas complejas y únicas para cada servicio")
    recomendaciones.append("  - Considerar usar un servicio VPN para ocultar tu IP pública")
    recomendaciones.append("  - Configurar alertas en Shodan.io para monitoreo de puertos expuestos")
    recomendaciones.append("  - SI SU IP ESTA EN LISTA NEGRA, CONTACTE A SU ISP")
    return "\n".join(recomendaciones)

def enviar_correo(reporte, correo_destino, ip):
    print(f"\nEnviando reporte a {correo_destino}...")
    remitente = "laboratorio.leica.ina@gmail.com"
    password = "uozm ownm fmsx unym"
    asunto = f"Reporte de análisis de IP {ip}"
    
    # Crear mensaje multipart
    msg = MIMEMultipart()
    msg["Subject"] = asunto
    msg["From"] = remitente
    msg["To"] = correo_destino
    
    # Parte de texto
    msg.attach(MIMEText(reporte, "plain", "utf-8"))
    
    # Adjuntar archivo .txt
    filename = f"reporte_ip_{ip}.txt"
    part = MIMEApplication(reporte.encode('utf-8'), Name=filename)
    part['Content-Disposition'] = f'attachment; filename="{filename}"'
    msg.attach(part)
    
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(remitente, password)
            server.sendmail(remitente, correo_destino, msg.as_string())
        print("Reporte enviado con éxito.")
    except Exception as e:
        print("Error enviando el correo:", e)

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("="*60)
    print("ANÁLISIS DE IP COMPLETO")
    print("="*60)

    ip = pedir_ip()
    correo = pedir_correo()

    # 1. GEOLOCALIZACIÓN
    print("\n--- GEOLOCALIZACIÓN ---")
    token = "f523b9e976cf29"
    geo = geolocalizar_ip(ip, token)
    if geo:
        for k, v in geo.items():
            print(f"{k}: {v}")
    else:
        print("No se pudo obtener la geolocalización.")

    # 2. CONSULTA WHOIS
    print("\n--- CONSULTA WHOIS ---")
    whois_data = consulta_whois(ip)
    if "error" in whois_data:
        print(whois_data["error"])
    else:
        for k, v in whois_data.items():
            print(f"{k}: {v}")

    # 3. DNSBL
    print("\n--- CONSULTA DNSBL (Listas Negras) ---")
    dnsbl_result = check_blacklist(ip)
    if dnsbl_result:
        for k, v in dnsbl_result.items():
            print(f"{k}: {'EN LISTA NEGRA' if v else 'LIMPIO'}")

    # 4. ABUSEIPDB
    print("\n--- CONSULTA ABUSEIPDB ---")
    abuse = check_abuseipdb(ip)
    if "error" in abuse:
        print("Error consultando AbuseIPDB:", abuse["error"])
    else:
        print(f"Abuse Confidence Score: {abuse['score']}")
        print(f"Total de reportes: {abuse['total_reports']}")
        print(f"Último reporte: {abuse['last_report']}")

    # 5. SCAN PORTS
    print("\n--- PUERTOS ABIERTOS (Criminal IP API) ---")
    puertos_api = obtener_info_puertos(ip)
    puertos_numeros = [p['numero'] for p in puertos_api] if puertos_api else []
    if puertos_api:
        print(f"Se encontraron {len(puertos_api)} puertos abiertos:")
        for p in puertos_api:
            print(f"\n- Puerto {p['numero']}/{p['protocolo']}:")
            print(f"  Servicio: {p['servicio']} (v{p['version']})")
            print(f"  Estado: {p['estado']}")
            print(f"  Vulnerable: {'Sí' if p['vulnerable'] else 'No'}")
            print(f"  Última detección: {p['ultima_deteccion']}")
            if p['banner'] != "N/A":
                print(f"  Banner: {p['banner']}")
    else:
        print("No se encontraron puertos abiertos o hubo un error en la consulta.")

    # 6. CLASIFICACIÓN DE RIESGO
    print("\n--- CLASIFICACIÓN DE RIESGO ---")
    riesgo = clasifica_riesgo(geo, whois_data, dnsbl_result, abuse, puertos_numeros)
    print(f"Nivel de riesgo estimado: {riesgo}")

    # 7. RECOMENDACIONES DE ACCIÓN
    print("\n--- RECOMENDACIONES DE ACCIÓN ---")
    abuse_score = abuse.get('score', 0) if not "error" in abuse else 0
    recomendaciones = generar_recomendaciones(riesgo, puertos_numeros, abuse_score)
    print(recomendaciones)

    # Generar reporte completo
    reporte = []
    reporte.append(f"Reporte de análisis para la IP: {ip}\n")
    reporte.append("="*60)

    reporte.append("\n--- GEOLOCALIZACIÓN ---")
    if geo:
        for k, v in geo.items():
            reporte.append(f"{k}: {v}")
    else:
        reporte.append("No se pudo obtener la geolocalización.")

    reporte.append("\n--- WHOIS ---")
    if "error" in whois_data:
        reporte.append(whois_data["error"])
    else:
        for k, v in whois_data.items():
            reporte.append(f"{k}: {v}")

    reporte.append("\n--- DNSBL ---")
    if dnsbl_result:
        for k, v in dnsbl_result.items():
            reporte.append(f"{k}: {'EN LISTA NEGRA' if v else 'LIMPIO'}")
    else:
        reporte.append("No se pudo consultar DNSBL.")

    reporte.append("\n--- ABUSEIPDB ---")
    if "error" in abuse:
        reporte.append(f"Error: {abuse['error']}")
    else:
        reporte.append(f"Abuse Confidence Score: {abuse['score']}")
        reporte.append(f"Total de reportes: {abuse['total_reports']}")
        reporte.append(f"Último reporte: {abuse['last_report']}")

    reporte.append("\n--- PUERTOS ABIERTOS ---")
    if puertos_api:
        for p in puertos_api:
            linea = f"Puerto {p['numero']} ({p['protocolo']}): Servicio {p['servicio']}"
            if p['vulnerable']:
                linea += " (VULNERABLE)"
            reporte.append(linea)
    else:
        reporte.append("No se encontraron puertos abiertos.")

    reporte.append(f"\n--- CLASIFICACIÓN DE RIESGO: {riesgo} ---")

    reporte.append("\n--- RECOMENDACIONES DE ACCIÓN ---")
    reporte.append(recomendaciones)

    reporte_final = "\n".join(reporte)

    print("\n--- REPORTE FINAL ---\n")
    print(reporte_final)

    # 8. ENVÍO POR CORREO CON ADJUNTO .TXT
    enviar_correo(reporte_final, correo, ip)
    
    # Guardar también localmente
    with open(f"reporte_ip_{ip}.txt", "w", encoding="utf-8") as f:
        f.write(reporte_final)
    
    print(f"\nReporte guardado como reporte_ip_{ip}.txt")
    print("Proceso finalizado.")

if __name__ == "__main__":
    main()
