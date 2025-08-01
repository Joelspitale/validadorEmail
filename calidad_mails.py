import dns.resolver
import smtplib
import socket
import re
import os
import csv
import whois
import time
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

class EmailValidator:
    def __init__(self, smtp_from='verificador@tudominio.com', smtp_timeout=5):
        self.smtp_from = smtp_from
        self.smtp_timeout = smtp_timeout

        self.dominios_bloqueados = {
            "mailinator.com", "tempmail.com", "10minutemail.com", "notiene.com",
            "discard.email", "guerrillamail.com"
        }

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

        self.dnsbl_servers = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'b.barracudacentral.org',
            'dnsbl.sorbs.net',
        ]

    @lru_cache(maxsize=128)
    def obtener_mx(self, dominio):
        try:
            return self.resolver.resolve(dominio, 'MX')
        except Exception:
            return None

    def dominio_tiene_mx(self, dominio):
        registros_mx = self.obtener_mx(dominio)
        return registros_mx is not None and len(registros_mx) > 0

    def verificar_whois(self, dominio):
        try:
            info = whois.whois(dominio)
            if info is None or (not info.creation_date and not info.expiration_date):
                return False
            return True
        except Exception:
            return False

    def chequear_dnsbl(self, dominio):
        try:
            ips = self.resolver.resolve(dominio, 'A')
        except Exception:
            return False
        for ip_rdata in ips:
            ip = ip_rdata.to_text()
            reversed_ip = '.'.join(ip.split('.')[::-1])
            for server in self.dnsbl_servers:
                query = f"{reversed_ip}.{server}"
                try:
                    self.resolver.resolve(query, 'A')
                    return True  # Está listado
                except dns.resolver.NXDOMAIN:
                    continue
                except Exception:
                    continue
        return False

    def verificar_catch_all(self, dominio):
        try:
            registros_mx = self.obtener_mx(dominio)
            if not registros_mx:
                return False

            servidor_mx = str(sorted(registros_mx, key=lambda r: r.preference)[0].exchange)
            server = smtplib.SMTP(timeout=self.smtp_timeout)
            server.connect(servidor_mx)
            server.helo(socket.gethostname())
            server.mail(self.smtp_from)
            falso_email = f"test_invalido_{os.urandom(4).hex()}@{dominio}"
            code, _ = server.rcpt(falso_email)
            server.quit()
            return code == 250
        except Exception:
            return False

    def validar_sintaxis(self, email):
        regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return re.match(regex, email) is not None

    def correo_sospechoso(self, email):
        usuario, _ = email.lower().split('@')
        patrones = ['test', 'demo', 'asdf', 'fake', 'correo', 'prueba']
        return any(p in usuario for p in patrones)

    def verificar_smtp(self, email):
        dominio = email.split('@')[1]
        registros_mx = self.obtener_mx(dominio)
        if not registros_mx:
            return None
        try:
            servidor_mx = str(sorted(registros_mx, key=lambda r: r.preference)[0].exchange)
            server = smtplib.SMTP(timeout=self.smtp_timeout)
            server.connect(servidor_mx)
            server.helo(socket.gethostname())
            server.mail(self.smtp_from)
            code, _ = server.rcpt(email)
            server.quit()
            return code == 250
        except smtplib.SMTPRecipientsRefused:
            return False
        except (socket.timeout, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected):
            return None
        except Exception:
            return None

def cargar_emails(path):
    if not os.path.exists(path):
        print(f"Archivo no encontrado: {path}")
        return []
    with open(path, 'r') as f:
        return list(set(line.strip().lower() for line in f if line.strip()))

def cargar_set(path):
    return set(open(path).read().splitlines()) if os.path.exists(path) else set()

def guardar_linea(path, linea):
    with open(path, 'a') as f:
        f.write(f"{linea}\n")

def exportar_resultados_csv(path, resultados):
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["email", "estado", "motivo"])
        writer.writeheader()
        for fila in resultados:
            writer.writerow(fila)

def main():
    inicio = time.time()
    archivo_entrada = "emails_a_validar.txt"
    archivo_no_validos = "mail_no_validos.txt"
    archivo_validados_ok = "email_validados_ok.txt"
    archivo_resultados_csv = "resultado_validacion.csv"
    archivo_dominios_ok = "dominios_ok.txt"
    archivo_dominios_error = "dominios_con_error.txt"
    archivo_no_procesados = "emails_no_procesados.txt"


    validador = EmailValidator()

    emails = cargar_emails(archivo_entrada)
    dominios_ok = cargar_set(archivo_dominios_ok)
    dominios_err = cargar_set(archivo_dominios_error)

    # Agrupar emails por dominio
    dominios_emails = {}
    for email in emails:
        dominio = email.split('@')[1]
        dominios_emails.setdefault(dominio, []).append(email)

    dominios_validacion = {}
    print(f"📨 Total de dominios es: {len(dominios_emails)}")
    contador = 0
    for dominio in dominios_emails:
        contador=contador+1
        if dominio in dominios_ok:
            dominios_validacion[dominio] = {"error": False, "warning": False, "mensaje": "Dom. previamente validado"}
            continue
        if dominio in dominios_err:
            dominios_validacion[dominio] = {"error": True, "mensaje": "Dom. previamente inválido"}
            continue
        if dominio in validador.dominios_bloqueados:
            guardar_linea(archivo_dominios_error, dominio)
            dominios_validacion[dominio] = {"error": True, "mensaje": "Bloqueado"}
            continue
        if not validador.dominio_tiene_mx(dominio):
            guardar_linea(archivo_dominios_error, dominio)
            dominios_validacion[dominio] = {"error": True, "mensaje": "Sin MX"}
            continue
        if not validador.verificar_whois(dominio):
            guardar_linea(archivo_dominios_error, dominio)
            dominios_validacion[dominio] = {"error": True, "mensaje": "WHOIS inválido"}
            continue
        if validador.chequear_dnsbl(dominio):
            guardar_linea(archivo_dominios_error, dominio)
            dominios_validacion[dominio] = {"error": True, "mensaje": "DNSBL listado"}
            continue
        catch_all = validador.verificar_catch_all(dominio)
        if catch_all:
            guardar_linea(archivo_dominios_ok, dominio)
            dominios_validacion[dominio] = {
                "error": False,
                "warning": True,
                "mensaje": "Catch-All detectado – Se omiten validaciones individuales"
            }
            print(f"⚠️ Dominio catch-all detectado: {dominio}, se omiten sus correos")
            continue  # omitir validación individual
        guardar_linea(archivo_dominios_ok, dominio)
        #print(f"📨 Validando el dominio --> {dominio}")
        
    print(f"📨 Se termino la validacion de los dominios, se validaron: {len(dominios_emails)}")
    resultados = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futuros = {}
        for dominio, emails in dominios_emails.items():
            estado_dominio = dominios_validacion.get(dominio, {})
            if estado_dominio.get("warning"):
                for email in emails:
                    resultados.append({
                        "email": email,
                        "estado": "⚠️ Dominio Catch-All",
                        "motivo": estado_dominio["mensaje"]
                    })
                continue
            if estado_dominio.get("error"):
                for email in emails:
                    resultados.append({"email": email, "estado": "❌ Dominio inválido", "motivo": estado_dominio["mensaje"]})
                    guardar_linea(archivo_no_validos, email)
                continue
            for email in emails:
                futuros[executor.submit(validar_email_con_estado, validador, email, estado_dominio, archivo_validados_ok, archivo_no_validos)] = email

        procesados = set()
        try:
            for future in as_completed(futuros, timeout=300):  # timeout global
                email = futuros[future]
                try:
                    resultado, _, _ = future.result(timeout=20)  # timeout individual
                    resultados.append(resultado)
                    procesados.add(email)
                except Exception as e:
                    resultados.append({"email": email, "estado": "❌ Error interno", "motivo": f"{type(e).__name__}: {str(e)}"})
        except Exception as e:
            print(f"⚠️ Tiempo excedido en procesamiento paralelo: {str(e)}")

        # Verificar emails no procesados
        faltantes = set(futuros.values()) - procesados
        if faltantes:
            print(f"⚠️ Los siguientes emails no fueron procesados correctamente:")
            open(archivo_no_procesados, 'w').close()  # Limpia archivo antes de escribir
            for email in faltantes:
                resultados.append({"email": email, "estado": "❌ No procesado", "motivo": "Timeout o excepción general"})
                print(f" - {email}")
                guardar_linea(archivo_no_procesados, email)



    exportar_resultados_csv(archivo_resultados_csv, resultados)
    print("\nValidación completada. Resultados exportados.")
    fin = time.time()
    tiempo_ejecucion = fin - inicio / 60
    print(f"El programa tardó {tiempo_ejecucion:.2f} minutos en ejecutarse.")
    total_validos = sum(1 for r in resultados if r['estado'].startswith("✅"))
    total_invalidos = sum(1 for r in resultados if r['estado'].startswith("❌"))
    total_warning = sum(1 for r in resultados if r['estado'].startswith("⚠️"))
    total_emails = len(resultados)
    dominios_catch_all = sum(1 for d in dominios_validacion.values() if d.get("warning"))

    print("\n=== RESUMEN FINAL ===")
    print(f"📬 Correos evaluados: {total_emails}")
    print(f"✅ Válidos: {total_validos}")
    print(f"❌ Inválidos: {total_invalidos}")
    print(f"⚠️ Warnings: {total_warning} (incluye dominios catch-all)")
    print(f"🌐 Dominios catch-all detectados: {dominios_catch_all}")

def validar_email_con_estado(validador, email, estado_dominio, archivo_validados_ok, archivo_no_validos):
    valido = 0
    guardado = 0
    warning_msg = estado_dominio.get("mensaje") if estado_dominio.get("warning", False) else None

    if not validador.validar_sintaxis(email):
        guardar_linea(archivo_no_validos, email)
        return {"email": email, "estado": "❌ Formato inválido", "motivo": "Sintaxis"}, valido, 1

    if validador.correo_sospechoso(email):
        return {"email": email, "estado": "⚠️ Sospechoso", "motivo": "Usuario sospechoso"}, valido, guardado

    smtp_ok = validador.verificar_smtp(email)
    if smtp_ok is True:
        guardar_linea(archivo_validados_ok, email)
        return {"email": email, "estado": "✅ Válido", "motivo": warning_msg or ""}, 1, guardado
    elif smtp_ok is False:
        guardar_linea(archivo_no_validos, email)
        return {"email": email, "estado": "❌ SMTP rechazado", "motivo": "Servidor lo rechazó"}, valido, 1
    else:
        return {"email": email, "estado": "⚠️ No verificado", "motivo": warning_msg or "No respondió"}, valido, guardado

if __name__ == "__main__":
    main()
