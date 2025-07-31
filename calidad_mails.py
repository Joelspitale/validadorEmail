import dns.resolver
import smtplib
import socket
import re
import os
import difflib
import csv
from functools import lru_cache

class EmailValidator:
    def __init__(self, smtp_from='verificador@tudominio.com', smtp_timeout=10):
        self.smtp_from = smtp_from
        self.smtp_timeout = smtp_timeout
        self.dominios_comunes = [
            "gmail.com", "hotmail.com", "yahoo.com", "outlook.com", 
            "icloud.com", "live.com", "aol.com"
        ]
        self.dominios_bloqueados = {
            "mailinator.com", "tempmail.com", "10minutemail.com", 
            "discard.email", "guerrillamail.com"
        }

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def validar_sintaxis(self, email):
        regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return re.match(regex, email) is not None


    @lru_cache(maxsize=128)
    def obtener_mx(self, dominio):
        try:
            return self.resolver.resolve(dominio, 'MX')
        except Exception:
            return None

    def dominio_tiene_mx(self, dominio):
        registros_mx = self.obtener_mx(dominio)
        return registros_mx is not None and len(registros_mx) > 0

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

    def correo_sospechoso(self, email):
        usuario, _ = email.lower().split('@')
        patrones = ['test', 'demo', 'asdf', 'fake', 'correo', 'prueba']
        return any(p in usuario for p in patrones)

    def validar(self, email):
        if not self.validar_sintaxis(email):
            return {"email": email, "estado": "❌ Formato inválido", "motivo": "El formato del correo no es válido"}

        dominio = email.split('@')[1].lower()

        if dominio in self.dominios_bloqueados:
            return {"email": email, "estado": "❌ Dominio bloqueado", "motivo": "Dominio temporal o de spam"}

        if not self.dominio_tiene_mx(dominio):
            return {"email": email, "estado": "❌ Dominio sin MX", "motivo": "No se encontraron registros MX para el dominio"}

        if self.correo_sospechoso(email):
            return {"email": email, "estado": "⚠️ Correo sospechoso", "motivo": "Nombre de usuario contiene patrones sospechosos"}

        smtp_valido = self.verificar_smtp(email)
        if smtp_valido is True:
            return {"email": email, "estado": "✅ Válido", "motivo": "SMTP confirmó que el correo es válido"}
        elif smtp_valido is False:
            return {"email": email, "estado": "❌ No aceptado por SMTP", "motivo": "El servidor rechazó la dirección"}
        else:
            return {"email": email, "estado": "⚠️ SMTP no verificable", "motivo": "No se pudo conectar con el servidor SMTP o no respondió"}

def cargar_emails(path):
    if not os.path.exists(path):
        print(f"Archivo no encontrado: {path}")
        return []
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def cargar_emails_invalidos(path):
    if os.path.exists(path):
        with open(path, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())
    return set()

def guardar_email_invalido(path, email):
    with open(path, 'a') as f:
        f.write(f"{email}\n")

def exportar_resultados_csv(path, resultados):
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["email", "estado", "motivo"])
        writer.writeheader()
        for fila in resultados:
            writer.writerow(fila)

if __name__ == "__main__":
    archivo_entrada = "emails_a_validar.txt"
    archivo_no_validos = "mail_no_validos.txt"
    archivo_resultados_csv = "resultado_validacion.csv"

    validador = EmailValidator()

    lista_emails = cargar_emails(archivo_entrada)
    emails_invalidos = cargar_emails_invalidos(archivo_no_validos)

    total = 0
    saltados = 0
    validos = 0
    guardados = 0
    resultados = []

    for email in lista_emails:
        total += 1
        email_lower = email.lower()
        if email_lower in emails_invalidos:
            print(f"{email} - ⚠️ Saltado (ya marcado como inválido previamente)")
            saltados += 1
            continue

        resultado = validador.validar(email)
        resultados.append(resultado)
        print(resultado)

        if resultado["estado"] == "✅ Válido":
            validos += 1
        elif resultado["estado"] == "❌ No aceptado por SMTP":
            guardar_email_invalido(archivo_no_validos, email_lower)
            guardados += 1

    exportar_resultados_csv(archivo_resultados_csv, resultados)

    print("\n📊 RESUMEN FINAL")
    print(f"📨 Total de correos analizados: {total}")
    print(f"✅ Correos válidos: {validos}")
    print(f"❌ Correos inválidos guardados: {guardados}")
    print(f"⚠️ Correos saltados (ya marcados): {saltados}")
    print(f"📄 Resultados exportados a: {archivo_resultados_csv}")
