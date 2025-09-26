import pandas as pd
import dns.resolver
import requests
from email_validator import validate_email, EmailNotValidError
import re
from datetime import datetime
import time
from math import log2
from concurrent.futures import ThreadPoolExecutor, as_completed  # <-- agregado para paralelizar

# ---------------- CONFIG ----------------
KNOWN_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com","icloud.com","live.com","msn.com"}
DISPOSABLE_LOCAL = {"tempmail.com", "mailinator.com", "10minutemail.com","knilok.com","yopmail.com","rapidletter.net","jkotypc.com","heheee.com"}
SUSPICIOUS_LOCAL = {"test", "asdf", "noreply", "fake", "example","NOTIENE","hola","noInfo","noposee","nose","sindatos","sincorreo","sincuenta"}
CHUNK_SIZE = 100000
MAX_WORKERS = 5  # <-- agregado: maximo de hilos para I/O (según tu RAM de 4 GB)

SAFE_BROWSING_API_KEY = "API_KEY_GOOGLE"
SAFE_BROWSING_ENDPOINT = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

URL_TLDS= "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

# Cache por dominio
mx_cache = {}
disposable_cache = {}
reputation_cache = {}
tlds_cache = None

# ---------------- UTILIDADES ----------------

def cargar_tlds():
    global tlds_cache
    if tlds_cache is not None:
        return tlds_cache
    response = requests.get(URL_TLDS)
    tlds = set()
    for line in response.text.splitlines():
        if not line.startswith("#"):
            tlds.add(line.strip().lower())
    tlds_cache = tlds
    return tlds


def shannon_entropy(s: str) -> float:
    if len(s) == 0:
        return 0
    prob = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * log2(p) for p in prob)

def local_alta_entropia(local: str, threshold: float = 4.0) -> bool:
    pocos_vocales = sum(c in "aeiyouAEIYOU" for c in local) < 2
    return shannon_entropy(local) > threshold  or len(set(local)) <= 3 or pocos_vocales

# ---------------- VALIDACIONES ----------------

def es_local_valido(local: str) -> bool:
    if not re.match(r'^[a-zA-Z0-9._-]+$', local):
        return False
    if not (1 <= len(local) <= 40):
        return False
    if local[0] in '._-%':
        return False
    if '..' in local:
        return False
    if local.endswith('.'):
        return False
    return True

def validar_email_y_extraer(email: str):
    try:
        v = validate_email(email, check_deliverability=False)
        local = v.local_part
        domain = v.domain
        if not es_local_valido(local):
            return False, None, None
        return True, local, domain
    except EmailNotValidError:
        return False, None, None


def validar_mx(dominio: str) -> bool:
    if dominio in mx_cache:
        return mx_cache[dominio]
    try:
        registros = dns.resolver.resolve(dominio, "MX")
        mx_cache[dominio] = len(registros) > 0
    except:
        mx_cache[dominio] = False
    return mx_cache[dominio]

def es_desechable_api(dominio: str, email: str = None) -> bool:
    """
    Retorna True si el dominio/email es desechable.
    Primero revisa cache, luego lista local, luego consulta API Debounce.
    """
    dominio = dominio.lower()

    # Cache
    if dominio in disposable_cache:
        return disposable_cache[dominio]

    # Lista local
    if dominio in DISPOSABLE_LOCAL:
        disposable_cache[dominio] = True
        return True

    # Verificación vía API Debounce (si no se proporciona email, se usa dominio)
    if email is None:
        email = f"test@{dominio}"

    try:
        response = requests.get(f"https://disposable.debounce.io/?email={email}", timeout=5)
        response.raise_for_status()
        data = response.json()
        is_disposable = data.get("disposable", False)  # True/False
        disposable_cache[dominio] = is_disposable
        return is_disposable
    except:
        # fallback: si falla la API, usar lista local
        disposable_cache[dominio] = False
        return False

def reputacion_dominio(dominio: str) -> bool:
    if dominio in reputation_cache:
        return reputation_cache[dominio]
    try:
        payload = {
            "client": {"clientId": "email_quality_checker", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"http://{dominio}"}]
            }
        }
        response = requests.post(SAFE_BROWSING_ENDPOINT, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            reputation_cache[dominio] = "matches" not in data
            return reputation_cache[dominio]
    except:
        pass
    reputation_cache[dominio] = True  # fallback: confiable
    return True

def local_sospechoso(local: str) -> bool:
    return any(pat.lower() in local.lower() for pat in SUSPICIOUS_LOCAL)

def tld_valido(domain: str) -> bool:
    tld = domain.split('.')[-1].lower()
    valid_tlds = cargar_tlds()
    return tld in valid_tlds, tld

def proveedor_reconocido(domain: str) -> bool:
    return domain in KNOWN_PROVIDERS

# ---------------- NUEVO: validaciones por dominio en paralelo ----------------
def validar_dominio_completo(dominio: str) -> dict:
    """Valida un dominio una sola vez (MX, desechable, reputación)."""
    
    # Si es un proveedor reconocido, lo marcamos como no desechable sin consultar API
    if proveedor_reconocido(dominio):
        return {
            "mx_valido": 1 if validar_mx(dominio) else 0,
            "no_desechable": 1,  # 🔹 siempre 1 para dominios conocidos
            "reputacion_ok": 1 if reputacion_dominio(dominio) else 0,
            "proveedor_reconocido": 1,
        }

    # Si no es reconocido, sí hacemos la verificación completa
    return {
        "mx_valido": 1 if validar_mx(dominio) else 0,
        "no_desechable": 0 if es_desechable_api(dominio) else 1,
        "reputacion_ok": 1 if reputacion_dominio(dominio) else 0,
        "proveedor_reconocido": 0,
    }

# ---------------- PIPELINE DE VALIDACIÓN ----------------
def procesar_chunk(chunk: pd.DataFrame):
    # 1. Vectorizamos validaciones baratas primero (local, formato, tld)
    resultados = []
    validaciones = [validar_email_y_extraer(e) for e in chunk['email']]  # vectorizado por lista
    chunk['formato_valido'] = [1 if v[0] else 0 for v in validaciones]
    chunk['local'] = [v[1] for v in validaciones]
    chunk['domain'] = [v[2] for v in validaciones]

    # 2. Obtenemos dominios únicos válidos
    dominios_unicos = chunk.loc[chunk['domain'].notnull(), 'domain'].unique().tolist()

    # 3. Resolvemos dominios en paralelo
    dominio_resultados = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:  # <-- agregado paralelización
        future_to_domain = {executor.submit(validar_dominio_completo, d): d for d in dominios_unicos}
        for future in as_completed(future_to_domain):
            dominio = future_to_domain[future]
            try:
                dominio_resultados[dominio] = future.result()
            except Exception:
                dominio_resultados[dominio] = {"mx_valido":0,"no_desechable":0,"reputacion_ok":0,"proveedor_reconocido":0}

    # 4. Construimos resultados fila a fila
    for _, row in chunk.iterrows():
        res = {
            "email": row['email'],
            "local_part": row['local'],
            "domain": row['domain'],
            "tld": None,
            "formato_valido": row['formato_valido'],
            "mx_valido": 0,
            "no_desechable": 0,
            "reputacion_ok": 0,
            "local_sospechoso": 0,
            "local_alta_entropia": 0,
            "tld_valido": 0,
            "proveedor_reconocido": 0,
            "calidad": 0,
            "fuente": row.get('fuente', None),
            "fecha_validacion": datetime.utcnow().isoformat()
        }
        dom = row['domain']
        if dom and dom in dominio_resultados:
            res.update(dominio_resultados[dom])

        # local sospechoso / entropía
        if res["local_part"]:
            if local_sospechoso(res["local_part"]):
                res["local_sospechoso"] = 1
            if local_alta_entropia(res["local_part"]):
                res["local_alta_entropia"] = 1

        # tld
        if dom:
            is_tld_valido, tld = tld_valido(dom)
            res["tld"] = tld
            if is_tld_valido:
                res["tld_valido"] = 1

        # --- scoring ---
        score = 0
        if res["formato_valido"]: score += 35
        if res["mx_valido"]: score += 25
        if res["no_desechable"]: score += 15
        if res["reputacion_ok"]: score += 10
        if res["tld_valido"]: score += 5
        if res["proveedor_reconocido"]: score += 5
        if res["local_sospechoso"]: score -= 10
        if res["local_alta_entropia"]: score -= 15
        res["calidad"] = min(score, 100)

        resultados.append(res)
    return pd.DataFrame(resultados)

# ---------------- PROCESAR CSV ----------------
def procesar_csv(entrada='emails.csv', salida='salida.csv'):  # <-- cambiado: salida parquet
    start_time = time.time()
    first_chunk = True
    for i, chunk in enumerate(pd.read_csv(entrada, chunksize=CHUNK_SIZE)):
        df_resultados = procesar_chunk(chunk)
        df_resultados.to_csv(salida, 
                            index=False, 
                            mode="w" if first_chunk else "a",  # escribir o anexar
                            header=first_chunk,                # solo escribir encabezado la primera vez
                            encoding="utf-8"                   # opcional, asegura compatibilidad
                            )
        print(f"Procesado chunk {i} con {len(chunk)} registros...")
    elapsed = time.time() - start_time
    print(f"✅ Archivo final generado: {salida}")
    print(f"⏱ Tiempo total de ejecución: {elapsed:.2f} segundos")

# ---------------- MAIN ----------------
if __name__ == '__main__':
    procesar_csv()
