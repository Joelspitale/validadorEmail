Este proyecto es una herramienta que permite analizar y evaluar listas de correos electrónicos para determinar su calidad y confiabilidad.
La idea es tomar un archivo con miles (o millones) de correos y generar un nuevo archivo con información sobre cada uno de ellos, indicando si parecen válidos o si presentan señales de ser falsos, temporales o poco confiables.

🚀 ¿Qué hace el programa?

1. Lee un archivo CSV con correos electrónicos (por defecto emails.csv).

2. Para cada correo, revisa:

    ✅ Si el formato es correcto (ejemplo: usuario@dominio.com).
    
    📮 Si el dominio tiene servidores de correo válidos (registros MX).
    
    🗑️ Si pertenece a un dominio desechable (correos temporales como 10minutemail.com).
    
    🛡️ Si el dominio tiene buena reputación (no está marcado como malware o phishing).
    
    🌍 Si el TLD (ejemplo: .com, .org) es válido según la lista oficial de internet.
    
    ⭐ Si es un proveedor conocido (ejemplo: Gmail, Yahoo, Outlook).
    
    ⚠️ Si la parte antes del @ parece sospechosa (test, noreply, asdf, etc.).
    
    🔀 Si el nombre local es demasiado aleatorio (se mide con entropía).

3. Calcula un puntaje de calidad para cada correo (0 a 100).

4. Guarda los resultados en un nuevo archivo (salida.csv) con todos los detalles y puntuaciones.


📊 Ejemplo de salida

El archivo final incluye columnas como:
  - email: el correo original. 
  - formato_valido: 1 si el formato es correcto, 0 si no.
  - mx_valido: 1 si el dominio realmente recibe correos.
  - no_desechable: 1 si no es temporal.
  - reputacion_ok: 1 si el dominio no es peligroso.
  - proveedor_reconocido: 1 si es Gmail, Yahoo, etc.
  - local_sospechoso: 1 si el nombre parece falso.
  - local_alta_entropia: 1 si el nombre es muy aleatorio.
  - tld_valido: 1 si la terminación del dominio existe.
  - calidad: puntaje final (0 a 100).
  - fecha_validacion: cuándo se hizo la validación.

⚡ Características técnicas:
  - Procesa millones de correos en bloques (chunks) para no quedarse sin memoria.
  - Usa paralelización (varios hilos a la vez) para acelerar validaciones de dominios.
  - Incluye listas locales de dominios sospechosos y desechables.
  - Se conecta a servicios externos como:
  - Google Safe Browsing (para reputación de dominios).
  - Debounce API (para detectar correos temporales).

▶️ Cómo usarlo
- Coloca tu lista de correos en un archivo llamado emails.csv. Dicho archivo tiene que tener las columnas:
  1. email: lista de los correos electronicos a validar.
  2. fuente: String que indica de la fuente de la cual proviene el email.
- Ejecuta el programa.
- Obtendrás un archivo llamado salida.csv con los resultados de las validaciones de cada correo electronico.
