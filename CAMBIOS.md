Novedades de esta versión (0.11.5):

- El tráfico por programa vuelve a verse aunque otro programa tenga cogido el "NT Kernel Logger" de Windows (pasó en el portátil de Jose en la red de la oficina: abajo ponía "solo totales (sin detalle por programa)"). Ahora la ventana usa su propia sesión de eventos de red, igual que el vigilante de subidas, y solo si falla prueba la del kernel.

De la 0.11.4:

- Medición de red diaria (lo pidió Jose): una vez al día, cuando el PC está en la red de casa y lleva 15 minutos encendido, el servicio mide bajada, subida y latencias. Si algo sale mal, lo repite a la media hora; si vuelve a salir mal, es un PROBLEMA DE RED y se ve EN ROJO:
  - en la barra de abajo de la ventana principal (pinchando se abre la ventana Router),
  - en la lista nueva "Mediciones de velocidad" de la ventana Router (también guarda las que hagas a mano),
  - en el registro y en el informe (apartado 11, tabla de los últimos 14 días).
- Cuenta como problema: sin Internet; el router no contesta o tarda más de 30 ms; latencia de más de 60 ms o muy irregular (más de ±30 ms); la latencia sube más de 200 ms al usar la línea; bajada o subida por debajo del 40 % de lo normal EN ESE PC (lo normal se saca de sus propias mediciones, porque un portátil por Wi-Fi no va como uno por cable). No manda correo al SOC.
- Fuera de casa no se mide solo. Historial en C:\ProgramData\FirewallFamiliar\velocidad.json.

De la 0.11.3:

- Medir velocidad: la latencia ya no incluye el tiempo que tarda el servidor de pruebas en contestar (Cloudflare lo indica en cada respuesta), solo el viaje por la red, como fast.com. En la 0.11.2 salía 40 ms en el portátil de Jose cuando fast.com daba 6 ms; las velocidades sí coincidían (471/514 frente a 490/560 Mbps).

De la 0.11.2:

- Ventana Router: botón "Medir velocidad". Mide bajada, subida, latencia a Internet (y su variación), latencia con la línea llena (bajando y subiendo: si sube mucho, las videollamadas y juegos van a tirones) y latencia al router. Solo cuando se pulsa. Usa el servidor de pruebas de Cloudflare (speed.cloudflare.com): solo viajan datos de relleno, nada del PC.

De la 0.11.1:

- Router fuera de casa (como pidió Jose): la primera red que ve cada PC es la "red de casa" (se puede cambiar con el botón "Esta es la red de casa" de la ventana Router). En casa se avisa de todo. Fuera (oficina, casa de amigos...) no se avisa de aparatos nuevos ni de lo que hacen los aparatos de otros: solo de lo crítico para este PC (un puerto abierto por UPnP hacia este PC por un programa sin firma o desconocido, o en un puerto de control remoto, y Telnet abierto en el router). La ventana y el informe dicen en qué red está el PC.

De la 0.11.0:

- Botón nuevo "Router" (y menú "Router y red de casa..."): revisa el router desde dentro de casa, sin salir a Internet y sin probar ninguna contraseña. Idea sacada del programa Bastion (github.com/0xCodez/bastion), hecha desde cero en Firewall Familiar:
  - Puertas del router que contestan: Telnet, SSH, FTP, disco compartido, página de configuración sin cifrar, gestión remota del operador (TR-069, normal en routers del operador)... con lo que conviene hacer en cada caso.
  - Puertos abiertos en el router por UPnP: qué aparato y qué programa (si es este PC) tiene una puerta abierta desde Internet.
  - Aparatos que este PC ve en la red, con el fabricante (lista oficial del IEEE dentro del programa, Assets/fabricantes.txt, generada por tools/fabricantes.py). Las direcciones privadas de móviles y tablets se marcan como tales.
  - Cifrado del Wi-Fi: avisa si va abierto, con WEP, WPA antiguo o TKIP.
- Vigilante del router en el servicio, cada 15 minutos (puertas del router cada 6 horas). Avisos urgentes al SOC: aparato nuevo en la red de casa; puerto abierto por UPnP hacia este PC por un programa sin firma o desconocido, o hacia cualquier aparato en un puerto de control remoto; puerta peligrosa nueva en el router. Cada red se recuerda por su router, así que un portátil fuera de casa aprende la red nueva sin avisar de todo.
- Informe: apartado nuevo "11. Router y red de casa"; el registro completo pasa a ser el 12.

De la 0.10.5:

- PDF Familiar (PDF Casero), el editor de PDF de casa, ya no sale como riesgo: ni el programa, ni su instalador, ni el archivo temporal del instalador. Se reconoce por su nombre y por los datos que lleva dentro (fabricante "PDF Familiar"). En la columna Firma sale "✔ PDF Familiar (de casa)".
- Firewall Familiar tampoco se marca a sí mismo como "sin firma" en la lista de arranque ni en las "conexiones periódicas" (su latido al SOC).

De la 0.10.4:

- Limpieza separada en dos sitios, como pidió Jose:
  - "Programas que arrancan solos" ya solo tiene programas que existen. Cada fila tiene casilla y hay "Marcar todos" (no marca lo de Windows). "Desactivar", "Volver a activar" y "Eliminar" funcionan con todas las marcadas a la vez (o con la fila pinchada si no hay ninguna marcada).
  - "Restos de programas" tiene ahora dos listas, cada una con sus casillas y "Marcar todas": 1) entradas de arranque de programas que ya no existen (como la tarea de CCleaner), que se eliminan guardando antes una copia; 2) carpetas que han quedado, que van a la Papelera.

De la 0.10.3:

- Chequeo de seguridad: nueva comprobación "DNS del PC". Avisa si un PC tiene las DNS puestas a mano (por ejemplo, las de AdGuard sin filtro), porque así se salta el filtro familiar del router (OpenDNS FamilyShield). Explica cómo dejarlas en Automático. Las VPN y las máquinas virtuales no cuentan. Si un PC que estaba bien pasa a tener DNS a mano, llega un aviso al SOC.

De la 0.10.2:

- Limpieza > Programas que arrancan solos:
  - Al pinchar una línea, abajo sale qué es, por qué está marcada y QUÉ CONVIENE HACER.
  - Botón nuevo "Eliminar entrada" para quitar para siempre restos (como la tarea de CCleaner que ya no existe), directivas impuestas al navegador o entradas que no quieras. Antes se guarda una copia en C:\ProgramData\FirewallFamiliar\copias-limpieza (los .reg se vuelven a poner con doble clic).
  - "Abrir ubicación" también funciona cuando el archivo ya no existe: abre el Programador de tareas, el Editor del registro en la clave exacta o la carpeta de Inicio.
  - Menos avisos falsos: los comandos sencillos de Windows (borrar archivos al reiniciar), las apps de la Tienda como Teams y las tareas de Windows sin archivo ya no salen en naranja (las de Windows solo con "Mostrar también lo de Microsoft").
- Limpieza > Restos de programas: casilla "Marcar todos".

De la 0.10.1:

- Aviso de la puerta trasera de la extensión Claude Code 2.1.313 (troyanizada en Open VSX y en la tienda de Cursor el 29/10/2026). Va con las listas de programas espía, en Assets/indicadores-extra.txt:
  - La IP de los atacantes (134.209.82.225) queda BLOQUEADA siempre.
  - Cada 2 minutos se buscan sus rastros: la clave "svc-telemetry" en .ssh\authorized_keys de cada usuario, la tarea programada SysMon, sysmon.cmd en la carpeta Inicio, los archivos .smt, .smtk y smt.cmd, y la carpeta de la extensión 2.1.313 en VS Code, Cursor, VSCodium o Windsurf. Si aparece algo, aviso urgente al SOC.
  - El informe diario tiene un apartado nuevo: "Huellas de puertas traseras y programas espía en el disco".
- Arreglado: en las gráficas de velocidad los números de la escala (1 Gbps, 100 M...) se montaban unos encima de otros. Si la gráfica es baja, ahora se pone uno de cada dos.

De la 0.10.0:

- Nuevo botón LIMPIEZA (también en Seguridad > Limpieza y revisión del PC). Ideas sacadas de Glary Utilities y Wise Care 365, hechas desde cero y sin nada que se conecte a Internet:
  - Programas que arrancan solos: inicio de Windows, carpetas de Inicio, tareas programadas, servicios, extensiones del menú contextual, protocolos de red, "secuestros" de programas y ajustes impuestos al navegador. Cada uno con su firma digital; en naranja lo que conviene mirar (sin firma en carpeta rara, firma no válida, scripts, directivas del navegador). Se puede desactivar y volver a activar (no se borra nada).
  - Restos de programas desinstalados: carpetas que no son de ningún programa instalado y llevan 60 días sin cambiar, y carpetas de programas basura conocidos (SweetLabs, OneLaunch, WaveBrowser...). Se marcan a mano y van a la Papelera.
  - Salud de los discos (SMART): estado, temperatura, desgaste del SSD, errores y espacio libre.
  - Chequeo de seguridad: Firewall de Windows, antivirus, Windows Update, Escritorio remoto, control de cuentas y herramientas bloqueadas (Administrador de tareas, Editor del registro).
- Nuevo VIGILANTE DEL SISTEMA en el servicio: cada 2 minutos mira si algo nuevo se ha puesto a arrancar solo. Aviso urgente al SOC si no tiene firma, está en una carpeta rara o es un script; también si se impone una página o extensión al navegador. Además avisa si un disco puede fallar o si algo del chequeo de seguridad pasa de bien a mal.
- El informe diario tiene una sección nueva "10. Arranque, restos de programas, discos y chequeo de seguridad".
- Las gráficas de velocidad van ahora en bits por segundo (Kbps, Mbps, Gbps), como la velocidad de la fibra, con escala fija hasta 1 Gbps. Cada raya es ×10, así se ve igual una web que una descarga grande. El título enseña la velocidad del momento.

De la 0.9.1:

- SOC familiar: menos avisos falsos de "SIN SEÑAL" en los sobremesa. Al apagar, Windows corta la red antes de que el firewall pueda despedirse. Ahora la despedida se manda al cerrar la sesión, que es antes, y se le da más tiempo. Si el PC no se apaga, a los 90 segundos vuelve a salir como activo.

De la 0.9.0:

- Nuevo: listas públicas de PROGRAMAS ESPÍA, las mismas que usan Amnesty International (MVT), Citizen Lab y ECHAP: Pegasus, Predator, Candiru, FinFisher, stalkerware (apps para espiar a otra persona) y otras. En total, 6.344 dominios, 686 direcciones IP y 3.461 huellas de archivos.
  - Las IPs de la lista quedan BLOQUEADAS siempre, por encima de cualquier regla.
  - Si el PC busca en Internet el nombre de uno de esos servidores, llega un aviso urgente y sus direcciones se bloquean.
  - Si un programa que se conecta a Internet es un archivo espía conocido (por su huella SHA-256), llega un aviso urgente.
  - Las apps de control parental (Microsoft Family, Life360, Qustodio, Kaspersky Safe Kids...) no cuentan: se pueden usar en casa a propósito.
  - Las listas van dentro del programa y se renuevan con cada versión. Se descargan de versiones fijas y comprobadas (tools/indicadores.py).

De la 0.8.4:

- El instalador de las actualizaciones de Firewall Familiar ya no sale como "programa sospechoso" mientras se instala.

De la 0.8.3:

- Arreglado un falso "POSIBLE ATAQUE" del router: si un programa de este PC (por ejemplo Tailscale, que pide puertos al router) habla con el router, lo que el router contesta llega a muchos puertos temporales del PC y se tomaba por un escaneo. Ahora las respuestas del router y de los aparatos de casa a los puertos temporales (49152 en adelante) no cuentan como escaneo.

De la 0.8.2:

- SOC familiar: si el servicio no consigue conectar con el buzón (pasaba en algún PC con la conexión segura de Google), los avisos, latidos e informes se mandan a través del icono del reloj, que usa la conexión del usuario. Así los avisos urgentes llegan igual.
- Si el antivirus detecta algo justo antes de apagar el PC, el aviso se manda al volver a encenderlo (antes se perdía).
- Cuando falla la conexión con el buzón, el registro apunta el motivo exacto que da Windows.

De la 0.8.1:

- El detector de control remoto reconoce también Zoho Assist (ZA_Connect, agent.exe de ZohoMeeting...) y cualquier programa que viva en la carpeta de una herramienta de control remoto conocida, aunque tenga un nombre genérico.
- En el informe, el resumen por programa enseña también la carpeta de cada programa.

De la 0.8.0:

- Nuevo: vigilancia de SUBIDAS GRANDES. El servicio cuenta lo que cada programa envía a Internet. Si uno sube más de 1 GB en una hora (o más de 50 MB siendo un programa sin firma o en una carpeta rara), llega un aviso urgente. Las nubes y copias de seguridad (OneDrive, Google Drive, Dropbox...) solo se anotan.
- Nuevo: detección de programas que "llaman a casa": conexiones al mismo sitio a intervalos casi exactos, como hacen los programas espía. Aviso urgente si el programa no tiene firma; todos salen en el informe diario.
- El informe tiene una sección nueva "8. Conexiones periódicas y subidas grandes".

De la 0.7.7:

- Los avisos de Trend Micro llegan resumidos: qué amenaza, cuántas veces y con qué usuario, en vez de las líneas en bruto.

De la 0.7.6:

- El informe lee también los registros propios de Trend Micro: virus, spyware, comportamiento sospechoso, webs bloqueadas, análisis y conexión con su consola.
- Si Trend Micro apunta un virus, spyware o comportamiento sospechoso, llega un aviso urgente al momento.

De la 0.7.5:

- El informe trae una sección nueva "Antivirus": qué antivirus tiene el PC (Trend Micro, Defender...), si están activos y al día, y sus eventos en los registros de Windows (detecciones, análisis, errores).
- Si el antivirus detecta un virus, llega un aviso urgente al momento (y correo del SOC).

De la 0.7.4:

- Arreglado: correo falso de "lleva un rato sin dar señales" al cerrar la tapa del portátil. En los portátiles modernos Windows no avisa de que se suspende; ahora el servicio vigila la pantalla y la tapa, y se despide antes de que se corte la red.

De la 0.7.3:

- Icono nuevo junto al reloj: flechas más gordas en semicírculo alrededor del escudo (verde = entran datos, roja = salen).

De la 0.7.2:

- La ventana completa se abre sin el aviso de Windows ("¿Quieres permitir que esta aplicación...?") en las cuentas de administrador. La abre el servicio, ya con permisos. En las cuentas estándar (los niños) sigue pidiendo la contraseña del administrador.

De la 0.7.1:

- Arreglado: falso "POSIBLE ATAQUE" del router justo al abrir la tapa del portátil (respuestas viejas que llegan al despertar).
- El informe enseña también desde qué puertos y con qué protocolo llegan los intentos de entrada.

De la 0.7.0: SOC familiar

- Nuevo menú Seguridad > "SOC familiar...": cada PC manda al Google Drive del SOC un informe diario, avisos urgentes al momento (con correo) y una señal cada 15 minutos. Si un PC se calla sin avisar de que se apaga o se suspende, llega un correo.
- Nuevo detector de control remoto: avisa si se abre AnyDesk, TeamViewer, RustDesk, VNC, ScreenConnect y similares, si un programa se conecta a los puertos que usan, si entra una conexión desde Internet o si está activado el Escritorio remoto de Windows.
- Aviso si alguien prueba 5 contraseñas incorrectas en un minuto en el icono.
- El servicio avisa al SOC si lo paran o desinstalan.
- En el informe, las respuestas tardías de servidores (webs, DNS) ya no salen como intentos de entrada.

De la 0.6.3:

- Arreglado: falsos avisos de "POSIBLE ATAQUE" al pulsar Bloquear todo. Eran respuestas de servidores con los que el PC ya estaba hablando (DNS, webs). Ya no cuentan como escaneo.

De la 0.6.2:

- Arreglado: "No se pudo añadir el filtro Permitir tráfico interno (0x8032000C)" al abrir la ventana con el servicio funcionando. Ventana y servicio usan ahora cada uno su propia subcapa de filtros.
- El servicio comprueba de otra forma que la ventana tiene permisos de administrador.

De la 0.6.1:

- Arreglado: la detección de escaneos de puertos no se activaba (Windows no deja cambiar esa opción desde la conexión del cortafuegos; ahora se usa una aparte).

De la 0.6.0:

- Nuevo servicio de Windows "Firewall Familiar": bloquea desde que arranca el PC, aunque nadie abra el programa y aunque el usuario no sea administrador. Guarda los registros, detecta escaneos y programas sospechosos y se actualiza solo.
- Icono junto al reloj para todos los usuarios, también en cuentas estándar: flechas de tráfico, avisos, preguntas del modo "Preguntar" y cambio de modo (con contraseña).
- La ventana completa pide permiso de administrador al abrirse. Mientras está abierta, es ella la que bloquea; al cerrarla, el servicio vuelve a encargarse solo.
- Ya no hace falta la tarea "Abrir al iniciar Windows": se quita sola.
