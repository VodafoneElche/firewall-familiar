Novedades de esta versión (0.9.0):

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
