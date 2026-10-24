Novedades de esta versión (0.7.0): SOC familiar

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
