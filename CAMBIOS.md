Novedades de esta versión (0.6.3):

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
