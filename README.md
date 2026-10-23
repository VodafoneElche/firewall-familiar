# Firewall Familiar

Firewall para Windows 11 inspirado en **Sygate Personal Firewall** (2003-2008): ver en tiempo real
todo el tráfico que entra y sale del ordenador, programa a programa, y poder bloquearlo a mano o con reglas.

Pensado para uso familiar: sencillo, eficaz y sin publicidad.

## Plan

| Paso | Qué incluye | Estado |
|------|-------------|--------|
| 1. Monitor | Gráficas de tráfico en tiempo real, programas en ejecución (también ocultos y servicios) con memoria, CPU y tráfico, conexiones abiertas, consola de mensajes | ✅ Hecho |
| 2. Bloqueo y reglas | Permitir / Preguntar / Bloquear por programa, aviso "este programa quiere conectarse", Bloquear todo, reglas por puerto e IP ordenadas por prioridad | ✅ Hecho |
| 3. Registros y avisos | Visor de registros (30 días), detección de escaneo de puertos, comprobación de firma digital, avisos de procesos sospechosos | ✅ Hecho |
| 4. Instalación | Instalar desde el propio programa, arranque con Windows, icono junto al reloj, contraseña, informe para análisis, actualización automática | 🧪 En pruebas |

## Cómo usar el bloqueo (paso 2)

Arriba a la derecha está el **Modo de seguridad**:

- **Sin preguntas**: aplica tus reglas y deja pasar todo lo demás. Es el modo con el que arranca la primera vez.
- **Preguntar (como Sygate)**: cuando un programa sin regla intenta salir a Internet, se bloquea y aparece una
  ventana abajo a la derecha preguntando si se le permite. Los programas de Windows (`C:\Windows`) se permiten solos.
- **Bloquear todo**: corta la red al momento (también con el botón *Bloquear todo*).

Clic derecho en un programa → **Permitir / Preguntar / Bloquear**. El botón **Reglas** abre la lista de reglas
por programa y las **reglas avanzadas** (por puerto, IP, protocolo y dirección), que se aplican de arriba abajo.

Las reglas se guardan en `C:\ProgramData\FirewallFamiliar\reglas.json`.

**Seguridad**: los bloqueos solo existen mientras Firewall Familiar está abierto. Si se cierra o falla,
Windows quita todos sus filtros y la red vuelve a funcionar normal. El Firewall de Windows sigue activo como siempre.

## Registros y avisos (paso 3)

- **Firma digital**: la columna *Firma* comprueba de verdad cada programa con Windows (firma dentro del .exe o en
  los catálogos de Windows). ✔ válida, ✖ sin firma, ⚠ firma NO válida (archivo modificado o certificado no fiable).
- **Programas sospechosos** (fondo naranja fuerte y aviso en la consola): ocultos y sin firma, ocultos y metidos en
  carpetas raras (temporales, Descargas, raíz de AppData...), o con firma no válida.
- **Escaneo de puertos**: si un mismo equipo intenta entrar por 10 o más puertos distintos en un minuto, sale un aviso
  "POSIBLE ATAQUE". La gráfica *Historial de ataques* muestra los intentos de entrada bloqueados (por Firewall Familiar
  o por el Firewall de Windows).
- **Registros**: botón *Registros*. Dos tipos: *Seguridad* (todo lo de la consola) y *Tráfico* (cada conexión nueva y
  cada intento bloqueado). Se guardan 30 días en `C:\ProgramData\FirewallFamiliar\registros` y se pueden exportar a Excel.
  Doble clic en una línea abre su ficha.

## Instalación y protección (paso 4)

- **Instalador**: `FirewallFamiliar-Instalar.exe` (Siguiente → Instalar). Lo deja en `C:\Program Files\Firewall Familiar`,
  crea accesos directos y registra el **servicio de Windows "Firewall Familiar"**.
  Se desinstala desde Configuración → Aplicaciones. Si Windows lo bloquea la primera vez: clic derecho → Propiedades → *Desbloquear*.
- **Servicio** (desde la 0.6.0): bloquea desde que arranca el PC, con cualquier usuario (también cuentas estándar),
  guarda los registros, detecta escaneos y programas sospechosos, y se actualiza solo.
- **Icono junto al reloj** (`FirewallFamiliar.exe --icono`, para todos los usuarios): el escudo FF entre una flecha verde
  (entran datos) y una roja (salen datos). Rojo entero = todo bloqueado. Desde ahí se contesta en modo "Preguntar"
  y se cambia el modo (con contraseña).
- **Ventana completa**: pide permiso de administrador. Mientras está abierta, ella aplica las reglas; al cerrarla,
  el servicio retoma el bloqueo.
- **Seguridad → Poner contraseña**: pide la contraseña para cerrar el programa, cambiar reglas o modo, y (si quieres)
  para pulsar "Permitir" en las preguntas. Bloquear todo siempre se puede sin contraseña.
- **Registros → Preparar para análisis**: crea en `C:\ProgramData\FirewallFamiliar\informes` (y en el Escritorio) un informe `.md` con avisos, resumen por programa y por IP
  (con su dueño), intentos de entrada, horas de uso y reglas, listo para arrastrarlo al chat de Claude.

## Cómo probar la versión actual

1. En GitHub, abre la pestaña **Actions**, entra en la última ejecución verde de **Compilar**
   y descarga **FirewallFamiliar-win-x64** (abajo, en *Artifacts*).
2. Descomprime el .zip en una carpeta, por ejemplo `C:\FirewallFamiliar`.
3. Ejecuta `FirewallFamiliar.exe`. Windows pedirá permiso de administrador: es necesario para ver el tráfico de cada programa.
   Si aparece "Windows protegió su PC", pulsa *Más información* → *Ejecutar de todas formas* (el programa aún no está firmado).

Por defecto arranca en modo **Sin preguntas** y no bloquea nada hasta que pongas una regla o cambies de modo.

### Qué significa cada color y tipo

- **Con ventana**: programas que ves en pantalla.
- **Servicio**: servicios registrados de Windows o de otros programas.
- **Sistema**: componentes de Windows sin ventana.
- **⚠ SOSPECHOSO** (naranja fuerte): oculto y además sin firma o en una carpeta rara. Mira su ficha.
- **OCULTO** (fondo naranja): procesos sin ventana, que no son servicios y no están en `C:\Windows`.
  No significa que sean malos (muchos son actualizadores o iconos de la bandeja), pero son los que conviene revisar.

## Tecnología

- C# / .NET 8 / WPF
- Tráfico por programa: eventos de red del kernel de Windows (ETW), mediante `Microsoft.Diagnostics.Tracing.TraceEvent`
- Conexiones: `GetExtendedTcpTable` / `GetExtendedUdpTable` (lo mismo que `netstat -ano`)
- Bloqueo: Windows Filtering Platform (WFP), la misma tecnología del Firewall de Windows, sin drivers de terceros.
  Declaraciones generadas con `Microsoft.Windows.CsWin32` a partir de los metadatos oficiales de Microsoft.

## Compilar a mano

```
dotnet publish src/FirewallFamiliar/FirewallFamiliar.csproj -c Release -r win-x64 --self-contained true -o publish
```
