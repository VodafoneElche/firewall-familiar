# Firewall Familiar

Firewall para Windows 11 inspirado en **Sygate Personal Firewall** (2003-2008): ver en tiempo real
todo el tráfico que entra y sale del ordenador, programa a programa, y poder bloquearlo a mano o con reglas.

Pensado para uso familiar: sencillo, eficaz y sin publicidad.

## Plan

| Paso | Qué incluye | Estado |
|------|-------------|--------|
| 1. Monitor | Gráficas de tráfico en tiempo real, programas en ejecución (también ocultos y servicios) con memoria, CPU y tráfico, conexiones abiertas, consola de mensajes | ✅ En pruebas |
| 2. Bloqueo y reglas | Permitir / Preguntar / Bloquear por programa, aviso "este programa quiere conectarse", Bloquear todo, reglas por puerto e IP ordenadas por prioridad | Pendiente |
| 3. Registros y avisos | Visor de paquetes, detección de escaneo de puertos, avisos de procesos ocultos o sin firma | Pendiente |
| 4. Instalación | Instalador, arranque con Windows, icono junto al reloj, contraseña | Pendiente |

## Cómo probar la versión actual (paso 1)

1. En GitHub, abre la pestaña **Actions**, entra en la última ejecución verde de **Compilar**
   y descarga **FirewallFamiliar-win-x64** (abajo, en *Artifacts*).
2. Descomprime el .zip en una carpeta, por ejemplo `C:\FirewallFamiliar`.
3. Ejecuta `FirewallFamiliar.exe`. Windows pedirá permiso de administrador: es necesario para ver el tráfico de cada programa.
   Si aparece "Windows protegió su PC", pulsa *Más información* → *Ejecutar de todas formas* (el programa aún no está firmado).

Esta versión **no bloquea nada**, así que es seguro probarla en cualquier equipo.

### Qué significa cada color y tipo

- **Con ventana**: programas que ves en pantalla.
- **Servicio**: servicios registrados de Windows o de otros programas.
- **Sistema**: componentes de Windows sin ventana.
- **OCULTO** (fondo naranja): procesos sin ventana, que no son servicios y no están en `C:\Windows`.
  No significa que sean malos (muchos son actualizadores o iconos de la bandeja), pero son los que conviene revisar.

## Tecnología

- C# / .NET 8 / WPF
- Tráfico por programa: eventos de red del kernel de Windows (ETW), mediante `Microsoft.Diagnostics.Tracing.TraceEvent`
- Conexiones: `GetExtendedTcpTable` / `GetExtendedUdpTable` (lo mismo que `netstat -ano`)
- Bloqueo (paso 2): WinDivert

## Compilar a mano

```
dotnet publish src/FirewallFamiliar/FirewallFamiliar.csproj -c Release -r win-x64 --self-contained true -o publish
```
