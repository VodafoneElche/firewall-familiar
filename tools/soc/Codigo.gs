/**
 * BUZÓN DEL SOC FAMILIAR  (Google Apps Script, en la cuenta socfamiliar@gmail.com)
 *
 * Recibe lo que mandan los PCs con Firewall Familiar y lo guarda en la carpeta
 * "INFORMES FIREWALL" del Drive, con una subcarpeta por PC:
 *   - informes diarios  ->  "2026-10-23 PORTATIL.md"
 *   - avisos urgentes   ->  "avisos-2026-10.txt"   (y además un correo al momento)
 *   - encendido/apagado ->  "actividad-2026-10.txt"
 *   - "estado.txt" en la carpeta principal: cómo está cada PC ahora mismo.
 * Cada 15 minutos mira si algún PC se ha quedado callado sin despedirse y avisa por correo.
 *
 * Los PCs no tienen la contraseña de Google: solo la dirección de este buzón y una clave.
 */

// ====== AJUSTES (puedes cambiarlos) ======
const CARPETA_ID = '1ro7ba1WGnyEWDXMrOq40Z9rllmwPE_5q';      // carpeta "INFORMES FIREWALL"
const CORREO_AVISOS = 'vodafone.grupomovil.elche@gmail.com';  // a quién llegan los avisos urgentes
const MINUTOS_SILENCIO = 45;     // sin señal durante este tiempo (y sin despedirse) = aviso
const MAX_CORREOS_HORA = 10;     // por PC, para no llenar el correo si algo se vuelve loco
// =========================================

/** PASO 1: ejecuta esta función UNA vez desde el editor (botón ▶ Ejecutar). */
function instalar() {
  const props = PropertiesService.getScriptProperties();
  let secreto = props.getProperty('SECRETO');
  if (!secreto) {
    secreto = Utilities.getUuid().replace(/-/g, '').slice(0, 24);
    props.setProperty('SECRETO', secreto);
  }
  ScriptApp.getProjectTriggers().forEach(t => ScriptApp.deleteTrigger(t));
  ScriptApp.newTrigger('comprobarSilencio').timeBased().everyMinutes(15).create();
  DriveApp.getFolderById(CARPETA_ID); // comprueba que la carpeta existe y pide permiso
  Logger.log('Listo. La CLAVE para poner en cada PC es:  ' + secreto);
  Logger.log('(También la ves en Configuración del proyecto > Propiedades del script > SECRETO)');
}

/** Para comprobar en el navegador que la dirección funciona. */
function doGet() {
  return ContentService.createTextOutput('Buzón del SOC familiar funcionando.');
}

function doPost(e) {
  const secreto = PropertiesService.getScriptProperties().getProperty('SECRETO');
  if (!secreto || !e || !e.parameter || e.parameter.k !== secreto) return texto('no');
  let d;
  try { d = JSON.parse(e.postData.contents); } catch (err) { return texto('mal'); }
  const equipo = limpiar(d.equipo || 'desconocido');
  const datos = d.datos || {};

  const lock = LockService.getScriptLock();
  lock.waitLock(30000);
  try {
    switch (d.tipo) {
      case 'latido':  latido(equipo, d, datos); break;
      case 'adios':   adios(equipo, d, datos); break;
      case 'aviso':   latido(equipo, d, datos.estado || {}); avisos(equipo, d, datos); break;
      case 'informe': latido(equipo, d, {}); informe(equipo, datos); break;
      default: return texto('tipo');
    }
    escribirEstado();
  } finally {
    lock.releaseLock();
  }
  return texto('ok');
}

// ---------------------------------------------------------------------------

function latido(equipo, d, estado) {
  const ahora = new Date();
  const prev = leer(equipo);
  if (!prev) {
    correo(equipo, 'Nuevo PC conectado al SOC: ' + equipo,
      'El PC "' + equipo + '" ha empezado a mandar informes al SOC familiar (versión ' + d.version + ').');
    actividad(equipo, 'Conectado al SOC por primera vez.');
  } else if (prev.estado === 'silencio') {
    correo(equipo, '✔ ' + equipo + ' vuelve a dar señales',
      'El PC "' + equipo + '" vuelve a comunicarse. Estuvo sin señal desde ' + fecha(prev.visto) + '.');
    actividad(equipo, 'Vuelve a dar señales (sin señal desde ' + fecha(prev.visto) + ').');
  } else if (prev.estado === 'parada' || prev.estado === 'desinstalacion') {
    correo(equipo, '✔ ' + equipo + ': la protección vuelve a funcionar',
      'Firewall Familiar vuelve a funcionar en "' + equipo + '".');
    actividad(equipo, 'La protección vuelve a funcionar.');
  } else if (prev.estado !== 'activo') {
    actividad(equipo, 'Encendido / activo (antes: ' + nombreEstado(prev.estado) + ' desde ' + fecha(prev.cambio) + ').');
  }
  const nuevo = {
    estado: 'activo',
    visto: ahora.getTime(),
    cambio: prev && prev.estado === 'activo' ? prev.cambio : ahora.getTime(),
    version: d.version || '',
    modo: estado.modo || (prev && prev.modo) || '',
    protegiendo: estado.protegiendo !== false,
    ventana: !!estado.ventanaAbierta
  };
  if (nuevo.protegiendo === false && prev && prev.protegiendo !== false)
    correo(equipo, '⚠ ' + equipo + ' sin protección', 'El servicio funciona pero no está bloqueando. Revisa el PC.');
  guardar(equipo, nuevo);
}

function adios(equipo, d, datos) {
  const motivo = datos.motivo || 'parada';
  const prev = leer(equipo) || {};
  const ahora = new Date().getTime();
  guardar(equipo, Object.assign(prev, { estado: motivo, visto: ahora, cambio: ahora, version: d.version || prev.version || '' }));
  actividad(equipo, nombreEstado(motivo) + '.');
  if (motivo === 'parada')
    correo(equipo, '⚠ Han PARADO la protección en ' + equipo,
      'Alguien ha parado el servicio de Firewall Familiar en "' + equipo + '" (' + d.hora + ').\n' +
      'Para eso hace falta una cuenta de administrador. Si no has sido tú, revisa ese PC.');
  if (motivo === 'desinstalacion')
    correo(equipo, '⚠ Están DESINSTALANDO Firewall Familiar en ' + equipo,
      'Se está desinstalando Firewall Familiar en "' + equipo + '" (' + d.hora + '). Si no has sido tú, revisa ese PC.');
}

function avisos(equipo, d, datos) {
  const lista = datos.avisos || [];
  if (!lista.length) return;
  const lineas = lista.map(a => a.hora + '  [' + a.tipo + ']  ' + a.texto +
    (a.programa ? '  · Programa: ' + a.programa : '') + (a.ip ? '  · IP: ' + a.ip : ''));
  anadir(carpetaEquipo(equipo), 'avisos-' + mes() + '.txt', lineas.join('\n') + '\n');
  const tipos = [...new Set(lista.map(a => nombreTipo(a.tipo)))].join(', ');
  correo(equipo, '⚠ ' + equipo + ': ' + tipos,
    'Firewall Familiar ha detectado esto en "' + equipo + '":\n\n' + lineas.join('\n\n') +
    '\n\nTodo queda guardado en la carpeta INFORMES FIREWALL / ' + equipo + ' del Drive del SOC.');
}

function informe(equipo, datos) {
  const nombre = limpiar(datos.nombre || ('informe ' + new Date().toISOString().slice(0, 10) + '.md'));
  const carpeta = carpetaEquipo(equipo);
  const viejos = carpeta.getFilesByName(nombre);
  while (viejos.hasNext()) viejos.next().setTrashed(true);
  carpeta.createFile(nombre, datos.contenido || '', MimeType.PLAIN_TEXT);
}

/** Cada 15 minutos: ¿algún PC se ha callado sin despedirse? */
function comprobarSilencio() {
  const lock = LockService.getScriptLock();
  lock.waitLock(30000);
  try {
    const ahora = new Date().getTime();
    todos().forEach(([equipo, st]) => {
      if (st.estado !== 'activo' || ahora - st.visto < MINUTOS_SILENCIO * 60000) return;
      guardar(equipo, Object.assign(st, { estado: 'silencio', cambio: ahora }));
      actividad(equipo, 'SIN SEÑAL desde ' + fecha(st.visto) + ' sin haberse despedido.');
      correo(equipo, '⚠ ' + equipo + ' lleva un rato sin dar señales',
        'El PC "' + equipo + '" no se comunica desde ' + fecha(st.visto) + ' y no avisó de que se apagaba ni se suspendía.\n\n' +
        'Puede ser normal (se quedó sin batería, se cortó el wifi, lo apagaron de golpe) o que alguien haya cortado la protección.\n' +
        'Te avisaré cuando vuelva a dar señales.');
    });
    escribirEstado();
  } finally {
    lock.releaseLock();
  }
}

// ------------------------------- utilidades -------------------------------

function texto(t) { return ContentService.createTextOutput(t); }
function limpiar(s) { return String(s).replace(/[\\\/:*?"<>|\r\n]/g, '_').slice(0, 120); }
function mes() { return Utilities.formatDate(new Date(), 'Europe/Madrid', 'yyyy-MM'); }
function fecha(ms) { return ms ? Utilities.formatDate(new Date(ms), 'Europe/Madrid', 'dd/MM/yyyy HH:mm') : '?'; }

function nombreEstado(s) {
  return ({ activo: 'Activo', apagado: 'Apagado o reiniciado', suspension: 'Suspendido (tapa cerrada o reposo)',
    actualizacion: 'Actualizándose', parada: 'PROTECCIÓN PARADA', desinstalacion: 'DESINSTALANDO',
    silencio: 'SIN SEÑAL' })[s] || s;
}
function nombreTipo(t) {
  return ({ Escaneo: 'posible ataque', Sospechoso: 'programa sospechoso', AccesoRemoto: 'control remoto',
    Alerta: 'aviso de seguridad' })[t] || t;
}

function leer(equipo) {
  const v = PropertiesService.getScriptProperties().getProperty('eq:' + equipo);
  return v ? JSON.parse(v) : null;
}
function guardar(equipo, st) {
  PropertiesService.getScriptProperties().setProperty('eq:' + equipo, JSON.stringify(st));
}
function todos() {
  const p = PropertiesService.getScriptProperties().getProperties();
  return Object.keys(p).filter(k => k.startsWith('eq:')).map(k => [k.slice(3), JSON.parse(p[k])]);
}

function carpetaEquipo(equipo) {
  const raiz = DriveApp.getFolderById(CARPETA_ID);
  const it = raiz.getFoldersByName(equipo);
  return it.hasNext() ? it.next() : raiz.createFolder(equipo);
}

function anadir(carpeta, nombre, contenido) {
  const it = carpeta.getFilesByName(nombre);
  if (it.hasNext()) {
    const f = it.next();
    f.setContent(f.getBlob().getDataAsString('UTF-8') + contenido);
  } else {
    carpeta.createFile(nombre, contenido, MimeType.PLAIN_TEXT);
  }
}

function actividad(equipo, linea) {
  anadir(carpetaEquipo(equipo), 'actividad-' + mes() + '.txt', fecha(new Date().getTime()) + '  ' + linea + '\n');
}

function escribirEstado() {
  const filas = todos().sort().map(([eq, st]) =>
    eq + ':  ' + nombreEstado(st.estado) + '   (última señal ' + fecha(st.visto) + ', versión ' + st.version +
    (st.modo ? ', modo ' + st.modo : '') + (st.ventana ? ', ventana abierta' : '') + ')');
  const txt = 'Estado de los PCs del SOC familiar (' + fecha(new Date().getTime()) + ')\n\n' + filas.join('\n') + '\n';
  const raiz = DriveApp.getFolderById(CARPETA_ID);
  const it = raiz.getFilesByName('estado.txt');
  if (it.hasNext()) it.next().setContent(txt); else raiz.createFile('estado.txt', txt, MimeType.PLAIN_TEXT);
}

function correo(equipo, asunto, cuerpo) {
  const cache = CacheService.getScriptCache();
  const clave = 'mails:' + equipo;
  const n = Number(cache.get(clave) || 0);
  if (n >= MAX_CORREOS_HORA) return;
  cache.put(clave, String(n + 1), 3600);
  MailApp.sendEmail(CORREO_AVISOS, '[SOC familiar] ' + asunto, cuerpo);
}
