# Sentinel Code — Cloudflare Pages

Proyecto organizado a partir del HTML original: interfaz, estilos y lógica del navegador separados. Mantiene el análisis local, las pestañas, los reportes y el historial local.

## Qué incluye

- `public/index.html`: página de entrada.
- `public/assets/styles.css`: estilos originales con mejoras responsive y accesibilidad.
- `public/assets/app.js`: analizador, panel, reglas y asistente.
- `functions/api/ask.js`: endpoint `/api/ask` para conectar el asistente con Anthropic sin exponer la clave al navegador.
- `wrangler.toml`: configuración inicial para Cloudflare Pages.

## Antes de publicar

1. Crea un repositorio en GitHub y sube el contenido de esta carpeta.
2. En Cloudflare, abre **Workers & Pages → Create → Pages → Connect to Git** y selecciona el repositorio.
3. Configura el directorio de salida como `public`. No necesitas comando de build para este proyecto estático.
4. En la configuración del proyecto, añade el secreto `ANTHROPIC_API_KEY` con tu clave de Anthropic. No la pongas en `app.js`, en el HTML ni en GitHub.
5. Añade `ANTHROPIC_MODEL` como variable de entorno con un ID de modelo que esté disponible en tu cuenta de Anthropic. La configuración incluida usa un valor de ejemplo y puede necesitar actualización.
6. Vuelve a desplegar el proyecto y prueba la pestaña **Asistente IA**.

## Prueba local

Requiere Node.js y Wrangler. Desde esta carpeta:

```bash
npm install -D wrangler
npx wrangler pages dev public
```

Para probar la función IA localmente, crea un archivo `.dev.vars` (no lo subas a Git):

```env
ANTHROPIC_API_KEY=tu_clave_de_api
ANTHROPIC_MODEL=ID_DE_MODELO_DISPONIBLE
```

## Datos y privacidad

La aplicación no exige cuenta. El historial, la configuración de reglas y el chat se guardan en `localStorage` del navegador de cada persona; no se sincronizan entre dispositivos ni se comparten entre usuarios. Por eso no se agrega base de datos por ahora. Cuando se consulta la IA, se envían la pregunta, hasta 4,000 caracteres de código y hasta 50 hallazgos al endpoint de Cloudflare y de ahí a Anthropic. No pegues secretos ni código privado que no tengas autorización de compartir.

## Seguridad y limitaciones

- La clave de Anthropic solo debe existir como secreto de Cloudflare.
- El endpoint limita el tamaño del código enviado al modelo y devuelve mensajes de error genéricos.
- Para producción con muchos usuarios, añade controles de uso/rate limiting y revisa costos de Anthropic.
- El analizador usa reglas y comprobaciones estructurales; un resultado sin hallazgos no garantiza que el código sea seguro.
- Esta entrega prepara el proyecto para desplegar; no publica nada por sí sola ni puede configurar las cuentas externas del propietario.
