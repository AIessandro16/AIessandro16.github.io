# EVOLVA — Proyecto final avanzado

Aplicación web responsive de EVOLVA para emprendimientos pequeños de Ecuador. Incluye identidad de marca, servicios y tarifas, diagnóstico interactivo, formulario que guarda solicitudes en SQLite, panel privado y asistente de orientación con IA.

## Estructura

- `frontend/`: sitio público, catálogo, diagnóstico, chat y panel de administración.
- `backend/server.js`: API Express, validaciones, límites de solicitudes, sesiones firmadas, SQLite e integración Gemini.
- `config.js` dentro de `frontend/`: URL del backend; vacía cuando frontend y API comparten dominio.
- `.env.example`: variables requeridas para ejecutar y publicar el backend.

## Ejecutar localmente

Requiere Node.js 20.6 o superior.

1. Instala dependencias: `npm install`.
2. Copia `.env.example` como `.env`.
3. Reemplaza `ADMIN_PASSWORD` con una contraseña única de al menos 12 caracteres y `SESSION_SECRET` con una cadena aleatoria larga (por ejemplo, generada con `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`).
4. Para activar respuestas con IA, crea una clave Gemini y asígnala a `GEMINI_API_KEY`. El servidor la guarda en el entorno y no la expone al navegador.
5. Ejecuta `npm start` y abre `http://localhost:3000`. La administración está en `/admin.html`.

Las solicitudes recibidas se guardan en `evolva.sqlite`. El chat necesita `GEMINI_API_KEY`; sin ella informa claramente que no está configurado. La API Gemini usa `generateContent` y el modelo puede cambiarse mediante `GEMINI_MODEL`.

## Publicación

La ruta del proyecto exige GitHub Pages. Pages puede alojar los archivos de `frontend/`, pero no ejecuta Express ni SQLite. Publica el frontend en Pages y despliega `backend/server.js` en un servicio Node compatible, como Render, Railway o un servidor propio:

1. Configura las variables del backend a partir de `.env.example`. En `FRONTEND_ORIGIN`, coloca el origen completo de Pages, sin ruta, por ejemplo `https://usuario.github.io`.
2. Usa HTTPS para la API. Para conservar las consultas después de reinicios o redeploys, monta almacenamiento persistente y asigna su ruta a `DB_PATH`; el disco local de muchos servicios se reinicia o es efímero.
3. En `config.js`, coloca el origen HTTPS de la API (sin `/` final). Los formularios y el panel envían credenciales de sesión al backend autorizado.
4. Publica los archivos estáticos de esta carpeta en GitHub Pages y comprueba el sitio y la API desde la URL pública.

No subas `.env`, claves de IA, contraseñas, bases SQLite ni datos de clientes a GitHub. La primera vez que se configure el backend, crea una contraseña de administración fuerte y almacena el secreto de sesión en el gestor de variables del hosting.

## Entregables de la ruta

| Requisito | Incluido | Pendiente fuera del código |
| --- | --- | --- |
| Marca y home responsive | Sí | Revisión final desde la URL pública |
| Catálogo de servicios | Sí | Confirmar precios antes de ofrecerlos |
| Formulario de contacto real | Sí, persiste en SQLite | Desplegar API con disco persistente |
| Admin con inicio de sesión | Sí, token firmado de 8 horas y panel de lectura | Definir credenciales en el hosting |
| IA personalizada | Sí, asistente Gemini con contexto EVOLVA y tarifas | Configurar clave de API y presupuesto del proveedor |
| Repositorio GitHub / 15 commits | Código listo para inicializar en Git | Conectar al repositorio del equipo y construir historial real de al menos 15 commits |
| Publicación en GitHub Pages | Frontend compatible | Activar Pages y publicar el frontend; alojar la API aparte |

El admin muestra hasta 200 consultas recientes; no incluye función de borrado ni correo automático. El formulario guarda el consentimiento junto con la solicitud. Antes de recopilar datos de clientes reales, completa y publica una política de privacidad que identifique responsable, finalidad, conservación y canal de derechos conforme a la normativa aplicable en Ecuador.
