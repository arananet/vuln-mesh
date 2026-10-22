# vuln-mesh: migración de Railway a Cloudflare Containers

Estado: auditoría de código completada el 2026-10-22 y forma decidida ese
mismo día. Este documento se escribe antes que el código, según la regla de
Spec-Driven Development de Edu. La migración prepara el repo; el despliegue
(crear el proyecto en Workers Builds, mintear el token, enganchar el dominio)
queda para el día del despliegue y se lista al final.

## Hallazgos de la auditoría (verificados en el código)

- Hay dos servicios pensados para Railway: el backend
  (`Dockerfile.backend`, uvicorn con `vuln_mesh.dashboard.server:app`,
  puerto 8000) y un frontend nginx (`Dockerfile.frontend` en la raíz y una
  segunda copia en `services/frontend/`) que sirve los estáticos del
  dashboard e inyecta `BACKEND_URL` en un `/config.js` en tiempo de arranque.
- El servicio frontend es redundante por diseño del propio repo:
  - `vuln_mesh/dashboard/app.py` (FastAPI) sirve todo el producto: `GET /`
    devuelve `index.html`, monta los estáticos en `/static`
    (`StaticFiles`), y expone `/api/*` y el stream SSE `/events`.
  - El propio `railway.toml` lo dice: el backend sirve la API y la UI, y el
    servicio frontend separado es opcional.
  - `static/app.js` calcula su base como
    `window.APP_CONFIG?.backendUrl || ''`, es decir, sin `config.js` el
    dashboard llama al API en el mismo origen. `index.html` carga
    `/config.js` con `onerror` tolerado: el archivo puede no existir.
- La IA entra solo por `vuln_mesh/adapters/cloudflare.py`, que hoy llama
  directo a la REST de Workers AI
  (`api.cloudflare.com/client/v4/accounts/{id}/ai/run/{model}`) con
  `CF_ACCOUNT_ID` y `CF_API_TOKEN`, y parsea `result.response`.
  `config/default.yaml` usa el proveedor cloudflare en los tiers triage,
  verifier y exploit. Los adaptadores de Anthropic existen comentados como
  opción de mayor calidad y quedan fuera de esta migración.

## Forma elegida: un solo servicio en Cloudflare

- **El backend va a Cloudflare Containers con su `Dockerfile.backend` tal
  cual**, detrás de un Worker envoltorio fino en `cf-worker/` con una clase
  Container (Durable Object) que reenvía todo el tráfico al contenedor
  (patrón ya usado en protocol-guard y en Geo Agentic Auditor).
- **El frontend nginx NO se migra.** El contenedor sirve la UI, los
  estáticos, el API y el stream SSE en un único origen, que es exactamente
  el modo en que la app ya funciona cuando `BACKEND_URL` está vacío.
  Los Dockerfile de frontend y el Procfile se quedan en el repo para uso
  local y para Railway; no se borra nada.

Justificación, por la regla de Edu de quedarnos con lo más eficiente:

- Un solo contenedor en vez de dos servicios: menos piezas, un solo
  arranque en frío y un solo dominio.
- Desaparece la URL pública separada del backend y con ella la necesidad de
  `BACKEND_URL`, de `config.js` generado y de abrir CORS entre orígenes.
- Sirviendo los estáticos desde el propio FastAPI no hay que duplicar la
  carpeta `vuln_mesh/dashboard/static` en un directorio de assets del
  Worker, que es la fuente de deriva clásica entre lo que se desarrolla y lo
  que se sirve.

Alternativa descartada: que el Worker sirva los estáticos como assets y
reenvíe solo `/api/*` y `/events` al contenedor. Encaja peor:
`index.html` referencia `/static/*` en rutas absolutas (el montaje de
FastAPI) y la sesión del dashboard se valida en el middleware del backend;
repartir el servicio entre Worker y contenedor duplica esa lógica sin
ahorrar el contenedor, que sigue haciendo falta para el API.

## Flujo resultante

Navegador → dominio del Worker → `getContainer` (singleton) → uvicorn en el
puerto 8000 → FastAPI sirve `/`, `/static/*`, `/api/*` y `/events` (SSE).
La instancia es singleton a propósito: el estado del pipeline vive en
memoria dentro del proceso (`PipelineTracker`) y la app rechaza escaneos
concurrentes con un 409, así que escalar a varias instancias rompería el
stream de eventos, no ayudaría.

Datos de la instancia elegida: `standard-2`, porque el trabajo pesado no es
servir HTTP sino compilar el código objetivo con gcc/clang y ejecutar los
binarios con ASan dentro del propio contenedor (el `Dockerfile.backend` ya
instala gcc, g++, clang y git). `sleepAfter` de 30 minutos: los escaneos
son largos y, mientras el usuario mira el dashboard, el polling y el SSE
generan tráfico de sobra; el límite solo muerde si un escaneo queda sin
nadie mirando más de 30 minutos, limitación conocida y aceptada.

## La IA entra por el AI Gateway compartido

- `vuln_mesh/adapters/cloudflare.py` cambia su URL base a la del gateway
  compartido `arananet-ai-gateway`:
  `https://gateway.ai.cloudflare.com/v1/{account_id}/arananet-ai-gateway/workers-ai/{model}`.
  El endpoint workers-ai del gateway devuelve el mismo contrato nativo
  (`success`, `result.response`, `errors`), así que el parseo no cambia.
- Cada llamada lleva la cabecera `cf-aig-metadata` con
  `{"app": "vuln-mesh", "env": "prod"}` para la observabilidad por app en
  los logs del gateway, igual que el resto de apps de Edu.
- `CF_API_TOKEN` y `CF_ACCOUNT_ID` se siguen leyendo de variables de entorno
  en runtime, sin valores en el repo. El nombre del gateway se puede
  sobreescribir con `CF_AI_GATEWAY` y el entorno de la metadata con
  `CF_AI_ENV`, ambos con el valor compartido por defecto.
- Ningún otro adaptador cambia: anthropic y ollama quedan como están.

## Bindings y secretos (día del despliegue, nunca en el repo)

El envoltorio reenvía al contenedor, solo si el binding existe en el Worker:

| Variable | Tipo | Notas |
| --- | --- | --- |
| `CF_ACCOUNT_ID` | binding | Identificador de la cuenta, lo lee el adaptador |
| `CF_API_TOKEN` | secreto | Token dedicado que se mintea el día del despliegue, con alcance Workers AI y solo esta cuenta, en proceso y sin mostrar el valor, como se hizo con Geo |
| `ADMIN_USER` | binding | Usuario del login del dashboard |
| `ADMIN_PASS` | secreto | Obligatoria en producción: si está vacía la app no pide autenticación y el dashboard queda abierto |
| `DATABASE_URL` | secreto, opcional | Sin ella la app degrada: `/api/scans` e historial devuelven vacío y `/api/health` marca `db: false` |
| `SCAN_TARGET`, `SCAN_CONFIG` | binding, opcional | Auto-escaneo al arrancar, herencia de la época Railway |

`PORT` lo fija el envoltorio a 8000, que es donde escucha uvicorn y el
`defaultPort` de la clase Container.

## Persistencia y límites aceptados

- El disco del contenedor es efímero: los clones temporales, los informes
  generados y cualquier archivo local desaparecen al rearrancar. La
  persistencia real del historial solo existe con una `DATABASE_URL`
  externa (un Postgres fuera de Cloudflare), que es trabajo posterior y
  queda fuera de alcance aquí.
- Un escaneo en curso se pierde si la instancia rearranca (despliegue,
  caída o fin del `sleepAfter`). Es el mismo compromiso ya aceptado en Geo
  con su estado en disco.

## Fuera de alcance

- Crear el proyecto en Workers Builds, mintear el token, cargar los
  bindings y enganchar el dominio (checklist del día del despliegue, abajo).
- Borrar o tocar los Dockerfile de frontend, el combinado, el Procfile o
  los `railway.toml`: siguen siendo la vía local y de Railway.
- Provisionar un Postgres ni migrar el historial.
- Cambiar los modelos de los tiers ni reactivar los adaptadores de
  Anthropic.
- Tocar la lógica del pipeline, el ranker, el oráculo o los agentes.

## Verificación tras el despliegue

1. `GET /` devuelve 200 con el HTML del dashboard y sin cabeceras
   `x-railway-*`.
2. `GET /api/health` devuelve `status: ok`.
3. Con `ADMIN_PASS` cargada, el login responde y sin token las rutas
   protegidas devuelven 401.
4. `GET /events` se mantiene abierto y emite el estado inicial (SSE de
   verdad a través del proxy del contenedor, no una respuesta cortada).
5. Un escaneo corto contra una URL de git pública completa el pipeline y
   los logs del AI Gateway muestran las llamadas con la metadata
   app=vuln-mesh.
6. El oráculo compila y ejecuta un objetivo mínimo con ASan dentro del
   contenedor.
