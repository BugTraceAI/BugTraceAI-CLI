# Release-candidate third-party register — BugTraceAI-CLI

> **Fecha de corte:** 2026-09-02  
> **Estado:** **CANDIDATO / PENDIENTE DE CIERRE**. Este registro acompaña al
> candidato local y no autoriza por sí solo una publicación. Las versiones,
> hashes y SBOM de los artefactos finales deben verificarse antes del GO.

## 1. Alcance y limitaciones demostradas

Este registro documenta lo observado en \`pyproject.toml\`, Dockerfiles, Compose,
código y assets del candidato. Todavía no identifica versiones instaladas,
hashes de ruedas/binarios, capas OCI ni dependencias transitivas reales.

El JSON \`SBOM-CLI-cyclonedx-20260902.json\` enumera 42 componentes manuales y no contiene grafo de dependencias. Sus propias notas declaran que parte de rangos mínimos, que los valores instalados pueden ser distintos y que omite transitivas. Es una pista de investigación, no un SBOM de release.

La fuente de verdad declarada para dependencias de producto es \`pyproject.toml\`. \`requirements.txt\` se usa durante el build Docker y debe reconciliarse con el manifiesto antes de cerrar el candidato. Si difieren, el SBOM y los avisos se derivan del artefacto realmente instalado, no de la intención del manifiesto.

## 2. Límites de distribución a inventariar por separado

| Unidad posible | Estado en la referencia | Registro final requerido |
|---|---|---|
| Árbol fuente / paquete Python | 34 dependencias directas declaradas | SBOM de fuente con versiones resueltas, transitivas y textos de licencia aplicables. |
| Imagen CLI principal | Dockerfile propio, herramientas nativas, navegador y paquetes OS | SBOM OCI por digest y plataforma, incluyendo filesystem final y capas. |
| Imagen MCP alternativa | \`Dockerfile.mcp\` separado | SBOM propio sólo si se publica o se soporta esta imagen. |
| Descargas bajo demanda | Imágenes Docker y modelo de embeddings | Inventario de componentes externos/dinámicos, fijados o explícitamente no soportados. |
| Datos, listas, templates y assets | Varios ficheros con origen incompleto | Ledger de procedencia y decisión de inclusión/exclusión. |

## 3. Dependencias Python directas declaradas

La tabla transcribe especificaciones de \`pyproject.toml\`. **No son versiones resueltas y la columna de licencia se deja intencionadamente sin conclusión.** Debe verificarse cada distribución exacta y plataforma efectivamente usada.

| Paquete | Especificación declarada | Uso aparente |
|---|---|---|
| \`typer\` | \`>=0.9.0,<1.0\` | CLI |
| \`rich\` | \`>=13.0.0,<14.0\` | Salida de terminal |
| \`httpx\` | \`>=0.25.0,<1.0\` | HTTP |
| \`aiohttp\` | \`>=3.9.0,<4.0\` | HTTP asíncrono |
| \`aiofiles\` | \`>=23.0.0,<25.0\` | I/O asíncrono |
| \`pydantic\` | \`>=2.0.0,<3.0\` | Modelos/configuración |
| \`pydantic-settings\` | \`>=2.0.0,<3.0\` | Configuración |
| \`python-dotenv\` | \`>=1.0.0,<2.0\` | Entorno |
| \`loguru\` | \`>=0.7.0,<1.0\` | Logging |
| \`sqlmodel\` | \`>=0.0.16,<1.0\` | Datos |
| \`sqlalchemy\` | \`>=2.0.0,<3.0\` | Datos |
| \`sqlparse\` | \`>=0.4.4,<1.0\` | SQL |
| \`openai\` | \`>=1.0.0,<3.0\` | Proveedor LLM |
| \`google-generativeai\` | \`>=0.8.0,<1.0\` | Proveedor LLM |
| \`PyJWT\` | \`>=2.8.0,<3.0\` | Flujos JWT funcionales |
| \`cryptography\` | \`>=41.0.0,<47.0\` | Criptografía |
| \`playwright\` | \`>=1.40.0,<2.0\` | Automatización navegador |
| \`fastapi\` | \`>=0.100.0,<1.0\` | API |
| \`uvicorn\` | \`>=0.20.0,<1.0\` | ASGI |
| \`websockets\` | \`>=12.0,<17.0\` | WebSocket |
| \`mcp\` | \`>=1.20.0,<2.0\` | MCP |
| \`lancedb\` | \`>=0.4.0,<1.0\` | Vector DB runtime |
| \`jinja2\` | \`>=3.1.0,<4.0\` | Templates |
| \`markdown\` | \`>=3.5.0,<4.0\` | Markdown |
| \`beautifulsoup4\` | \`>=4.12.0,<5.0\` | HTML |
| \`PyYAML\` | \`>=6.0.0,<7.0\` | YAML |
| \`tenacity\` | \`>=8.0.0,<10.0\` | Reintentos |
| \`filelock\` | \`>=3.12.0,<4.0\` | Locks |
| \`networkx\` | \`>=3.0,<4.0\` | Grafos |
| \`psutil\` | \`>=5.9.0,<7.0\` | Sistema |
| \`opentelemetry-api\` | \`>=1.20.0,<2.0\` | Observabilidad |
| \`opentelemetry-sdk\` | \`>=1.20.0,<2.0\` | Observabilidad |
| \`torch\` | \`>=2.0.0\` | Embeddings |
| \`sentence-transformers\` | \`>=2.0.0,<6.0\` | Embeddings |

No se pueden reutilizar como hechos los copyright, versiones o licencias que contenía el borrador anterior. Se han verificado varios errores concretos: \`httpx\` no debe describirse como Apache-2.0, \`openai\` no como MIT, \`tenacity\` no como MIT, \`filelock\` 3.12.0 no como MPL-2.0 y \`cryptography\` requiere evaluar el wheel y sus componentes nativos. La corrección apropiada es extraer datos desde los artefactos congelados, no reemplazar un dato manual por otro dato manual.

## 4. Componentes incorporados durante build o presentes en la imagen CLI

| Componente / clase | Evidencia | Riesgo o dato pendiente |
|---|---|---|
| Bases Docker | \`golang:1.24-alpine\`, \`alpine:3.19\`, \`docker:cli\`, \`python:3.10-slim\` | Tags mutables/sin digest y sistemas con múltiples licencias por capa. |
| GoSpider | \`go install github.com/jaeles-project/gospider@latest\` | El borrador previo confundía este proyecto con ProjectDiscovery. Fijar módulo, tag/commit y checksum. |
| Nuclei | Binario \`3.3.7\` descargado desde release | Registrar hash oficial y plataforma; templates se actualizan dinámicamente. |
| Docker CLI | Copiado desde etapa \`docker:cli\` | Es cliente como fallback, no Docker-in-Docker; inventariar binario y licencia real. |
| Paquetes Debian | \`gcc\`, \`nmap\`, \`curl\` y transitivas | Inventariar por imagen. Nmap tiene licencia propia (NPSL), no resumirla como MIT/Apache. |
| SQLMap | \`pip install sqlmap\` sin versión | Se obtiene desde PyPI; no afirmar artefacto GitHub ni licencia final sin verificar paquete exacto. |
| Playwright/Chromium | \`playwright install chromium\` y \`install-deps\` | Navegador y dependencias OS requieren inventario de imagen, no una única etiqueta de licencia. |
| Fuzzers Go | Cuatro módulos internos compilados | No tienen \`LICENSE\` individual ni dependencias de terceros declaradas en sus \`go.mod\`; no inventar avisos inexistentes. |
| Nuclei templates | \`nuclei -update-templates || true\` | Descarga flotante; no existe el directorio cacheado que afirmaba el borrador. Fijar revisión o excluir. |
| Datos copiados por \`COPY . .\` | Contexto completo no excluido por \`.dockerignore\` | Revisar staging exacto, no sólo Git. |

\`Dockerfile.mcp\` es una imagen distinta: parte de \`python:3.11-slim\`, instala paquetes APT y añade \`mcp[cli]>=1.0.0\` y \`fastmcp>=0.1.0\`, ausentes del manifiesto/SBOM actual. El compose canónico utiliza el Dockerfile principal para API y MCP; aun así, si se publica o soporta \`Dockerfile.mcp\`, necesita su propio inventario y SBOM.

## 5. Componentes dinámicos, datos y activos pendientes

| Clase | Hallazgo | Decisión necesaria antes de release |
|---|---|---|
| Imágenes bajo demanda | Fallbacks a Nuclei, SQLMap y GoSpider en imágenes externas con tags flotantes | Tratar como externas/no redistribuidas, fijar digest o deshabilitar la ruta. |
| Modelo | \`BAAI/bge-small-en-v1.5\` descargado en runtime | Registrar revisión, hashes, model card/licencia y si se cachea o sólo se descarga. |
| Payloads | Fuentes declaradas para open redirect/prototype pollution; listas XSS sin procedencia clara | Verificar licencia/origen, atribuir o excluir. |
| Benchmark | \`bugtrace/benchmark/ground_truth/bugstore.json\` declara derivación de BugStore | Confirmar permiso/licencia y distribución o excluir. |
| Datos generados | \`learned_breakouts.json\` está ignorado por Git pero puede entrar en Docker | Excluir del staging o documentar origen, contenido y permiso. |
| Assets | \`logo.png\`, \`ClawdBot.png\` | Cadena de titularidad/licencia antes de afirmar copyright. |
| Servicios | Proveedores LLM, Hugging Face, registros Docker, etc. | Documentar como servicios externos; no confundir con contenido redistribuido. |

## 6. Criterios para convertir este registro en aviso de release

No se crea \`THIRD_PARTY_NOTICES.md\` final hasta que, para cada artefacto que realmente se distribuya, exista una fila con nombre, tipo, versión/commit o digest, plataforma, PURL cuando aplique, hash, licencia SPDX o \`NOASSERTION\`, texto de aviso exigible, fuente, modo de distribución, obligación, decisión y evidencia de revisión.

El paquete final debe separar como mínimo:

\`\`\`text
THIRD_PARTY_NOTICES.md        # Sólo avisos y resumen verificados
LICENSES/                     # Textos de licencia que deban acompañar
sbom/source.cdx.json          # Árbol/paquete congelado
sbom/image-cli-<digest>.cdx.json
sbom/image-mcp-<digest>.cdx.json   # Sólo si se distribuye
EXTERNAL_COMPONENTS.md        # Servicios, descargas bajo demanda y límites
\`\`\`

Hasta entonces, este documento es evidencia de **NO-GO** para el gate de terceros, no una conclusión de incompatibilidad general entre Apache-2.0 y el código propio de BugTraceAI.
