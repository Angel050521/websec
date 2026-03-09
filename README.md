# WebSec Audit

[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org/)
[![Jest Tests](https://img.shields.io/badge/Tests-185%20Passed-success.svg)](https://jestjs.io/)
[![Coverage](https://img.shields.io/badge/Coverage-94%25-brightgreen.svg)](#)

**Analizador de seguridad web profesional que escanea sitios y genera informes completos de vulnerabilidades con recomendaciones accionables.**

---

## Características Principales

### **Integración con IA** (Característica Única)
- **Prompts optimizados para ChatGPT/Claude** - Cada hallazgo incluye un botón "Copiar prompt" con contexto completo de seguridad.
- **Ahorra horas de investigación** - No necesitas explicar el problema, el prompt ya está optimizado para obtener soluciones exactas.

### **Modos de Escaneo Avanzados**
- **Escaneo Remoto (Pasivo y Activo)** - Analiza cualquier sitio web mediante URL.
- **Auditoría Local (SAST)** - Escanea carpetas de tu PC para detectar secretos y fallos de código antes del despliegue mediante la File System Access API.
- **WebSec Audit Engine v5.0** - Análisis profundo de DNS, SSL/TLS y vulnerabilidades activas mediante backend PHP.

### Análisis Completo de Seguridad
- **Cabeceras HTTP** - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Rutas sensibles expuestas** - .env, .git, backups SQL, phpMyAdmin, paneles admin, archivos de configuración
- **Vulnerabilidades en HTML** - API keys expuestas, tokens, CSRF, mixed content, emails, comentarios sensibles
- **Análisis de cookies** - Verifica flags HttpOnly, Secure, SameSite
- **Scripts de terceros** - Detecta falta de SRI y dependencias externas riesgosas
- **Detección de tecnologías** - Identifica WordPress, Next.js, Nuxt, React, Vue, Laravel, Django, Nginx, Apache, Cloudflare

### Sistema de Puntuación Inteligente
- **Semáforo visual** - Rojo/Amarillo/Verde según la seguridad del sitio
- **Score detallado 5-100** - Con desglose por categoría de vulnerabilidades (mínimo 5 para visibilidad)
- **Fórmula balanceada** - Críticos: -15pts, Altos: -8pts, Medios: -3pts, Bajos: -1pt
- **Checklist interactivo** - Marca correcciones completadas y ve tu progreso en tiempo real

### Exportación Profesional
- **Informes en PDF** - Genera reportes profesionales con un clic
- **Historial de escaneos** - Compara resultados a lo largo del tiempo

---

## Inicio Rápido

### Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Angel050521/websec.git
cd websec

# Instalar dependencias
npm install
```

### Uso

**Opción 1: Servidor local (recomendado)**
```bash
# Con PHP
php -S localhost:8000

# O con npx serve
npx serve
```

**Opción 2: Abrir directamente**
```bash
# Abre index.html en tu navegador
open index.html  # macOS
start index.html # Windows
```

---

## Modos de Operación

La herramienta detecta automáticamente si hay un backend disponible para ofrecer el máximo nivel de detalle:

| Función | Modo Cliente (Navegador) | Modo Backend (PHP/WAMP) |
|---------|-------------------------|-------------------------|
| **Cabeceras HTTP** | ✅ Limitado por CORS | ✅ Completo vía Proxy |
| **Análisis HTML** | ✅ Sí | ✅ Sí |
| **SSL/TLS Profundo** | ❌ No | ✅ Certificado, Protocolos, Expiración |
| **DNS Security** | ⚠️ Básico (vía DoH) | ✅ Real (SPF, DMARC, DNSSEC, CAA) |
| **Port Scanning** | ❌ No | ✅ Escaneo de puertos comunes |
| **Subdominios** | ⚠️ 30 comunes (DoH) | ✅ 70+ comunes (DNS real) |
| **Escaneo Activo** | ❌ No | ✅ XSS, SQLi, LFI, SSRF, Redirect |
| **WordPress CVEs** | ⚠️ Detección básica | ✅ Análisis de plugins y core |
| **Auditoría SAST** | ✅ Sí (Acceso local) | ✅ Sí |

### Ejemplo de Uso

1.Ingresa la URL del sitio: `https://ejemplo.com`
2.Haz clic en "Escanear →"
3.Espera ~20 segundos mientras se analiza
4.Revisa los hallazgos organizados por severidad
5.**Usa el botón "Copiar prompt"** en cualquier hallazgo para obtener ayuda de IA
6.Exporta el informe en PDF si lo necesitas

---

## Ejemplo de Prompt Generado para IA

Cuando encuentras un problema, el botón **"Copiar prompt"** genera automáticamente:

```
Tengo un problema de seguridad web en mi sitio https://ejemplo.com que necesito corregir.

HALLAZGO [ALTO]: Content-Security-Policy ausente

DESCRIPCION: No se detectó cabecera CSP. Esto permite ataques XSS y carga 
de recursos no autorizados.

EVIDENCIA:
No se encontró la cabecera Content-Security-Policy en la respuesta HTTP

CORRECCION RECOMENDADA: Define directivas CSP para restringir qué recursos 
puede cargar la página.

Por favor:
1. Explica exactamente que archivo(s) necesito modificar
2. Dame el codigo o configuracion exacta para implementar la correccion
3. Si es una cabecera HTTP, dame la configuracion para Nginx, Apache y Cloudflare
4. Verifica que la correccion no rompa funcionalidad existente
```

**Simplemente pega esto en ChatGPT, Claude o cualquier IA y obtendrás soluciones específicas y listas para implementar.**

---

## Qué Analiza

| Categoría | Checks Realizados |
|-----------|-------------------|
| **Cabeceras HTTP** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS, X-Powered-By |
| **Rutas Sensibles** | .env, .git/HEAD, backups SQL, phpMyAdmin, adminer, paneles admin, config.json, debug endpoints |
| **HTML** | API keys (Stripe, AWS, Google), tokens, CSRF, mixed content, emails expuestos, comentarios sensibles |
| **Cookies** | HttpOnly, Secure, SameSite flags |
| **Scripts** | Subresource Integrity (SRI), CDNs públicos, dependencias externas |
| **Tecnologías** | WordPress, Next.js, Nuxt, React, Vue, Angular, Laravel, Django, Rails, Nginx, Apache, Cloudflare |
| **Otros** | robots.txt, iframes externos, target="_blank" sin noopener, formularios sin CSRF |

---

## Testing

Mantenemos una suite de pruebas robusta para asegurar la precisión:

```bash
# Ejecutar 185 tests unitarios
npm test

# Ver reporte de cobertura (94%+)
npm run test:coverage

# Tests en modo watch
npm run test:watch
```

---

## Tecnologías

- **Frontend**: Vanilla JavaScript
- **Testing**: Jest con cobertura del 94%
- **PDF**: jsPDF para exportación de informes
- **Backend opcional**: PHP proxy para bypass CORS


## Aviso Legal

Esta herramienta ofrece dos niveles de análisis según el modo de uso:

1. **Análisis Pasivo (Modo Cliente)**: Fetch de cabeceras públicas y verificación de rutas.
2. **Análisis Activo (Modo Backend)**: Realiza pruebas controladas con payloads seguros de vulnerabilidades comunes (XSS, SQLi, etc.).

**IMPORTANTE:** Úsala exclusivamente en sitios que te pertenezcan o para los que tengas autorización explícita. El escaneo de sitios de terceros sin permiso puede ser ilegal y poco ético. El autor no se hace responsable del uso indebido de esta herramienta.

Esta herramienta ha sido creada con fines educativos y de auditoría ética.

---

## Licencia

ISC License - Ver [LICENSE](LICENSE) para más detalles.

---

## Apoya el Proyecto

Si te resulta útil, considera:
-**Darle una estrella en GitHub**
-Reportar bugs o sugerir mejoras
-Hacer un fork y contribuir
-Compartirlo con otros desarrolladores
-Dejar feedback en Issues

---

## Autor

Desarrollado por **[Angel050521](https://github.com/Angel050521)**

---

**¿Encontraste útil esta herramienta? ¡Dale una estrella al repo!**
