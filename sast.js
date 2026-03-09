'use strict';

const IGNORE_DIRS = ['.git', 'node_modules', 'vendor', 'dist', 'build', '.next', '.nuxt', 'coverage'];
const TEXT_EXTENSIONS = ['.js', '.jsx', '.ts', '.tsx', '.php', '.py', '.html', '.css', '.env', '.json', '.xml', '.yml', '.yaml', '.txt', '.md', '.sql'];

const SAST_RULES = [
    {
        id: 'HARDCODED_SECRET_AWS',
        name: 'AWS Access Key',
        regex: /AKIA[0-9A-Z]{16}/g,
        sev: 'C',
        desc: 'Se detectó una clave de AWS hardcodeada en el código fuente.',
        fix: 'Mueve esta clave a variables de entorno (.env) y usa process.env u obténla desde la configuración del servidor.'
    },
    {
        id: 'HARDCODED_SECRET_STRIPE',
        name: 'Stripe Secret Key',
        regex: /sk_(?:live|test|mock)_[a-zA-Z0-9]{20,}/g,
        sev: 'C',
        desc: 'Se detectó una clave secreta de Stripe hardcodeada.',
        fix: 'Las claves secretas NUNCA deben estar en el código. Múevela al backend o a variables de entorno.'
    },
    {
        id: 'HARDCODED_PASSWORD',
        name: 'Contraseña en código',
        regex: /(?:password|passwd|pwd|contrasena)\s*[:=]\s*['"]([^'"]{4,})['"]/gi,
        sev: 'H',
        desc: 'Se detectó una posible contraseña hardcodeada.',
        fix: 'Extrae esta contraseña a la configuración externa o un gestor de secretos.'
    },
    {
        id: 'SQL_INJECTION',
        name: 'Posible Inyección SQL (Concatenación)',
        regex: /SELECT.+FROM.+WHERE.+(?:'|"|`)\s*\+\s*[a-zA-Z0-9_]+/gi,
        sev: 'H',
        desc: 'Se detectó concatenación de strings en una consulta SQL. Esto es altamente vulnerable a inyecciones SQL.',
        fix: 'Usa consultas parametrizadas (Prepared Statements) o un ORM seguro.'
    },
    {
        id: 'DOM_XSS',
        name: 'Riesgo de DOM XSS',
        regex: /\.innerHTML\s*=\s*[^'"]/gi,
        sev: 'M',
        desc: 'Uso de innerHTML asignando un valor dinámico. Si el valor proviene del usuario, puede resultar en XSS.',
        fix: 'Usa .textContent o sanitiza el valor con una librería como DOMPurify antes de insertarlo.'
    },
    {
        id: 'EVAL_USAGE',
        name: 'Uso de eval()',
        regex: /eval\s*\(/g,
        sev: 'H',
        desc: 'El uso de eval() es extremadamente peligroso si procesa datos no confiables.',
        fix: 'Evita usar eval(). Usa JSON.parse() u otras alternativas seguras.'
    }
];

async function startLocalScan() {
    try {
        if (!window.showDirectoryPicker) {
            alert('Tu navegador no soporta la API de File System Access. Por favor, usa una versión reciente de Chrome o Edge.');
            return;
        }

        const dirHandle = await window.showDirectoryPicker();

        // UI Preparation
        document.getElementById('hero-section').style.display = 'none';
        const progSec = document.getElementById('progress-section');
        progSec.style.display = 'flex';
        document.getElementById('progress-log').innerHTML = '';
        setProgress(10, 'Analizando archivos locales...');
        addLog(`<span class="log-info">Iniciando escaneo estático (SAST) en la carpeta local: ${dirHandle.name}</span>`);

        const findings = [];
        let filesScanned = 0;
        let sensitiveFilesFound = 0;
        let ruleHits = 0;

        async function scanDirectory(currentHandle, path = '') {
            for await (const entry of currentHandle.values()) {
                if (entry.kind === 'directory') {
                    if (IGNORE_DIRS.includes(entry.name)) {
                        addLog(`<span class="log-dim">Ignorando directorio: ${path}/${entry.name}</span>`);
                        continue;
                    }
                    await scanDirectory(entry, path + '/' + entry.name);
                } else if (entry.kind === 'file') {
                    const ext = entry.name.includes('.') ? entry.name.substring(entry.name.lastIndexOf('.')).toLowerCase() : '';

                    // Sensitive files check
                    const fileAbsPath = path + '/' + entry.name;

                    // Cross-check with WebScanner's SENSITIVE_PATHS + hardcoded SAST checks
                    const isSensitiveExt = ['.env', '.env.local', 'wp-config.php', 'config.js', '.htpasswd', 'id_rsa', 'database.sqlite'].includes(entry.name);
                    const sensitiveMatch = typeof SENSITIVE_PATHS !== 'undefined' ? SENSITIVE_PATHS.find(sp => fileAbsPath.endsWith(sp.p)) : null;

                    if (isSensitiveExt || sensitiveMatch) {
                        sensitiveFilesFound++;
                        const label = sensitiveMatch ? sensitiveMatch.label : `Archivo crítico`;
                        const sev = sensitiveMatch ? sensitiveMatch.sev : 'C';

                        findings.push({
                            sev: sev,
                            title: `${label} expuesto y detectado en Local: ${fileAbsPath}`,
                            desc: 'Este tipo de archivo suele contener credenciales, tokens o configuraciones críticas. Si el servidor web no está bien configurado y el archivo se sube a internet, la aplicación entera puede ser comprometida.',
                            code: `Ruta Local: ${fileAbsPath}`,
                            fix: `Asegúrate de que "${entry.name}" no se transfiera al servidor público y que esté protegido en tu servidor web. Agregalo al archivo .gitignore.`
                        });
                        addLog(`<span class="log-err">¡Alerta! Archivo crítico encontrado: ${fileAbsPath}</span>`);
                    }

                    // Content scanning
                    if (TEXT_EXTENSIONS.includes(ext) || entry.name.startsWith('.env')) {
                        filesScanned++;
                        if (filesScanned % 20 === 0) {
                            setProgress(10 + Math.min(80, (filesScanned / 200) * 80), `Analizando archivos... (${filesScanned})`);
                        }

                        try {
                            const fileHandle = await currentHandle.getFileHandle(entry.name);
                            const file = await fileHandle.getFile();
                            if (file.size > 2 * 1024 * 1024) { // Skip files > 2MB
                                addLog(`<span class="log-dim">Saltando archivo grande (>2MB): ${path}/${entry.name}</span>`);
                                continue;
                            }
                            const text = await file.text();

                            // Apply custom SAST rules
                            for (const rule of SAST_RULES) {
                                // Reset regex state
                                rule.regex.lastIndex = 0;
                                const matches = text.match(rule.regex);
                                if (matches) {
                                    const uniqueMatches = [...new Set(matches)];
                                    uniqueMatches.forEach(match => {
                                        ruleHits++;
                                        findings.push({
                                            sev: rule.sev,
                                            title: `${rule.name} en ${path}/${entry.name}`,
                                            desc: rule.desc,
                                            code: `Fragmento: ${match.substring(0, 100).replace(/</g, '&lt;').replace(/>/g, '&gt;')}...`,
                                            fix: rule.fix
                                        });
                                        addLog(`<span class="log-warn">Posible vulnerabilidad [${rule.name}] en ${entry.name}</span>`);
                                    });
                                }
                            }

                            // Apply App.js powerful scanners to the raw text

                            // 1. Secret Scanner (Advanced)
                            const secrets = analyzeSecrets(text);
                            for (const sec of secrets) {
                                sec.title = sec.title + ` (en ${path}/${entry.name})`;
                                findings.push(sec);
                                ruleHits++;
                            }

                            // HTML/PHP/JS Specific analysis
                            if (ext === '.html' || ext === '.php' || ext === '.js') {

                                // 2. DOM Sinks
                                const sinks = analyzeDOMSinks(text);
                                for (const sink of sinks) {
                                    sink.title = sink.title + ` (en ${entry.name})`;
                                    findings.push(sink);
                                    ruleHits++;
                                }

                                // 3. Vulnerable / Outdated libraries
                                const vulnLibs = analyzeOutdatedLibs(text);
                                for (const lib of vulnLibs) {
                                    lib.title = lib.title + ` (en ${entry.name})`;
                                    findings.push(lib);
                                    ruleHits++;
                                }

                                // 4. Basic HTML security flaws (Forms without CSRF, missing autocomplete, etc.)
                                if (ext === '.html' || ext === '.php') {
                                    const htmlVulns = analyzeHTML(text, `local://${path}/${entry.name}`);
                                    for (const hv of htmlVulns) {
                                        findings.push(hv);
                                        ruleHits++;
                                    }
                                }
                            }

                        } catch (e) {
                            addLog(`<span class="log-dim">No se pudo leer: ${path}/${entry.name}</span>`);
                        }
                    }
                }
            }
        }

        await scanDirectory(dirHandle, dirHandle.name);

        setProgress(100, 'Análisis completado');
        addLog(`<span class="log-ok">Análisis finalizado. Archivos escaneados: ${filesScanned}. Hallazgos: ${sensitiveFilesFound + ruleHits}. Generando reporte...</span>`);

        await sleep(1500);

        // Sort findings by severity
        findings.sort((a, b) => sevOrder(a.sev) - sevOrder(b.sev));

        // Map checklist logic
        const checkItems = findings.map(f => ({
            id: Math.random().toString(36).substring(7),
            text: f.title,
            sev: f.sev,
            done: false
        }));

        // Populate global scanResults for app.js renderReport
        scanResults = {
            url: `[Local SAST] ${dirHandle.name}`,
            timestamp: new Date().toISOString(),
            findings: findings,
            headers: {},
            paths: {},
            metrics: { scripts: 0, styles: 0, images: 0, iframes: 0, forms: 0, inputs: 0, htmlSizeKB: 0 },
            thirdPartyStats: {},
            dns: {},
            subdomains: [],
            waf: [],
            ssl: { available: false },
            ports: { available: false },
            vulnScan: { available: false },
            wordpress: { isWordPress: false },
            recon: {
                status: 200,
                tech: 'Inspección de código fuente estático (.html, .js, .php, .env, etc.)'
            },
            backendUsed: false,
            checklist: checkItems
        };

        // Call renderReport
        renderReport(scanResults.url, findings, {});

        // Overwrite the recon-grid since the default one expects remote scan fields
        setTimeout(() => {
            const grid = document.getElementById('recon-grid');
            if (grid) {
                grid.innerHTML = `
                    <div class="recon-card">
                      <div class="rc-label">Tipo de Análisis</div>
                      <div class="rc-val rc-blue">Análisis Estático (SAST) Local</div>
                    </div>
                    <div class="recon-card">
                      <div class="rc-label">Directorio Analizado</div>
                      <div class="rc-val">${dirHandle.name}</div>
                    </div>
                    <div class="recon-card">
                      <div class="rc-label">Archivos Inspeccionados</div>
                      <div class="rc-val rc-green">${filesScanned} archivos fuente</div>
                    </div>
                    <div class="recon-card">
                      <div class="rc-label">Archivos Sensibles</div>
                      <div class="rc-val ${sensitiveFilesFound > 0 ? 'rc-red' : 'rc-green'}">${sensitiveFilesFound} detectados</div>
                    </div>
                    <div class="recon-card">
                      <div class="rc-label">Vulnerabilidades en Código</div>
                      <div class="rc-val ${ruleHits > 0 ? 'rc-yellow' : 'rc-green'}">${ruleHits} detectadas</div>
                    </div>
                `;
            }

            // Hide the 'Cabeceras HTTP detectadas' section because it's irrelevant here
            const headersHeader = [...document.querySelectorAll('.sec-hdr')].find(el => el.textContent.includes('Cabeceras HTTP'));
            if (headersHeader) headersHeader.style.display = 'none';
            const headersGrid = document.getElementById('headers-grid');
            if (headersGrid) headersGrid.style.display = 'none';

        }, 100);

    } catch (err) {
        if (err.name === 'AbortError') {
            console.log('El usuario canceló la selección del directorio.');
        } else {
            console.error(err);
            alert('Error al acceder a los archivos locales. Intenta usar Chrome o Edge.');
        }
    }
}
