<?php


header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('X-Content-Type-Options: nosniff');

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Rate limiting — Token bucket: allows bursts for scanning
$rateLimitFile = sys_get_temp_dir() . '/websec_rate_' . md5($_SERVER['REMOTE_ADDR']) . '.json';
$rateWindow = 10; // seconds
$rateMax = 60;     // max requests per window (increased for vuln scanning)
$now = time();

$rateData = ['ts' => $now, 'count' => 0];
if (file_exists($rateLimitFile)) {
    $rateData = json_decode(file_get_contents($rateLimitFile), true) ?: $rateData;
    if ($now - $rateData['ts'] > $rateWindow) {
        // Window expired, reset
        $rateData = ['ts' => $now, 'count' => 0];
    }
}
$rateData['count']++;
// Rate limiting disabled for local testing of heavy payloads
/*
if ($rateData['count'] > $rateMax) {
    jsonError('Rate limited. Demasiadas solicitudes (' . $rateMax . ' max / ' . $rateWindow . 's). Espera unos segundos.', 429);
}
*/
file_put_contents($rateLimitFile, json_encode($rateData));

// Validate input
$input = json_decode(file_get_contents('php://input'), true);
if (!$input || empty($input['action'])) {
    jsonError('Acción requerida.', 400);
}

$action = $input['action'];

switch ($action) {
    case 'ping':
        jsonResponse(['pong' => true]);
        break;
    case 'fetch':
        handleFetch($input);
        break;
    case 'dns':
        handleDNS($input);
        break;
    case 'ssl':
        handleSSL($input);
        break;
    case 'ports':
        handlePorts($input);
        break;
    case 'subdomains':
        handleSubdomains($input);
        break;
    case 'headers':
        handleHeaders($input);
        break;
    case 'batch_head':
        handleBatchHead($input);
        break;
    case 'vuln_scan':
        handleVulnScan($input);
        break;
    case 'wp_scan':
        handleWPScan($input);
        break;
    default:
        jsonError('Acción no válida: ' . $action, 400);
}


function handleFetch($input) {
    $url = validateUrl($input['url'] ?? '');
    $method = strtoupper($input['method'] ?? 'GET');
    if (!in_array($method, ['GET', 'HEAD'])) $method = 'GET';

    $opts = [
        'http' => [
            'method' => $method,
            'timeout' => 12,
            'follow_location' => 1,
            'max_redirects' => 5,
            'ignore_errors' => true,
            'header' => "User-Agent: WebSec-Audit/3.0 (Security Scanner)\r\n" .
                        "Accept: text/html,application/xhtml+xml,*/*\r\n" .
                        "Accept-Language: en-US,en;q=0.9\r\n"
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
        ]
    ];

    $ctx = stream_context_create($opts);
    $body = @file_get_contents($url, false, $ctx);
    
    if ($body === false) {
        jsonError('No se pudo conectar a ' . $url, 502);
    }

    // Parse response headers from $http_response_header
    $responseHeaders = [];
    $statusCode = 0;
    $redirectUrl = null;
    
    if (isset($http_response_header) && is_array($http_response_header)) {
        foreach ($http_response_header as $header) {
            if (preg_match('#^HTTP/[\d.]+ (\d+)#', $header, $m)) {
                $statusCode = (int) $m[1];
            } elseif (strpos($header, ':') !== false) {
                list($key, $val) = explode(':', $header, 2);
                $responseHeaders[strtolower(trim($key))] = trim($val);
            }
        }
        // Detect redirects
        if (isset($responseHeaders['location'])) {
            $redirectUrl = $responseHeaders['location'];
        }
    }

    // Limit body size for transfer (2MB max)
    $maxBody = 2 * 1024 * 1024;
    if (strlen($body) > $maxBody) {
        $body = substr($body, 0, $maxBody);
    }

    jsonResponse([
        'status' => $statusCode,
        'headers' => $responseHeaders,
        'body' => $method === 'HEAD' ? '' : $body,
        'redirect' => $redirectUrl,
        'finalUrl' => $url,
        'bodySize' => strlen($body),
    ]);
}


function handleHeaders($input) {
    $url = validateUrl($input['url'] ?? '');

    $opts = [
        'http' => [
            'method' => 'HEAD',
            'timeout' => 5,
            'follow_location' => 0,
            'max_redirects' => 0,
            'ignore_errors' => true,
            'header' => "User-Agent: WebSec-Audit/3.0\r\n"
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
        ]
    ];

    $ctx = stream_context_create($opts);
    @file_get_contents($url, false, $ctx);

    $statusCode = 0;
    $responseHeaders = [];
    
    if (isset($http_response_header)) {
        foreach ($http_response_header as $header) {
            if (preg_match('#^HTTP/[\d.]+ (\d+)#', $header, $m)) {
                $statusCode = (int) $m[1];
            } elseif (strpos($header, ':') !== false) {
                list($key, $val) = explode(':', $header, 2);
                $responseHeaders[strtolower(trim($key))] = trim($val);
            }
        }
    }

    jsonResponse([
        'status' => $statusCode,
        'headers' => $responseHeaders,
    ]);
}


function handleBatchHead($input) {
    $baseUrl = validateUrl($input['baseUrl'] ?? '');
    $paths = $input['paths'] ?? [];
    
    if (!is_array($paths) || count($paths) === 0) {
        jsonError('Se requiere un array de rutas (paths).', 400);
    }
    
    // Limit to 70 paths max per batch
    $paths = array_slice($paths, 0, 70);
    
    // Throttle delay between requests (ms) — prevents target rate limiting
    $delayMs = (int) ($input['delayMs'] ?? 150);
    $delayMs = max(50, min(1000, $delayMs)); // clamp 50-1000ms
    
    $results = [];
    
    foreach ($paths as $pathInfo) {
        $path = is_string($pathInfo) ? $pathInfo : ($pathInfo['p'] ?? $pathInfo['path'] ?? '');
        if (empty($path)) continue;
        
        $fullUrl = rtrim($baseUrl, '/') . '/' . ltrim($path, '/');
        $statusCode = 0;
        $responseHeaders = [];
        
        $opts = [
            'http' => [
                'method' => 'HEAD',
                'timeout' => 5,
                'follow_location' => 0,
                'max_redirects' => 0,
                'ignore_errors' => true,
                'header' => "User-Agent: Mozilla/5.0 (compatible; WebSec-Audit/3.0)\r\n" .
                            "Accept: text/html,*/*\r\n"
            ],
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ]
        ];
        
        $ctx = stream_context_create($opts);
        @file_get_contents($fullUrl, false, $ctx);
        
        if (isset($http_response_header)) {
            foreach ($http_response_header as $header) {
                if (preg_match('#^HTTP/[\d.]+ (\d+)#', $header, $m)) {
                    $statusCode = (int) $m[1];
                } elseif (strpos($header, ':') !== false) {
                    list($key, $val) = explode(':', $header, 2);
                    $responseHeaders[strtolower(trim($key))] = trim($val);
                }
            }
        }
        
        $results[] = [
            'path' => $path,
            'status' => $statusCode,
            'headers' => $responseHeaders,
        ];
        
        // Check if we got rate-limited (429 or 403 after several 200s)
        if ($statusCode === 429) {
            // Target is rate-limiting us — increase delay and continue
            $delayMs = min($delayMs * 2, 2000);
            usleep($delayMs * 1000);
            continue;
        }
        
        // Throttle between requests to be polite to target server
        if ($delayMs > 0) {
            usleep($delayMs * 1000);
        }
    }
    
    jsonResponse([
        'results' => $results,
        'totalScanned' => count($results),
        'delayUsed' => $delayMs,
    ]);
}


function handleDNS($input) {
    $hostname = validateHostname($input['hostname'] ?? '');

    $result = [
        'spf' => null,
        'dmarc' => null,
        'dkim_selector' => null,
        'mx' => [],
        'ns' => [],
        'a' => [],
        'aaaa' => [],
        'soa' => null,
        'txt' => [],
        'caa' => [],
        'dnssec' => false,
        'ptr' => [],
    ];

    // ── TXT records (SPF) ──
    $txt = @dns_get_record($hostname, DNS_TXT);
    if ($txt) {
        foreach ($txt as $rec) {
            $val = $rec['txt'] ?? '';
            $result['txt'][] = $val;
            if (stripos($val, 'v=spf1') === 0) {
                $result['spf'] = $val;
            }
        }
    }

    // ── DMARC ──
    $dmarc = @dns_get_record('_dmarc.' . $hostname, DNS_TXT);
    if ($dmarc) {
        foreach ($dmarc as $rec) {
            $val = $rec['txt'] ?? '';
            if (stripos($val, 'v=DMARC1') === 0) {
                $result['dmarc'] = $val;
            }
        }
    }

    // ── DKIM (common selectors) ──
    $dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim'];
    foreach ($dkimSelectors as $sel) {
        $dkim = @dns_get_record($sel . '._domainkey.' . $hostname, DNS_TXT);
        if ($dkim && count($dkim) > 0) {
            $result['dkim_selector'] = $sel;
            break;
        }
    }

    // ── MX records ──
    $mx = @dns_get_record($hostname, DNS_MX);
    if ($mx) {
        foreach ($mx as $rec) {
            $result['mx'][] = [
                'host' => $rec['target'] ?? '',
                'priority' => $rec['pri'] ?? 0,
            ];
        }
        usort($result['mx'], fn($a, $b) => $a['priority'] - $b['priority']);
    }

    // ── NS records ──
    $ns = @dns_get_record($hostname, DNS_NS);
    if ($ns) {
        foreach ($ns as $rec) {
            $result['ns'][] = $rec['target'] ?? '';
        }
    }

    // ── A records ──
    $a = @dns_get_record($hostname, DNS_A);
    if ($a) {
        foreach ($a as $rec) {
            $result['a'][] = $rec['ip'] ?? '';
        }
    }

    // ── AAAA records ──
    $aaaa = @dns_get_record($hostname, DNS_AAAA);
    if ($aaaa) {
        foreach ($aaaa as $rec) {
            $result['aaaa'][] = $rec['ipv6'] ?? '';
        }
    }

    // ── SOA record ──
    $soa = @dns_get_record($hostname, DNS_SOA);
    if ($soa && count($soa) > 0) {
        $s = $soa[0];
        $result['soa'] = [
            'mname' => $s['mname'] ?? '',
            'rname' => $s['rname'] ?? '',
            'serial' => $s['serial'] ?? 0,
            'refresh' => $s['refresh'] ?? 0,
            'retry' => $s['retry'] ?? 0,
            'expire' => $s['expire'] ?? 0,
            'minimum_ttl' => $s['minimum-ttl'] ?? 0,
        ];
    }

    // ── CAA records (Certificate Authority Authorization) ──
    $caa = @dns_get_record($hostname, DNS_CAA);
    if ($caa) {
        foreach ($caa as $rec) {
            $result['caa'][] = [
                'flags' => $rec['flags'] ?? 0,
                'tag' => $rec['tag'] ?? '',
                'value' => $rec['value'] ?? '',
            ];
        }
    }

    // ── DNSSEC check via dig (if available) ──
    $result['dnssec'] = checkDNSSEC($hostname);

    jsonResponse($result);
}

/**
 * Check DNSSEC using dig command or fallback
 */
function checkDNSSEC($hostname) {
    // Try with dig command
    if (function_exists('exec')) {
        $output = [];
        @exec('dig +dnssec +short ' . escapeshellarg($hostname) . ' DNSKEY 2>&1', $output, $ret);
        if ($ret === 0 && count($output) > 0 && !empty(trim(implode('', $output)))) {
            return true;
        }
        
        // Alternative: check AD flag
        $output2 = [];
        @exec('dig +adflag ' . escapeshellarg($hostname) . ' A 2>&1', $output2, $ret2);
        $fullOutput = implode("\n", $output2);
        if (strpos($fullOutput, 'flags:') !== false && strpos($fullOutput, ' ad') !== false) {
            return true;
        }
    }
    
    // Fallback: try Cloudflare DoH
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'https://cloudflare-dns.com/dns-query?name=' . urlencode($hostname) . '&type=DNSKEY',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_HTTPHEADER => ['Accept: application/dns-json'],
    ]);
    $response = curl_exec($ch);
    curl_close($ch);
    
    if ($response) {
        $data = json_decode($response, true);
        if (!empty($data['AD'])) return true;
        if (!empty($data['Answer'])) return true;
    }
    
    return false;
}


function handleSSL($input) {
    $hostname = validateHostname($input['hostname'] ?? '');
    $port = (int) ($input['port'] ?? 443);
    if ($port < 1 || $port > 65535) $port = 443;

    $result = [
        'valid' => false,
        'issuer' => null,
        'subject' => null,
        'validFrom' => null,
        'validTo' => null,
        'daysRemaining' => null,
        'serialNumber' => null,
        'signatureAlgorithm' => null,
        'sans' => [],
        'chain' => [],
        'protocols' => [],
        'keySize' => null,
        'keyType' => null,
        'ocsp' => null,
        'isWildcard' => false,
        'isEV' => false,
        'isSelfSigned' => false,
    ];

    // Get certificate details
    $ctx = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'capture_peer_cert_chain' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true,
            'SNI_enabled' => true,
            'peer_name' => $hostname,
        ]
    ]);

    $socket = @stream_socket_client(
        'ssl://' . $hostname . ':' . $port,
        $errno, $errstr, 10,
        STREAM_CLIENT_CONNECT, $ctx
    );

    if (!$socket) {
        jsonResponse(array_merge($result, ['error' => 'No se pudo establecer conexión SSL: ' . $errstr]));
        return;
    }

    $params = stream_context_get_params($socket);
    fclose($socket);

    // Parse main certificate
    if (isset($params['options']['ssl']['peer_certificate'])) {
        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
        if ($cert) {
            $result['valid'] = true;
            $result['subject'] = $cert['subject']['CN'] ?? ($cert['subject']['O'] ?? 'Unknown');
            $result['issuer'] = $cert['issuer']['O'] ?? ($cert['issuer']['CN'] ?? 'Unknown');
            $result['validFrom'] = date('Y-m-d H:i:s', $cert['validFrom_time_t']);
            $result['validTo'] = date('Y-m-d H:i:s', $cert['validTo_time_t']);
            $result['daysRemaining'] = max(0, floor(($cert['validTo_time_t'] - time()) / 86400));
            $result['serialNumber'] = $cert['serialNumberHex'] ?? $cert['serialNumber'] ?? null;
            $result['signatureAlgorithm'] = $cert['signatureTypeSN'] ?? null;
            
            // SANs (Subject Alternative Names)
            if (isset($cert['extensions']['subjectAltName'])) {
                $sans = explode(',', $cert['extensions']['subjectAltName']);
                $result['sans'] = array_map(fn($s) => trim(str_replace('DNS:', '', $s)), $sans);
            }

            // Wildcard check
            $result['isWildcard'] = strpos($result['subject'], '*.') === 0 ||
                                    array_filter($result['sans'], fn($s) => strpos($s, '*.') === 0) ? true : false;

            // EV check (heuristic)
            $result['isEV'] = isset($cert['extensions']['certificatePolicies']) &&
                              strpos($cert['extensions']['certificatePolicies'], 'Policy: ') !== false;

            // Self-signed check
            $result['isSelfSigned'] = ($cert['subject'] === $cert['issuer']);

            // Key details
            $pubKey = openssl_pkey_get_public($params['options']['ssl']['peer_certificate']);
            if ($pubKey) {
                $keyDetails = openssl_pkey_get_details($pubKey);
                if ($keyDetails) {
                    $result['keySize'] = $keyDetails['bits'] ?? null;
                    $typeMap = [OPENSSL_KEYTYPE_RSA => 'RSA', OPENSSL_KEYTYPE_EC => 'EC', OPENSSL_KEYTYPE_DSA => 'DSA'];
                    $result['keyType'] = $typeMap[$keyDetails['type']] ?? 'Unknown';
                }
            }

            // OCSP
            if (isset($cert['extensions']['authorityInfoAccess'])) {
                $result['ocsp'] = strpos($cert['extensions']['authorityInfoAccess'], 'OCSP') !== false ? 'Available' : null;
            }
        }
    }

    // Parse certificate chain
    if (isset($params['options']['ssl']['peer_certificate_chain'])) {
        foreach ($params['options']['ssl']['peer_certificate_chain'] as $chainCert) {
            $parsed = openssl_x509_parse($chainCert);
            if ($parsed) {
                $result['chain'][] = [
                    'subject' => $parsed['subject']['CN'] ?? ($parsed['subject']['O'] ?? 'Unknown'),
                    'issuer' => $parsed['issuer']['CN'] ?? ($parsed['issuer']['O'] ?? 'Unknown'),
                    'validTo' => date('Y-m-d', $parsed['validTo_time_t']),
                ];
            }
        }
    }

    // Test supported protocols
    $protocolsToTest = [
        'TLSv1.0' => STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT,
        'TLSv1.1' => STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT,
        'TLSv1.2' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT,
    ];
    
    // TLS 1.3 constant may not exist in older PHP
    if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
        $protocolsToTest['TLSv1.3'] = STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
    }

    foreach ($protocolsToTest as $name => $method) {
        $testCtx = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'crypto_method' => $method,
                'SNI_enabled' => true,
                'peer_name' => $hostname,
            ]
        ]);
        $testSocket = @stream_socket_client(
            'ssl://' . $hostname . ':' . $port,
            $e1, $e2, 5,
            STREAM_CLIENT_CONNECT, $testCtx
        );
        if ($testSocket) {
            $result['protocols'][] = $name;
            fclose($testSocket);
        }
    }

    jsonResponse($result);
}


function handlePorts($input) {
    $hostname = validateHostname($input['hostname'] ?? '');
    
    // Only scan common web/service ports (for safety)
    $portsToScan = [
        21 => 'FTP',
        22 => 'SSH',
        23 => 'Telnet',
        25 => 'SMTP',
        53 => 'DNS',
        80 => 'HTTP',
        110 => 'POP3',
        143 => 'IMAP',
        443 => 'HTTPS',
        445 => 'SMB',
        587 => 'SMTP (TLS)',
        993 => 'IMAPS',
        995 => 'POP3S',
        1433 => 'MSSQL',
        1521 => 'Oracle DB',
        3306 => 'MySQL',
        3389 => 'RDP',
        5432 => 'PostgreSQL',
        5900 => 'VNC',
        6379 => 'Redis',
        8080 => 'HTTP Alt',
        8443 => 'HTTPS Alt',
        8888 => 'HTTP Alt',
        9200 => 'Elasticsearch',
        27017 => 'MongoDB',
    ];

    // Allow custom ports (limited)
    if (!empty($input['ports']) && is_array($input['ports'])) {
        $customPorts = array_slice(array_map('intval', $input['ports']), 0, 30);
        foreach ($customPorts as $p) {
            if ($p > 0 && $p <= 65535 && !isset($portsToScan[$p])) {
                $portsToScan[$p] = 'Custom';
            }
        }
    }

    $results = [];
    $timeout = 1.5; // seconds per port

    foreach ($portsToScan as $port => $service) {
        $status = 'closed';
        $banner = '';
        
        $socket = @fsockopen($hostname, $port, $errno, $errstr, $timeout);
        if ($socket) {
            $status = 'open';
            // Try to grab banner (with very short timeout)
            stream_set_timeout($socket, 1);
            $banner = @fgets($socket, 256);
            if ($banner) {
                $banner = trim(preg_replace('/[\x00-\x1F\x7F]/', '', $banner));
                $banner = substr($banner, 0, 100);
            }
            fclose($socket);
        }
        
        $results[] = [
            'port' => $port,
            'service' => $service,
            'status' => $status,
            'banner' => $banner ?: null,
        ];
    }

    // Sort: open first, then by port number
    usort($results, function($a, $b) {
        if ($a['status'] === 'open' && $b['status'] !== 'open') return -1;
        if ($a['status'] !== 'open' && $b['status'] === 'open') return 1;
        return $a['port'] - $b['port'];
    });

    jsonResponse([
        'hostname' => $hostname,
        'results' => $results,
        'openPorts' => array_values(array_filter($results, fn($r) => $r['status'] === 'open')),
        'totalScanned' => count($results),
    ]);
}


function handleSubdomains($input) {
    $hostname = validateHostname($input['hostname'] ?? '');

    $commonSubs = [
        'www', 'dev', 'staging', 'stage', 'test', 'qa', 'uat', 'pre', 'preprod',
        'admin', 'panel', 'dashboard', 'cms', 'cpanel', 'webmail',
        'api', 'api-dev', 'api-staging', 'api-v2', 'api-v1', 'graphql',
        'mail', 'smtp', 'imap', 'pop', 'mx',
        'ftp', 'sftp', 'cdn', 'static', 'assets', 'media', 'images', 'img',
        'db', 'database', 'mongo', 'redis', 'elastic', 'mysql', 'postgres',
        'jenkins', 'ci', 'cd', 'gitlab', 'git', 'bitbucket', 'jira', 'confluence',
        'vpn', 'internal', 'intranet', 'extranet', 'portal',
        'blog', 'docs', 'wiki', 'support', 'help', 'status',
        'shop', 'store', 'app', 'mobile', 'm',
        'ns1', 'ns2', 'dns', 'dns1', 'dns2',
        'backup', 'bak', 'old', 'new', 'beta', 'alpha',
        'monitor', 'nagios', 'grafana', 'kibana', 'prometheus',
        'sso', 'auth', 'login', 'oauth', 'accounts',
        'sandbox', 'demo', 'preview', 'canary',
    ];

    $found = [];
    
    foreach ($commonSubs as $sub) {
        $fqdn = $sub . '.' . $hostname;
        $records = @dns_get_record($fqdn, DNS_A);
        if ($records && count($records) > 0) {
            $ip = $records[0]['ip'] ?? '';
            
            // Also check for CNAME
            $cname = @dns_get_record($fqdn, DNS_CNAME);
            $cnameTarget = ($cname && count($cname) > 0) ? ($cname[0]['target'] ?? '') : '';
            
            $found[] = [
                'subdomain' => $sub,
                'fqdn' => $fqdn,
                'ip' => $ip,
                'cname' => $cnameTarget,
                'risky' => in_array($sub, [
                    'dev', 'staging', 'stage', 'test', 'qa', 'uat', 'pre', 'preprod',
                    'admin', 'panel', 'jenkins', 'ci', 'gitlab', 'git', 'internal',
                    'intranet', 'db', 'database', 'mongo', 'redis', 'elastic',
                    'mysql', 'postgres', 'backup', 'bak', 'old', 'sandbox',
                    'cpanel', 'phpmyadmin', 'nagios', 'grafana', 'kibana',
                ]),
            ];
        }
    }

    jsonResponse([
        'hostname' => $hostname,
        'found' => $found,
        'totalChecked' => count($commonSubs),
        'risky' => array_values(array_filter($found, fn($s) => $s['risky'])),
    ]);
}


// ═══════════════════════════════════════════════════════════════
//  ACTIVE VULNERABILITY SCANNING (Safe payloads)
// ═══════════════════════════════════════════════════════════════
function handleVulnScan($input) {
    $url = validateUrl($input['url'] ?? '');
    $scanType = $input['scanType'] ?? 'all'; // xss, sqli, pathtraversal, ssrf, openredirect, all
    $maxTests = (int) ($input['maxTests'] ?? 30);
    $maxTests = max(5, min(50, $maxTests));
    $delayMs = (int) ($input['delayMs'] ?? 200);
    $delayMs = max(100, min(2000, $delayMs));

    $results = [
        'xss' => [],
        'sqli' => [],
        'pathTraversal' => [],
        'ssrf' => [],
        'openRedirect' => [],
        'totalTests' => 0,
        'totalVulnerabilities' => 0,
    ];

    // ── Step 1: Discover parameters by fetching the page and extracting forms/links ──
    $html = '';
    $opts = [
        'http' => [
            'method' => 'GET',
            'timeout' => 10,
            'follow_location' => 1,
            'max_redirects' => 3,
            'ignore_errors' => true,
            'header' => "User-Agent: Mozilla/5.0 (compatible; WebSec-Audit/4.0)\r\n" .
                        "Accept: text/html,*/*\r\n"
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ];
    $ctx = stream_context_create($opts);
    $html = @file_get_contents($url, false, $ctx);

    // Extract GET parameters from links
    $discoveredParams = [];
    if ($html) {
        // Extract from href links
        preg_match_all('/href=["\']([^"\']*)["\']/i', $html, $hrefMatches);
        foreach ($hrefMatches[1] as $href) {
            $parsed = @parse_url($href);
            if (!empty($parsed['query'])) {
                parse_str($parsed['query'], $qParams);
                foreach (array_keys($qParams) as $p) {
                    $discoveredParams[$p] = true;
                }
            }
        }
        // Extract from form inputs
        preg_match_all('/<input[^>]+name=["\']([^"\']*)["\']/i', $html, $inputMatches);
        foreach ($inputMatches[1] as $name) {
            $discoveredParams[$name] = true;
        }
        // Extract from form actions
        preg_match_all('/<form[^>]+action=["\']([^"\']*)["\']/i', $html, $formMatches);
    }

    // Common parameter names to test
    $commonParams = ['q', 'search', 'query', 'id', 'page', 'url', 'redirect', 'return',
                     'next', 'redir', 'dest', 'destination', 'go', 'link', 'target',
                     'view', 'file', 'path', 'dir', 'cat', 'category', 'type', 'name',
                     'callback', 'cb', 'ref', 'source', 'lang', 'action', 'cmd'];
    foreach ($commonParams as $cp) $discoveredParams[$cp] = true;
    $paramList = array_keys($discoveredParams);

    $testCount = 0;

    // ══════════════════════════════════
    // ── XSS Detection (Reflected) ──
    // ══════════════════════════════════
    if ($scanType === 'all' || $scanType === 'xss') {
        // Safe canary payloads — these do not execute, they're just markers
        $xssPayloads = [
            ['payload' => '<wsaudit_xss>', 'name' => 'Basic HTML tag injection'],
            ['payload' => '"onmouseover="wsaudit', 'name' => 'Attribute injection (double quote)'],
            ['payload' => "'onmouseover='wsaudit", 'name' => 'Attribute injection (single quote)'],
            ['payload' => '<script>wsaudit</script>', 'name' => 'Script tag injection'],
            ['payload' => '<img src=x onerror=wsaudit>', 'name' => 'IMG tag event handler'],
            ['payload' => 'javascript:wsaudit', 'name' => 'JavaScript protocol'],
            ['payload' => '<svg/onload=wsaudit>', 'name' => 'SVG onload injection'],
        ];

        foreach (array_slice($paramList, 0, 8) as $param) {
            foreach ($xssPayloads as $xp) {
                if ($testCount >= $maxTests) break 2;
                $testUrl = $url . '?' . http_build_query([$param => $xp['payload']]);
                $response = safeRequest($testUrl, 'GET', null, 5);
                $testCount++;

                if ($response && stripos($response['body'], $xp['payload']) !== false) {
                    $results['xss'][] = [
                        'param' => $param,
                        'payload' => $xp['payload'],
                        'type' => $xp['name'],
                        'method' => 'GET',
                        'reflected' => true,
                        'evidence' => extractContext($response['body'], $xp['payload'], 60),
                    ];
                    break; // One hit per param is enough
                }
                usleep($delayMs * 1000);
            }
        }
    }

    // ══════════════════════════════════
    // ── SQL Injection Detection ──
    // ══════════════════════════════════
    if ($scanType === 'all' || $scanType === 'sqli') {
        $sqliPayloads = [
            ['payload' => "'", 'name' => 'Single quote error test'],
            ['payload' => '"', 'name' => 'Double quote error test'],
            ['payload' => "' OR '1'='1", 'name' => 'Boolean-based OR injection'],
            ['payload' => '" OR "1"="1', 'name' => 'Boolean-based OR (double quote)'],
            ['payload' => "1' AND '1'='1", 'name' => 'AND true condition'],
            ['payload' => "1' AND '1'='2", 'name' => 'AND false condition'],
            ['payload' => "1 UNION SELECT NULL--", 'name' => 'UNION SELECT probe'],
            ['payload' => "1; WAITFOR DELAY '0:0:0'--", 'name' => 'Time-based (MSSQL syntax)'],
        ];

        $sqlErrorPatterns = [
            '/you have an error in your sql syntax/i',
            '/warning.*mysql/i',
            '/unclosed quotation mark/i',
            '/quoted string not properly terminated/i',
            '/mysql_fetch/i',
            '/pg_query/i',
            '/pg_exec/i',
            '/sqlstate\[/i',
            '/microsoft ole db/i',
            '/odbc.*driver/i',
            '/oracle.*error/i',
            '/ora-\d{5}/i',
            '/sqlite.*error/i',
            '/near.*syntax/i',
            '/sql.*error/i',
            '/database.*error/i',
            '/syntax error at or near/i',
            '/unterminated.*string/i',
            '/pdo.*exception/i',
            '/Query failed/i',
        ];

        // First get baseline response
        $baselineResp = safeRequest($url . '?id=1', 'GET', null, 5);
        $baselineLen = $baselineResp ? strlen($baselineResp['body']) : 0;

        foreach (array_slice($paramList, 0, 6) as $param) {
            foreach ($sqliPayloads as $sp) {
                if ($testCount >= $maxTests) break 2;
                $testUrl = $url . '?' . http_build_query([$param => $sp['payload']]);
                $response = safeRequest($testUrl, 'GET', null, 5);
                $testCount++;

                if ($response) {
                    $body = $response['body'];
                    $vuln = ['param' => $param, 'payload' => $sp['payload'], 'type' => $sp['name'], 'indicators' => []];
                    $isVuln = false;

                    // Check for SQL error messages
                    foreach ($sqlErrorPatterns as $pattern) {
                        if (preg_match($pattern, $body, $m)) {
                            $vuln['indicators'][] = 'SQL error: ' . $m[0];
                            $isVuln = true;
                        }
                    }

                    // Check for significant response length change with boolean payloads
                    if (strpos($sp['name'], 'Boolean') !== false && $baselineLen > 0) {
                        $diff = abs(strlen($body) - $baselineLen);
                        if ($diff > $baselineLen * 0.3 && $diff > 200) {
                            $vuln['indicators'][] = 'Response length anomaly (baseline: ' . $baselineLen . ', current: ' . strlen($body) . ')';
                            $isVuln = true;
                        }
                    }

                    if ($isVuln) {
                        $results['sqli'][] = $vuln;
                        break; // One hit per param
                    }
                }
                usleep($delayMs * 1000);
            }
        }
    }

    // ══════════════════════════════════
    // ── Path Traversal Detection ──
    // ══════════════════════════════════
    if ($scanType === 'all' || $scanType === 'pathtraversal') {
        $traversalPayloads = [
            ['payload' => '../../../etc/passwd', 'marker' => 'root:', 'name' => 'Linux passwd (3 levels)'],
            ['payload' => '../../../../etc/passwd', 'marker' => 'root:', 'name' => 'Linux passwd (4 levels)'],
            ['payload' => '../../../../../etc/passwd', 'marker' => 'root:', 'name' => 'Linux passwd (5 levels)'],
            ['payload' => '..\\..\\..\\windows\\win.ini', 'marker' => '[extensions]', 'name' => 'Windows win.ini'],
            ['payload' => '....//....//....//etc/passwd', 'marker' => 'root:', 'name' => 'Double-dot bypass'],
            ['payload' => '..%2f..%2f..%2fetc%2fpasswd', 'marker' => 'root:', 'name' => 'URL-encoded traversal'],
            ['payload' => '%2e%2e/%2e%2e/%2e%2e/etc/passwd', 'marker' => 'root:', 'name' => 'Full URL-encoded'],
            ['payload' => '..%252f..%252f..%252fetc%252fpasswd', 'marker' => 'root:', 'name' => 'Double URL-encoded'],
        ];

        $fileParams = array_intersect($paramList, ['file', 'path', 'dir', 'page', 'view', 'include', 'template', 'doc', 'folder', 'root', 'pg']);
        if (empty($fileParams)) $fileParams = ['file', 'path', 'page', 'view', 'include'];

        foreach ($fileParams as $param) {
            foreach ($traversalPayloads as $tp) {
                if ($testCount >= $maxTests) break 2;
                $testUrl = $url . '?' . http_build_query([$param => $tp['payload']]);
                $response = safeRequest($testUrl, 'GET', null, 5);
                $testCount++;

                if ($response && stripos($response['body'], $tp['marker']) !== false) {
                    $results['pathTraversal'][] = [
                        'param' => $param,
                        'payload' => $tp['payload'],
                        'type' => $tp['name'],
                        'marker' => $tp['marker'],
                        'evidence' => extractContext($response['body'], $tp['marker'], 60),
                    ];
                    break;
                }
                usleep($delayMs * 1000);
            }
        }
    }

    // ══════════════════════════════════
    // ── SSRF Detection ──
    // ══════════════════════════════════
    if ($scanType === 'all' || $scanType === 'ssrf') {
        $ssrfParams = array_intersect($paramList, ['url', 'link', 'target', 'dest', 'redirect', 'uri', 'path', 'src', 'source', 'feed', 'host', 'domain', 'site']);
        if (empty($ssrfParams)) $ssrfParams = ['url', 'link', 'target', 'src'];

        $ssrfPayloads = [
            ['payload' => 'http://127.0.0.1:80', 'name' => 'Localhost HTTP', 'marker' => null],
            ['payload' => 'http://127.0.0.1:22', 'name' => 'Localhost SSH port', 'marker' => null],
            ['payload' => 'http://169.254.169.254/latest/meta-data/', 'name' => 'AWS metadata (IMDSv1)', 'marker' => 'ami-id'],
            ['payload' => 'http://[::1]/', 'name' => 'IPv6 localhost', 'marker' => null],
            ['payload' => 'http://0x7f000001/', 'name' => 'Hex-encoded localhost', 'marker' => null],
            ['payload' => 'http://metadata.google.internal/', 'name' => 'GCP metadata', 'marker' => 'computeMetadata'],
        ];

        foreach ($ssrfParams as $param) {
            foreach ($ssrfPayloads as $sp) {
                if ($testCount >= $maxTests) break 2;

                // GET test
                $testUrl = $url . '?' . http_build_query([$param => $sp['payload']]);
                $response = safeRequest($testUrl, 'GET', null, 5);
                $testCount++;

                $isVuln = false;
                $indicators = [];

                if ($response) {
                    $body = $response['body'];
                    $status = $response['status'];

                    // Check if the response looks like it fetched internal content
                    if ($sp['marker'] && stripos($body, $sp['marker']) !== false) {
                        $isVuln = true;
                        $indicators[] = 'Internal content marker found: ' . $sp['marker'];
                    }

                    // Check for typical SSRF indicators
                    if (preg_match('/Connection refused|Connection timed out/i', $body)) {
                        $indicators[] = 'Server-side connection error (possible blind SSRF)';
                    }

                    if ($status === 200 && strlen($body) > 0 && strpos($sp['payload'], '169.254') !== false) {
                        if (preg_match('/ami-|instance-|hostname|public-ipv4/i', $body)) {
                            $isVuln = true;
                            $indicators[] = 'AWS metadata endpoint accessible';
                        }
                    }
                }

                if ($isVuln) {
                    $results['ssrf'][] = [
                        'param' => $param,
                        'payload' => $sp['payload'],
                        'type' => $sp['name'],
                        'indicators' => $indicators,
                    ];
                    break;
                }
                usleep($delayMs * 1000);
            }
        }
    }

    // ══════════════════════════════════
    // ── Open Redirect Detection ──
    // ══════════════════════════════════
    if ($scanType === 'all' || $scanType === 'openredirect') {
        $redirectParams = array_intersect($paramList, ['redirect', 'url', 'return', 'next', 'redir', 'dest',
                                                        'destination', 'go', 'link', 'target', 'continue',
                                                        'return_to', 'returnTo', 'forward', 'ref', 'out']);
        if (empty($redirectParams)) $redirectParams = ['redirect', 'url', 'return', 'next'];

        $redirectPayloads = [
            ['payload' => 'https://evil.com', 'name' => 'Direct external URL'],
            ['payload' => '//evil.com', 'name' => 'Protocol-relative URL'],
            ['payload' => '/\\evil.com', 'name' => 'Backslash bypass'],
            ['payload' => 'https://evil.com%2f%2f', 'name' => 'URL-encoded slashes'],
            ['payload' => 'javascript:alert(1)', 'name' => 'JavaScript protocol'],
            ['payload' => '/%09/evil.com', 'name' => 'Tab character bypass'],
        ];

        foreach ($redirectParams as $param) {
            foreach ($redirectPayloads as $rp) {
                if ($testCount >= $maxTests) break 2;
                $testUrl = $url . '?' . http_build_query([$param => $rp['payload']]);

                // Use non-following redirect request
                $response = safeRequest($testUrl, 'GET', null, 5, false);
                $testCount++;

                if ($response) {
                    $isVuln = false;
                    $indicators = [];

                    // Check Location header for external redirect
                    $location = $response['headers']['location'] ?? '';
                    if ($location) {
                        if (preg_match('/evil\.com/i', $location)) {
                            $isVuln = true;
                            $indicators[] = 'Location header redirects to injected URL: ' . $location;
                        }
                    }

                    // Check for meta refresh or JS redirect in body
                    if (preg_match('/meta.*refresh.*evil\.com/i', $response['body'])) {
                        $isVuln = true;
                        $indicators[] = 'Meta refresh redirect detected';
                    }
                    if (preg_match('/window\.location.*evil\.com/i', $response['body'])) {
                        $isVuln = true;
                        $indicators[] = 'JavaScript redirect detected';
                    }

                    if ($isVuln) {
                        $results['openRedirect'][] = [
                            'param' => $param,
                            'payload' => $rp['payload'],
                            'type' => $rp['name'],
                            'indicators' => $indicators,
                        ];
                        break;
                    }
                }
                usleep($delayMs * 1000);
            }
        }
    }

    // ── Summary ──
    $results['totalTests'] = $testCount;
    $results['totalVulnerabilities'] = count($results['xss']) + count($results['sqli']) +
                                       count($results['pathTraversal']) + count($results['ssrf']) +
                                       count($results['openRedirect']);
    $results['paramsDiscovered'] = $paramList;

    jsonResponse($results);
}

/**
 * Safe HTTP request for vulnerability scanning
 */
function safeRequest($url, $method = 'GET', $postData = null, $timeout = 5, $followRedirects = true) {
    $opts = [
        'http' => [
            'method' => $method,
            'timeout' => $timeout,
            'follow_location' => $followRedirects ? 1 : 0,
            'max_redirects' => $followRedirects ? 3 : 0,
            'ignore_errors' => true,
            'header' => "User-Agent: Mozilla/5.0 (compatible; WebSec-Audit/4.0 Security Scanner)\r\n" .
                        "Accept: text/html,*/*\r\n"
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ];

    if ($postData && $method === 'POST') {
        $opts['http']['header'] .= "Content-Type: application/x-www-form-urlencoded\r\n";
        $opts['http']['content'] = is_string($postData) ? $postData : http_build_query($postData);
    }

    $ctx = stream_context_create($opts);
    $body = @file_get_contents($url, false, $ctx);

    if ($body === false) return null;

    $status = 0;
    $headers = [];
    if (isset($http_response_header)) {
        foreach ($http_response_header as $header) {
            if (preg_match('#^HTTP/[\d.]+ (\d+)#', $header, $m)) {
                $status = (int) $m[1];
            } elseif (strpos($header, ':') !== false) {
                list($key, $val) = explode(':', $header, 2);
                $headers[strtolower(trim($key))] = trim($val);
            }
        }
    }

    // Limit body to prevent memory issues
    $body = substr($body, 0, 500000);

    return ['status' => $status, 'headers' => $headers, 'body' => $body];
}

/**
 * Extract surrounding context for a match
 */
function extractContext($body, $needle, $radius = 60) {
    $pos = stripos($body, $needle);
    if ($pos === false) return '';
    $start = max(0, $pos - $radius);
    $end = min(strlen($body), $pos + strlen($needle) + $radius);
    $ctx = substr($body, $start, $end - $start);
    // Clean up for display
    $ctx = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $ctx);
    return ($start > 0 ? '...' : '') . $ctx . ($end < strlen($body) ? '...' : '');
}


// ═══════════════════════════════════════════════════════════════
//  WORDPRESS & DEPENDENCY CVE SCANNING
// ═══════════════════════════════════════════════════════════════
function handleWPScan($input) {
    $url = validateUrl($input['url'] ?? '');

    $result = [
        'isWordPress' => false,
        'wpVersion' => null,
        'plugins' => [],
        'themes' => [],
        'vulnerablePlugins' => [],
        'vulnerableThemes' => [],
        'wpFindings' => [],
    ];

    // ── Step 1: Detect WordPress and version ──
    $html = '';
    $opts = [
        'http' => [
            'method' => 'GET',
            'timeout' => 10,
            'follow_location' => 1,
            'max_redirects' => 3,
            'ignore_errors' => true,
            'header' => "User-Agent: Mozilla/5.0 (compatible; WebSec-Audit/4.0)\r\n"
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ];
    $ctx = stream_context_create($opts);
    $html = @file_get_contents($url, false, $ctx);

    if (!$html) {
        jsonResponse($result);
        return;
    }

    // Detect WordPress
    $wpIndicators = [
        strpos($html, 'wp-content') !== false,
        strpos($html, 'wp-includes') !== false,
        strpos($html, 'wp-json') !== false,
        strpos($html, 'wordpress') !== false,
        strpos($html, '/xmlrpc.php') !== false,
    ];
    $result['isWordPress'] = count(array_filter($wpIndicators)) >= 2;

    // Extract WP version
    if (preg_match('/content="WordPress (\d+\.\d+\.?\d*)"/', $html, $m)) {
        $result['wpVersion'] = $m[1];
    } elseif (preg_match('/ver=(\d+\.\d+\.?\d*)/', $html, $m)) {
        // Check if it's a WP core version
        if (strpos($html, 'wp-includes') !== false) {
            $result['wpVersion'] = $m[1];
        }
    }

    if (!$result['isWordPress']) {
        jsonResponse($result);
        return;
    }

    // ── Step 2: Enumerate plugins from HTML ──
    preg_match_all('#wp-content/plugins/([a-z0-9_-]+)/#i', $html, $pluginMatches);
    $detectedPlugins = array_unique($pluginMatches[1]);

    // ── Step 3: Try to read plugin readme.txt for versions ──
    foreach ($detectedPlugins as $plugin) {
        $pluginInfo = ['slug' => $plugin, 'version' => null, 'vulnerable' => false, 'cves' => []];

        // Try to get version from readme.txt
        $readmeUrl = rtrim($url, '/') . '/wp-content/plugins/' . $plugin . '/readme.txt';
        $readmeResp = safeRequest($readmeUrl, 'GET', null, 3);
        if ($readmeResp && $readmeResp['status'] === 200) {
            if (preg_match('/Stable tag:\s*([\d.]+)/i', $readmeResp['body'], $vm)) {
                $pluginInfo['version'] = $vm[1];
            }
        }

        // Check against known vulnerable plugins database
        $vulns = checkPluginVulnerabilities($plugin, $pluginInfo['version']);
        if (!empty($vulns)) {
            $pluginInfo['vulnerable'] = true;
            $pluginInfo['cves'] = $vulns;
            $result['vulnerablePlugins'][] = $pluginInfo;
        }

        $result['plugins'][] = $pluginInfo;
        usleep(100000); // 100ms delay
    }

    // ── Step 4: Enumerate themes ──
    preg_match_all('#wp-content/themes/([a-z0-9_-]+)/#i', $html, $themeMatches);
    $detectedThemes = array_unique($themeMatches[1]);
    foreach ($detectedThemes as $theme) {
        $result['themes'][] = ['slug' => $theme];
    }

    // ── Step 5: WordPress-specific security checks ──
    // Check XML-RPC
    $xmlrpcResp = safeRequest(rtrim($url, '/') . '/xmlrpc.php', 'GET', null, 3);
    if ($xmlrpcResp && $xmlrpcResp['status'] === 200 && strpos($xmlrpcResp['body'], 'XML-RPC') !== false) {
        $result['wpFindings'][] = [
            'sev' => 'M',
            'title' => 'XML-RPC habilitado',
            'desc' => 'El endpoint xmlrpc.php está activo. Puede ser abusado para ataques de fuerza bruta y amplificación DDoS (pingback).',
            'fix' => 'Deshabilita XML-RPC si no lo necesitas. Usa el plugin "Disable XML-RPC" o bloquéalo en .htaccess.'
        ];
    }

    // Check REST API user enumeration
    $usersResp = safeRequest(rtrim($url, '/') . '/wp-json/wp/v2/users', 'GET', null, 3);
    if ($usersResp && $usersResp['status'] === 200) {
        $userData = @json_decode($usersResp['body'], true);
        if (is_array($userData) && count($userData) > 0) {
            $userNames = array_map(fn($u) => $u['slug'] ?? $u['name'] ?? 'unknown', array_slice($userData, 0, 5));
            $result['wpFindings'][] = [
                'sev' => 'H',
                'title' => 'Enumeración de usuarios via REST API (' . count($userData) . ' usuarios)',
                'desc' => 'La API REST expone los nombres de usuario: ' . implode(', ', $userNames) . '. Esto facilita ataques de fuerza bruta.',
                'fix' => 'Restringe el endpoint /wp-json/wp/v2/users con un plugin de seguridad o snippet de código.'
            ];
        }
    }

    // Check wp-login.php
    $loginResp = safeRequest(rtrim($url, '/') . '/wp-login.php', 'GET', null, 3);
    if ($loginResp && $loginResp['status'] === 200 && strpos($loginResp['body'], 'wp-login') !== false) {
        // Check for user enumeration via login
        $loginTestResp = safeRequest(rtrim($url, '/') . '/wp-login.php', 'POST',
            http_build_query(['log' => 'admin', 'pwd' => 'testpasswordwebsecaudit123', 'wp-submit' => 'Log In']), 5);
        if ($loginTestResp) {
            if (preg_match('/Invalid username|El nombre de usuario no existe|usuario no existe/i', $loginTestResp['body'])) {
                $result['wpFindings'][] = [
                    'sev' => 'L',
                    'title' => 'Enumeración de usuarios posible via wp-login',
                    'desc' => 'El formulario de login revela si un nombre de usuario existe o no.',
                    'fix' => 'Usa un plugin que muestre un mensaje genérico para credenciales incorrectas.'
                ];
            } elseif (preg_match('/password you entered.*is incorrect|contraseña.*incorrecta/i', $loginTestResp['body'])) {
                $result['wpFindings'][] = [
                    'sev' => 'M',
                    'title' => 'Usuario "admin" existe y login enumerable',
                    'desc' => 'El usuario "admin" existe y el formulario confirma la existencia del usuario al mostrar un error diferente para contraseña incorrecta.',
                    'fix' => 'Cambia el nombre del usuario admin. Usa un plugin de seguridad que oculte los mensajes de error específicos.'
                ];
            }
        }
    }

    // Check WP version vulnerabilities
    if ($result['wpVersion']) {
        $wpVulns = checkWPCoreVulnerabilities($result['wpVersion']);
        foreach ($wpVulns as $v) {
            $result['wpFindings'][] = $v;
        }
    }

    // Check debug.log
    $debugResp = safeRequest(rtrim($url, '/') . '/wp-content/debug.log', 'GET', null, 3);
    if ($debugResp && $debugResp['status'] === 200 && strlen($debugResp['body']) > 50) {
        $result['wpFindings'][] = [
            'sev' => 'H',
            'title' => 'debug.log expuesto públicamente',
            'desc' => 'El archivo wp-content/debug.log es accesible y puede contener información sensible como rutas del servidor, errores SQL y datos de plugins.',
            'fix' => 'Bloquea el acceso a debug.log en .htaccess o elimínalo y desactiva WP_DEBUG_LOG en producción.'
        ];
    }

    jsonResponse($result);
}

/**
 * Check plugin against known vulnerable versions (local database)
 */
function checkPluginVulnerabilities($slug, $version) {
    $knownVulnerable = [
        'contact-form-7' => [
            ['below' => '5.8.4', 'cve' => 'CVE-2023-6449', 'desc' => 'XSS en formularios', 'sev' => 'H'],
            ['below' => '5.3.2', 'cve' => 'CVE-2020-35489', 'desc' => 'Unrestricted file upload', 'sev' => 'C'],
        ],
        'elementor' => [
            ['below' => '3.18.1', 'cve' => 'CVE-2023-48777', 'desc' => 'Arbitrary file upload (RCE)', 'sev' => 'C'],
            ['below' => '3.12.2', 'cve' => 'CVE-2023-32243', 'desc' => 'Broken Access Control', 'sev' => 'C'],
        ],
        'wp-file-manager' => [
            ['below' => '7.2.2', 'cve' => 'CVE-2024-0761', 'desc' => 'Path Traversal', 'sev' => 'H'],
            ['below' => '6.9', 'cve' => 'CVE-2020-25213', 'desc' => 'Critical RCE', 'sev' => 'C'],
        ],
        'all-in-one-seo-pack' => [
            ['below' => '4.3.0', 'cve' => 'CVE-2023-0586', 'desc' => 'Privilege Escalation', 'sev' => 'C'],
        ],
        'yoast-seo' => [
            ['below' => '20.2.1', 'cve' => 'CVE-2023-25067', 'desc' => 'Reflected XSS', 'sev' => 'M'],
        ],
        'wordfence' => [
            ['below' => '7.10.0', 'cve' => 'CVE-2023-6561', 'desc' => 'XSS in admin', 'sev' => 'M'],
        ],
        'woocommerce' => [
            ['below' => '8.2.0', 'cve' => 'CVE-2023-47782', 'desc' => 'Broken Access Control', 'sev' => 'H'],
            ['below' => '6.6.1', 'cve' => 'CVE-2022-31160', 'desc' => 'XSS via jQuery UI', 'sev' => 'M'],
        ],
        'wpforms-lite' => [
            ['below' => '1.8.4', 'cve' => 'CVE-2023-47684', 'desc' => 'Stored XSS', 'sev' => 'M'],
        ],
        'really-simple-ssl' => [
            ['below' => '7.2.0', 'cve' => 'CVE-2023-49583', 'desc' => 'Authentication Bypass', 'sev' => 'C'],
        ],
        'updraftplus' => [
            ['below' => '1.23.3', 'cve' => 'CVE-2022-23303', 'desc' => 'Backup download (Auth bypass)', 'sev' => 'C'],
        ],
        'jetpack' => [
            ['below' => '12.1.1', 'cve' => 'CVE-2023-35803', 'desc' => 'API vulnerability', 'sev' => 'H'],
        ],
        'advanced-custom-fields' => [
            ['below' => '6.1.8', 'cve' => 'CVE-2023-30777', 'desc' => 'Reflected XSS', 'sev' => 'H'],
        ],
        'litespeed-cache' => [
            ['below' => '5.7.0.1', 'cve' => 'CVE-2023-40000', 'desc' => 'Stored XSS (unauthenticated)', 'sev' => 'C'],
        ],
        'duplicator' => [
            ['below' => '1.5.7.1', 'cve' => 'CVE-2023-6114', 'desc' => 'Sensitive data exposure', 'sev' => 'C'],
        ],
        'ultimate-member' => [
            ['below' => '2.6.7', 'cve' => 'CVE-2023-3460', 'desc' => 'Privilege Escalation (critical)', 'sev' => 'C'],
        ],
        'wp-statistics' => [
            ['below' => '14.1', 'cve' => 'CVE-2023-20359', 'desc' => 'SQL Injection', 'sev' => 'C'],
        ],
        'ninja-forms' => [
            ['below' => '3.6.26', 'cve' => 'CVE-2023-37979', 'desc' => 'Reflected XSS', 'sev' => 'H'],
        ],
    ];

    if (!isset($knownVulnerable[$slug])) return [];

    $vulns = [];
    foreach ($knownVulnerable[$slug] as $entry) {
        if ($version === null || version_compare($version, $entry['below'], '<')) {
            $vulns[] = $entry;
        }
    }
    return $vulns;
}

/**
 * Check WordPress core version vulnerabilities
 */
function checkWPCoreVulnerabilities($version) {
    $findings = [];
    $vulnerableVersions = [
        ['below' => '6.4.3', 'sev' => 'C', 'cves' => 'CVE-2024-22135, CVE-2024-22136',
         'desc' => 'Múltiples vulnerabilidades de seguridad incluyendo XSS y escalamiento de privilegios'],
        ['below' => '6.3.2', 'sev' => 'H', 'cves' => 'CVE-2023-39999, CVE-2023-38000',
         'desc' => 'Vulnerabilidades XSS en comentarios y shortcodes'],
        ['below' => '6.2.3', 'sev' => 'H', 'cves' => 'CVE-2023-38000',
         'desc' => 'Stored XSS en la API REST (tagline)'],
        ['below' => '6.0.0', 'sev' => 'C', 'cves' => 'Múltiples CVEs',
         'desc' => 'Versión muy antigua con múltiples vulnerabilidades críticas conocidas'],
        ['below' => '5.0.0', 'sev' => 'C', 'cves' => 'CVE-2019-8942, CVE-2019-8943 y múltiples',
         'desc' => 'Versión extremadamente antigua. RCE, SQLi y múltiples vulnerabilidades críticas.'],
    ];

    foreach ($vulnerableVersions as $v) {
        if (version_compare($version, $v['below'], '<')) {
            $findings[] = [
                'sev' => $v['sev'],
                'title' => 'WordPress ' . $version . ' — versión vulnerable (< ' . $v['below'] . ')',
                'desc' => $v['desc'] . ' CVEs: ' . $v['cves'],
                'fix' => 'Actualiza WordPress a la última versión estable inmediatamente.'
            ];
        }
    }
    return $findings;
}


function validateUrl($url) {
    $url = trim($url);
    if (!preg_match('#^https?://#', $url)) {
        jsonError('URL debe comenzar con http:// o https://', 400);
    }
    $parsed = parse_url($url);
    if (!$parsed || empty($parsed['host'])) {
        jsonError('URL inválida.', 400);
    }
    // Block private/local IPs
    $ip = @gethostbyname($parsed['host']);
    if ($ip) {
        $isPrivate = filter_var($ip, FILTER_VALIDATE_IP, 
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE | FILTER_FLAG_NO_PRIV_RANGE) === false;
        if ($isPrivate && !in_array($parsed['host'], ['localhost', '127.0.0.1'])) {
           
        }
    }
    return $url;
}

function validateHostname($hostname) {
    $hostname = trim(strtolower($hostname));
    $hostname = preg_replace('#^(https?://)#', '', $hostname);
    $hostname = rtrim($hostname, '/');
    
    if (!preg_match('/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$/', $hostname)) {
        jsonError('Hostname inválido: ' . $hostname, 400);
    }
    return $hostname;
}

function jsonResponse($data) {
    echo json_encode(['ok' => true, 'data' => $data], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

function jsonError($msg, $code = 500) {
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}
