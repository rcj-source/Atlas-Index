<?php
/**
 * ============================================================
 *  ATLAS CAPITAL — proxy.php SEGURO
 * ============================================================
 *  Este archivo actúa como puente entre tu web y el Worker
 *  de Cloudflare. Añade validaciones que el frontend no puede
 *  hacer por sí mismo.
 *
 *  INSTRUCCIONES:
 *  1. Pon tu URL de Worker en WORKER_BASE_URL
 *  2. Sube este archivo junto con index.html
 * ============================================================
 */

declare(strict_types=1);

// ── Configura tu Worker aquí ──────────────────────────────────
const WORKER_BASE_URL = 'https://yellow-tooth-e55d.ramirezricardocontacto.workers.dev';

// ── Cabeceras de respuesta ────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// ── Rate limiting simple por IP (archivo temporal) ───────────
function checkRateLimit(): bool {
    $ip      = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $file    = sys_get_temp_dir() . '/atlas_rl_' . md5($ip) . '.json';
    $now     = time();
    $window  = 60;   // segundos
    $maxHits = 15;   // máximo 15 requests por minuto por IP

    $data = ['count' => 0, 'start' => $now];
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        if ($raw) $data = json_decode($raw, true) ?: $data;
    }

    if ($now - $data['start'] > $window) {
        $data = ['count' => 1, 'start' => $now];
    } else {
        $data['count']++;
    }

    file_put_contents($file, json_encode($data), LOCK_EX);
    return $data['count'] > $maxHits;
}

// ── Validar dirección de wallet Solana ───────────────────────
function isValidSolanaWallet(string $wallet): bool {
    return (bool) preg_match('/^[1-9A-HJ-NP-Za-km-z]{32,44}$/', $wallet);
}

// ── Función para llamar al Worker ─────────────────────────────
function callWorker(string $path, string $method = 'GET', ?array $body = null): array {
    $url     = WORKER_BASE_URL . $path;
    $options = [
        'http' => [
            'method'        => $method,
            'timeout'       => 20,
            'ignore_errors' => true,
            'header'        => "User-Agent: AtlasCapitalProxy/2.0\r\nAccept: application/json\r\n",
        ],
        'ssl' => [
            'verify_peer'      => true,
            'verify_peer_name' => true,
        ],
    ];

    if ($body !== null) {
        $json = json_encode($body);
        $options['http']['header']  .= "Content-Type: application/json\r\nContent-Length: " . strlen($json) . "\r\n";
        $options['http']['content']  = $json;
    }

    $context = stream_context_create($options);
    $result  = @file_get_contents($url, false, $context);

    if ($result === false) {
        return ['error' => 'No se pudo conectar con el servidor de verificación'];
    }

    $decoded = json_decode($result, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['error' => 'Respuesta inválida del servidor'];
    }

    return $decoded;
}

// ── Extraer código HTTP de la respuesta ──────────────────────
function getResponseCode(): int {
    if (!isset($http_response_header) || !is_array($http_response_header)) return 200;
    preg_match('#HTTP/\S+\s+(\d{3})#', $http_response_header[0], $m);
    return isset($m[1]) ? (int)$m[1] : 200;
}

// ── Salir con error ───────────────────────────────────────────
function bail(int $code, string $message): never {
    http_response_code($code);
    echo json_encode(['error' => $message]);
    exit;
}

// ════════════════════════════════════════════════════════════
//  ROUTER
// ════════════════════════════════════════════════════════════

if (checkRateLimit()) {
    bail(429, 'Demasiadas solicitudes. Espera un momento.');
}

$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action        = $_GET['action'] ?? '';

// ── POST /proxy.php?action=verify  →  verificar firma + emitir token ──
if ($requestMethod === 'POST' && $action === 'verify') {
    $raw  = file_get_contents('php://input');
    $body = json_decode($raw, true);

    if (!$body || !isset($body['wallet'], $body['message'], $body['signature'])) {
        bail(400, 'Faltan campos: wallet, message, signature');
    }

    $wallet    = trim($body['wallet']);
    $message   = trim($body['message']);
    $signature = trim($body['signature']);

    if (!isValidSolanaWallet($wallet)) {
        bail(400, 'Dirección de wallet inválida');
    }
    if (strlen($message) > 500 || strlen($signature) > 200) {
        bail(400, 'Parámetros demasiado largos');
    }

    $response = callWorker('/verify', 'POST', [
        'wallet'    => $wallet,
        'message'   => $message,
        'signature' => $signature,
    ]);

    echo json_encode($response);
    exit;
}

// ── GET /proxy.php?action=check-token&token=XXX  →  validar JWT ──
if ($requestMethod === 'GET' && $action === 'check-token') {
    $token = trim($_GET['token'] ?? '');

    if ($token === '' || strlen($token) > 1000) {
        bail(400, 'Token inválido');
    }

    // Validar formato JWT básico (3 partes separadas por punto)
    if (substr_count($token, '.') !== 2) {
        bail(400, 'Formato de token inválido');
    }

    $response = callWorker('/check-token?token=' . rawurlencode($token));

    echo json_encode($response);
    exit;
}

// ── GET /proxy.php?action=calendar&token=XXX  →  calendario FMP ──
if ($requestMethod === 'GET' && $action === 'calendar') {
    $token = trim($_GET['token'] ?? '');
    if ($token === '' || strlen($token) > 1000) bail(400, 'Token inválido');
    $response = callWorker('/calendar?token=' . rawurlencode($token));
    echo json_encode($response);
    exit;
}

// ── GET /proxy.php?action=fred-data&token=XXX  →  datos FRED ──
if ($requestMethod === 'GET' && $action === 'fred-data') {
    $token = trim($_GET['token'] ?? '');
    if ($token === '' || strlen($token) > 1000) bail(400, 'Token inválido');
    $response = callWorker('/fred-data?token=' . rawurlencode($token));
    echo json_encode($response);
    exit;
}

// Ruta no encontrada
bail(404, 'Acción no reconocida');
