<?php
// ============================================================
//  AUTH.PHP — Sicheres Login-System
//  - bcrypt Passwort-Hashing (cost=12)
//  - Secure Session Flags (HttpOnly, SameSite=Strict, Secure-only-via-HTTPS)
//  - IP-Binding (Session-Hijacking Schutz)
//  - User-Agent-Binding (SHA3-256)
//  - Brute-Force-Schutz (5 Versuche -> 15 Min Sperre)
//  - CSRF-Token Schutz
//  - Timing-Attack Schutz
//  - Session-Fixation Schutz
//  - Audit Logging
//  - Passwort aendern + Account anlegen (eingeloggte Nutzer)
// ============================================================
require_once __DIR__ . '/config.php';

function _isHttpsRequest(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') == 443)
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}

// ============================================================
//  SESSION
// ============================================================
function startSecureSession(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $isHttps = _isHttpsRequest();

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_name(SESSION_NAME);
    session_start();
    if (empty($_SESSION['__init'])) {
        session_regenerate_id(true);
        $_SESSION['__init'] = true;
    }
}

// ============================================================
//  LOGIN CHECK
// ============================================================
function isLoggedIn(): bool {
    startSecureSession();
    if (empty($_SESSION['user']) || empty($_SESSION['ts'])) return false;
    if (time() - $_SESSION['ts'] > SESSION_LIFETIME) {
        auditLog('SESSION_EXPIRED', $_SESSION['user'] ?? '?');
        session_destroy();
        return false;
    }
    if (($_SESSION['ip'] ?? '') !== ($_SERVER['REMOTE_ADDR'] ?? '')) {
        auditLog('SESSION_IP_MISMATCH', $_SESSION['user'] ?? '?');
        session_destroy();
        return false;
    }
    $uaHash = hash('sha3-256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    if (($_SESSION['ua'] ?? '') !== $uaHash) {
        auditLog('SESSION_UA_MISMATCH', $_SESSION['user'] ?? '?');
        session_destroy();
        return false;
    }
    $_SESSION['ts'] = time();
    return true;
}

function requireLogin(): void {
    if (!isLoggedIn()) { header('Location: index.php?e=auth'); exit; }
}

function currentUser(): string { return $_SESSION['user'] ?? ''; }

// ============================================================
//  CSRF
// ============================================================
function csrfToken(): string {
    startSecureSession();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function verifyCsrf(string $token): bool {
    return !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

function rotateCsrf(): void {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

// ============================================================
//  BRUTE FORCE
// ============================================================
function getLockouts(): array {
    if (!file_exists(LOCKOUT_FILE)) return [];
    $data = @json_decode(file_get_contents(LOCKOUT_FILE), true);
    return is_array($data) ? $data : [];
}

function saveLockouts(array $data): void {
    file_put_contents(LOCKOUT_FILE, json_encode($data), LOCK_EX);
}

function clientKey(): string {
    return hash('sha3-256', ($_SERVER['REMOTE_ADDR'] ?? '0') . '|' . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
}

function isLockedOut(): bool {
    $key = clientKey(); $data = getLockouts();
    if (!isset($data[$key])) return false;
    $e = $data[$key];
    if (time() - $e['last'] > LOCKOUT_SECS) {
        unset($data[$key]); saveLockouts($data); return false;
    }
    return $e['attempts'] >= MAX_ATTEMPTS;
}

function recordFail(): int {
    $key = clientKey(); $data = getLockouts();
    if (!isset($data[$key]) || time() - $data[$key]['last'] > LOCKOUT_SECS) {
        $data[$key] = ['attempts' => 0, 'last' => time()];
    }
    $data[$key]['attempts']++; $data[$key]['last'] = time();
    saveLockouts($data);
    return $data[$key]['attempts'];
}

function clearFails(): void {
    $key = clientKey(); $data = getLockouts();
    unset($data[$key]); saveLockouts($data);
}

function lockoutRemaining(): int {
    $key = clientKey(); $data = getLockouts();
    if (!isset($data[$key])) return 0;
    return max(0, LOCKOUT_SECS - (time() - $data[$key]['last']));
}

// ============================================================
//  AUDIT LOG
// ============================================================
function auditLog(string $event, string $user = ''): void {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '?';
    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '?', 0, 80);
    $line = date('Y-m-d H:i:s') . " | {$event} | user={$user} | ip={$ip} | ua={$ua}\n";
    @file_put_contents(LOG_FILE, $line, FILE_APPEND | LOCK_EX);
}

// ============================================================
//  USER STORE — users.json (Quelle der Wahrheit nach erstem Run)
// ============================================================
function loadUsers(): array {
    if (file_exists(USERS_FILE)) {
        $fp = @fopen(USERS_FILE, 'r');
        if ($fp) {
            @flock($fp, LOCK_SH);
            $raw = stream_get_contents($fp);
            @flock($fp, LOCK_UN);
            fclose($fp);
            $data = json_decode((string)$raw, true);
            if (is_array($data) && $data !== []) return $data;
        }
        return USERS;
    }
    saveUsers(USERS);
    return USERS;
}

function saveUsers(array $users): bool {
    $tmp = USERS_FILE . '.tmp';
    $fp  = @fopen($tmp, 'w');
    if (!$fp) return false;
    @flock($fp, LOCK_EX);
    $json = json_encode($users, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    fwrite($fp, $json === false ? '{}' : $json);
    fflush($fp);
    @flock($fp, LOCK_UN);
    fclose($fp);
    @chmod($tmp, 0600);
    return @rename($tmp, USERS_FILE);
}

function userList(): array {
    $out = [];
    foreach (loadUsers() as $name => $u) {
        $out[] = [
            'name'    => $name,
            'display' => $u['display'] ?? $name,
            'color'   => $u['color']   ?? '#0a84ff',
        ];
    }
    return $out;
}

// ============================================================
//  VALIDIERUNG
// ============================================================
function validateUsername(string $u): ?string {
    $u = trim($u);
    if ($u === '')               return 'Benutzername darf nicht leer sein.';
    if (strlen($u) < UN_MIN_LEN) return 'Benutzername muss mindestens ' . UN_MIN_LEN . ' Zeichen lang sein.';
    if (strlen($u) > UN_MAX_LEN) return 'Benutzername darf hoechstens ' . UN_MAX_LEN . ' Zeichen lang sein.';
    if (!preg_match('/^[A-Za-z][A-Za-z0-9_-]*$/', $u))
        return 'Nur Buchstaben, Ziffern, _ und - erlaubt; muss mit Buchstabe beginnen.';
    return null;
}

function validatePassword(string $p): ?string {
    $len = strlen($p);
    if ($len < PW_MIN_LEN) return 'Passwort muss mindestens ' . PW_MIN_LEN . ' Zeichen lang sein.';
    if ($len > PW_MAX_LEN) return 'Passwort darf hoechstens ' . PW_MAX_LEN . ' Zeichen lang sein (bcrypt-Limit).';
    $classes = 0;
    if (preg_match('/[a-z]/', $p))        $classes++;
    if (preg_match('/[A-Z]/', $p))        $classes++;
    if (preg_match('/[0-9]/', $p))        $classes++;
    if (preg_match('/[^A-Za-z0-9]/', $p)) $classes++;
    if ($classes < 3) return 'Passwort braucht mindestens 3 verschiedene Zeichen-Arten (a-z, A-Z, 0-9, Sonderzeichen).';
    return null;
}

function passwordsMatch(string $a, string $b): bool { return hash_equals($a, $b); }

// ============================================================
//  PASSWORT AENDERN
// ============================================================
function changePassword(string $current, string $new, string $confirm, string $csrf): array {
    if (!isLoggedIn())            return ['ok'=>false,'error'=>'Nicht eingeloggt.'];
    if (!verifyCsrf($csrf)) {
        auditLog('PW_CHANGE_CSRF_FAIL', currentUser());
        return ['ok'=>false,'error'=>'Ungueltige Anfrage. Seite neu laden.'];
    }
    if (!passwordsMatch($new, $confirm))
        return ['ok'=>false,'error'=>'Die beiden neuen Passwoerter stimmen nicht ueberein.'];
    if ($current === $new)
        return ['ok'=>false,'error'=>'Neues Passwort muss sich vom alten unterscheiden.'];
    if (($err = validatePassword($new)) !== null)
        return ['ok'=>false,'error'=>$err];

    $users = loadUsers();
    $me    = currentUser();
    if (!isset($users[$me])) {
        auditLog('PW_CHANGE_USER_MISSING', $me);
        session_destroy();
        return ['ok'=>false,'error'=>'Account nicht gefunden. Bitte neu einloggen.'];
    }
    if (!password_verify($current, $users[$me]['hash'])) {
        auditLog('PW_CHANGE_BAD_CURRENT', $me);
        return ['ok'=>false,'error'=>'Aktuelles Passwort ist falsch.'];
    }

    $users[$me]['hash'] = password_hash($new, PASSWORD_BCRYPT, ['cost' => 12]);
    if (!saveUsers($users)) {
        auditLog('PW_CHANGE_SAVE_FAIL', $me);
        return ['ok'=>false,'error'=>'Speichern fehlgeschlagen. Bitte erneut versuchen.'];
    }

    session_regenerate_id(true);
    rotateCsrf();
    auditLog('PW_CHANGED', $me);
    return ['ok'=>true];
}

// ============================================================
//  ACCOUNT ANLEGEN — eingeloggte Nutzer
// ============================================================
function createAccount(string $username, string $password, string $confirm, string $csrf, ?string $color = null): array {
    if (!isLoggedIn())            return ['ok'=>false,'error'=>'Nicht eingeloggt.'];
    if (!verifyCsrf($csrf)) {
        auditLog('ACCOUNT_CREATE_CSRF_FAIL', currentUser());
        return ['ok'=>false,'error'=>'Ungueltige Anfrage. Seite neu laden.'];
    }
    $username = trim($username);
    if (($err = validateUsername($username)) !== null) return ['ok'=>false,'error'=>$err];
    if (!passwordsMatch($password, $confirm))
        return ['ok'=>false,'error'=>'Die beiden Passwoerter stimmen nicht ueberein.'];
    if (($err = validatePassword($password)) !== null) return ['ok'=>false,'error'=>$err];

    $users = loadUsers();
    foreach (array_keys($users) as $existing) {
        if (strcasecmp($existing, $username) === 0)
            return ['ok'=>false,'error'=>'Benutzername ist bereits vergeben.'];
    }

    $palette = ['#7f6af8','#0a84ff','#16a34a','#dc2626','#d97706','#0891b2','#7c3aed'];
    if ($color !== null && preg_match('/^#[0-9a-fA-F]{6}$/', $color)) {
        $userColor = $color;
    } else {
        $userColor = $palette[count($users) % count($palette)];
    }

    $users[$username] = [
        'hash'    => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
        'display' => $username,
        'color'   => $userColor,
    ];

    if (!saveUsers($users)) {
        auditLog('ACCOUNT_CREATE_SAVE_FAIL', currentUser());
        return ['ok'=>false,'error'=>'Speichern fehlgeschlagen. Bitte erneut versuchen.'];
    }

    auditLog('ACCOUNT_CREATED:' . $username, currentUser());
    return ['ok'=>true,'username'=>$username];
}

// ============================================================
//  LOGIN ATTEMPT
// ============================================================
function attemptLogin(string $username, string $password, string $csrf): array {
    startSecureSession();

    if (!verifyCsrf($csrf)) {
        auditLog('CSRF_FAIL', $username);
        return ['ok'=>false,'error'=>'Ungueltige Anfrage. Seite neu laden.'];
    }
    if (isLockedOut()) {
        $mins = ceil(lockoutRemaining() / 60);
        auditLog('LOCKOUT_BLOCKED', $username);
        return ['ok'=>false,'error'=>"Zu viele Fehlversuche. Bitte {$mins} Min. warten."];
    }

    $users = loadUsers();

    $dummyHash  = '$2y$12$CwTycUXWue0Thq9StjUM0uJ8.Z6fG5q.dD8oR8yYJ7eP4GvA1bW9G';
    $userExists = isset($users[$username]);
    $hash       = $userExists ? $users[$username]['hash'] : $dummyHash;

    $passwordOk = password_verify($password, $hash);

    if (!$userExists || !$passwordOk) {
        $attempts = recordFail();
        $left     = MAX_ATTEMPTS - $attempts;
        auditLog('LOGIN_FAIL', $username);
        if ($left <= 0) {
            $mins = ceil(LOCKOUT_SECS / 60);
            return ['ok'=>false,'error'=>"Zu viele Fehlversuche. Gesperrt fuer {$mins} Min."];
        }
        return ['ok'=>false,'error'=>"Falscher Benutzername oder Passwort. Noch {$left} Versuch" . ($left===1?'':'e') . "."];
    }

    clearFails();
    session_regenerate_id(true);
    rotateCsrf();
    $_SESSION['user'] = $username;
    $_SESSION['ts']   = time();
    $_SESSION['ip']   = $_SERVER['REMOTE_ADDR'] ?? '';
    $_SESSION['ua']   = hash('sha3-256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    auditLog('LOGIN_OK', $username);
    return ['ok'=>true];
}

// ============================================================
//  LOGOUT
// ============================================================
function logout(): void {
    startSecureSession();
    $user = currentUser();
    auditLog('LOGOUT', $user);
    session_unset();
    session_destroy();
    $isHttps = _isHttpsRequest();
    setcookie(SESSION_NAME, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}
