<?php
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';");
header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');

require_once __DIR__ . '/auth.php';

$loginError = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['_action'] ?? '') === 'login') {
    $res = attemptLogin(trim($_POST['username'] ?? ''), $_POST['password'] ?? '', $_POST['_csrf'] ?? '');
    if ($res['ok']) { header('Location: index.php'); exit; }
    $loginError = $res['error'];
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['_action'] ?? '') === 'logout') {
    logout(); header('Location: index.php?bye=1'); exit;
}

$apiAction = $_GET['a'] ?? '';
if ($apiAction !== '') {
    // Output-Buffer kapselt die ganze API-Route. Wenn PHP irgendeine
    // Deprecation/Warning emittiert, landet sie nicht im JSON-Body.
    ob_start();
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    // Deprecations + Warnings nicht in den Output schreiben — wir loggen
    // sie ueber den Default-Logger (access.log existiert ja).
    @ini_set('display_errors', '0');
    @ini_set('log_errors', '1');

    set_exception_handler(function($e) {
        if (ob_get_length() !== false) ob_clean();
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok'=>false, 'e'=>'exception', 'error'=>$e->getMessage()]);
        exit;
    });

    try {
        if (!isLoggedIn()) {
            if (ob_get_length() !== false) ob_clean();
            http_response_code(401); echo json_encode(['e'=>'auth']); exit;
        }
        if (in_array($apiAction, ['add','del','upd','upd_status','change_pw','create_acct','invite_accept','invite_decline','wm_save','casino_add','casino_del'], true)) {
            $body = json_decode(file_get_contents('php://input'), true) ?? [];
            if (!verifyCsrf($body['_csrf'] ?? '')) {
                if (ob_get_length() !== false) ob_clean();
                http_response_code(403); echo json_encode(['e'=>'csrf']); exit;
            }
        }
        // Vor dem eigentlichen Handler nochmal puffer leeren — falls Header
        // oder Funktionen oben Notices produziert haben.
        if (ob_get_length() !== false) ob_clean();
        handleApi($apiAction);
        // Falls handleApi via return (nicht exit) zurueckkehrt, sicher schicken:
        ob_end_flush();
        exit;
    } catch (\Throwable $e) {
        if (ob_get_length() !== false) ob_clean();
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok'=>false, 'e'=>'exception', 'error'=>$e->getMessage()]);
        exit;
    }
}

$loggedIn = isLoggedIn();
$me       = currentUser();
$csrf     = csrfToken();

function csvRead(): array {
    // Datei initial anlegen (mit Header)
    if (!file_exists(CSV_FILE)) {
        $fp = fopen(CSV_FILE, 'w');
        if ($fp) {
            flock($fp, LOCK_EX);
            fputcsv($fp, CSV_HEADER, ',', '"');
            flock($fp, LOCK_UN);
            fclose($fp);
        }
        return [];
    }
    $fp = fopen(CSV_FILE, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);                       // Shared-Lock gegen Race-Conditions

    // Header lesen + UTF-8-BOM entfernen (Excel-Export schreibt oft BOM)
    $header = fgetcsv($fp, 0, ',', '"');
    if ($header && isset($header[0])) {
        $header[0] = preg_replace('/^\xEF\xBB\xBF/u', '', $header[0]);
    }

    $rows  = [];
    $cols  = count(CSV_HEADER);
    while (($row = fgetcsv($fp, 0, ',', '"')) !== false) {
        // Leere Zeilen überspringen (fgetcsv liefert dafür [null])
        if ($row === null) continue;
        if (count($row) === 1 && ($row[0] === null || $row[0] === '')) continue;
        // Mindestens id+date+sport+desc+league+market+stake+odds müssen da sein
        if (count($row) < 8) continue;
        $padded = array_pad($row, $cols, '');
        $rows[] = array_combine(CSV_HEADER, array_slice($padded, 0, $cols));
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return array_reverse($rows);
}

function csvWrite(array $rows): void {
    // Atomarer Write: erst in Temp-Datei, dann rename → kein halb-geschriebener CSV
    $rows = array_reverse($rows);
    $tmp  = CSV_FILE . '.tmp';
    $fp   = fopen($tmp, 'w');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    fputcsv($fp, CSV_HEADER, ',', '"');
    foreach ($rows as $r) fputcsv($fp, array_values($r), ',', '"');
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    @rename($tmp, CSV_FILE);
}

// ============================================================
//  SHARES STORE — shares.csv: bet_id, user, stake
//  (Issue #1+#4: Shared Bets — Bets mit mehreren Stake-Anteilen)
// ============================================================
// SHARES_HEADER ist nun in config.php definiert

function sharesRead(): array {
    if (!file_exists(SHARES_FILE)) {
        $fp = @fopen(SHARES_FILE, 'w');
        if ($fp) {
            flock($fp, LOCK_EX);
            fputcsv($fp, SHARES_HEADER, ',', '"');
            flock($fp, LOCK_UN);
            fclose($fp);
        }
        return [];
    }
    $fp = @fopen(SHARES_FILE, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    fgetcsv($fp, 0, ',', '"'); // skip header
    $rows = [];
    while (($row = fgetcsv($fp, 0, ',', '"')) !== false) {
        if ($row === null || (count($row) === 1 && ($row[0] === null || $row[0] === ''))) continue;
        if (count($row) < 3) continue;
        $rows[] = [
            'bet_id' => (string)$row[0],
            'user'   => (string)$row[1],
            'stake'  => (float)$row[2],
        ];
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return $rows;
}

function sharesWrite(array $rows): void {
    $tmp = SHARES_FILE . '.tmp';
    $fp  = fopen($tmp, 'w');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    fputcsv($fp, SHARES_HEADER, ',', '"');
    foreach ($rows as $r) {
        fputcsv($fp, [(string)($r['bet_id'] ?? ''), (string)($r['user'] ?? ''), (float)($r['stake'] ?? 0)], ',', '"');
    }
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    @rename($tmp, SHARES_FILE);
}

function sharesForBet(string $betId): array {
    $out = [];
    foreach (sharesRead() as $s) {
        if ($s['bet_id'] === $betId) $out[] = $s;
    }
    return $out;
}

// ============================================================
//  INVITES STORE — bet_invites.csv (Issue #1+#4: Invite-Flow)
//  Schema: id, bet_id, from_user, to_user, stake, status, created_at
//  status: pending | accepted | declined
// ============================================================
function invitesRead(): array {
    if (!file_exists(INVITES_FILE)) {
        $fp = @fopen(INVITES_FILE, 'w');
        if ($fp) {
            flock($fp, LOCK_EX);
            fputcsv($fp, INVITES_HEADER, ',', '"');
            flock($fp, LOCK_UN);
            fclose($fp);
        }
        return [];
    }
    $fp = @fopen(INVITES_FILE, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    fgetcsv($fp, 0, ',', '"'); // skip header
    $rows = [];
    while (($row = fgetcsv($fp, 0, ',', '"')) !== false) {
        if ($row === null) continue;
        if (count($row) === 1 && ($row[0] === null || $row[0] === '')) continue;
        if (count($row) < 7) continue;
        $rows[] = [
            'id'         => (string)$row[0],
            'bet_id'     => (string)$row[1],
            'from_user'  => (string)$row[2],
            'to_user'    => (string)$row[3],
            'stake'      => (float)$row[4],
            'status'     => (string)$row[5],
            'created_at' => (string)$row[6],
        ];
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return $rows;
}

function invitesWrite(array $rows): void {
    $tmp = INVITES_FILE . '.tmp';
    $fp  = fopen($tmp, 'w');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    fputcsv($fp, INVITES_HEADER, ',', '"');
    foreach ($rows as $r) {
        fputcsv($fp, [
            (string)($r['id']         ?? ''),
            (string)($r['bet_id']     ?? ''),
            (string)($r['from_user']  ?? ''),
            (string)($r['to_user']    ?? ''),
            (float) ($r['stake']      ?? 0),
            (string)($r['status']     ?? 'pending'),
            (string)($r['created_at'] ?? ''),
        ], ',', '"');
    }
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    @rename($tmp, INVITES_FILE);
}

// Pending Invites fuer einen User (zeigen wir im UI als Badge + Liste).
function pendingInvitesForUser(string $user): array {
    $out = [];
    foreach (invitesRead() as $i) {
        if ($i['to_user'] === $user && $i['status'] === 'pending') $out[] = $i;
    }
    return $out;
}

// ============================================================
//  TEAMS STORE — teams.json
// ============================================================
function teamsRead(): array {
    if (!file_exists(TEAMS_FILE)) return [];
    $raw = @file_get_contents(TEAMS_FILE);
    if ($raw === false) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

// ============================================================
//  KOMBI LEGS STORE — kombi_legs.csv
//  Eine Zeile pro Leg einer Kombiwette: bet_id, leg_idx, team, desc, odds
// ============================================================
function kombiLegsRead(): array {
    if (!file_exists(KOMBI_LEGS_FILE)) {
        $fp = @fopen(KOMBI_LEGS_FILE, 'w');
        if ($fp) {
            flock($fp, LOCK_EX);
            fputcsv($fp, KOMBI_LEGS_HEADER, ',', '"');
            flock($fp, LOCK_UN);
            fclose($fp);
        }
        return [];
    }
    $fp = @fopen(KOMBI_LEGS_FILE, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    fgetcsv($fp, 0, ',', '"'); // skip header
    $rows = [];
    while (($row = fgetcsv($fp, 0, ',', '"')) !== false) {
        if ($row === null) continue;
        if (count($row) === 1 && ($row[0] === null || $row[0] === '')) continue;
        if (count($row) < 5) continue;
        $rows[] = [
            'bet_id'  => (string)$row[0],
            'leg_idx' => (int)$row[1],
            'team'    => (string)$row[2],
            'desc'    => (string)$row[3],
            'odds'    => (float)$row[4],
        ];
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return $rows;
}

function kombiLegsWrite(array $rows): void {
    $tmp = KOMBI_LEGS_FILE . '.tmp';
    $fp  = fopen($tmp, 'w');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    fputcsv($fp, KOMBI_LEGS_HEADER, ',', '"');
    foreach ($rows as $r) {
        fputcsv($fp, [
            (string)($r['bet_id']  ?? ''),
            (int)   ($r['leg_idx'] ?? 0),
            (string)($r['team']    ?? ''),
            (string)($r['desc']    ?? ''),
            (float) ($r['odds']    ?? 0),
        ], ',', '"');
    }
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    @rename($tmp, KOMBI_LEGS_FILE);
}

// Aggregierte Team-Stats: Win/Loss/PnL pro Team.
// Logik: Eine Kombiwette ist eindeutig "won" oder "lost" -> jedes Leg dieser
// Wette zaehlt entsprechend. Cashouts behandeln wir wie partielle Erfolge,
// indem wir den Status NICHT in die W/L-Counter aufnehmen, aber den
// proportionalen PnL-Anteil (PnL / Anzahl Legs) jeder Team-Statistik
// zurechnen.
function teamStats(string $forUser = ''): array {
    $bets   = csvRead();
    $shares = sharesRead();
    $legs   = kombiLegsRead();
    if (empty($legs)) return [];

    // Lookup bet by id
    $betById = [];
    foreach ($bets as $b) $betById[$b['id']] = $b;

    // Owner-Filter & Stake-Anteil bestimmen
    $stakeFractionFor = function(string $betId) use ($shares, $forUser): float {
        if ($forUser === '') return 1.0;
        $rel = array_values(array_filter($shares, fn($s) => $s['bet_id'] === $betId));
        if (empty($rel)) {
            // Solo-Bet
            return 1.0;
        }
        $total = 0; $mine = 0;
        foreach ($rel as $r) { $total += (float)$r['stake']; if ($r['user'] === $forUser) $mine = (float)$r['stake']; }
        return $total > 0 ? $mine / $total : 0.0;
    };

    // Kombi-Bet PnL (vereinfacht: stake*(combo-odds) - tax, je nach Status)
    // Wir nutzen den existierenden Datensatz: gross/net berechnen analog zu
    // taxedReturn() im JS — aber nur wenn der Bet won/lost/cashout ist.
    $stats = [];   // [team => ['cnt'=>, 'won'=>, 'lost'=>, 'pnl'=>]]

    // Group legs by bet_id
    $legsByBet = [];
    foreach ($legs as $l) $legsByBet[$l['bet_id']][] = $l;

    foreach ($legsByBet as $bid => $betLegs) {
        if (!isset($betById[$bid])) continue;
        $b = $betById[$bid];
        if (!in_array($b['status'], ['won','lost','cashout'], true)) continue; // open ueberspringen

        $stake   = (float)$b['stake'];
        $odds    = (float)$b['odds'];
        $tax     = (float)$b['tax_rate'];
        $cashout = (float)$b['cashout'];

        // PnL berechnen (gleiche Logik wie JS calcPnL/taxedReturn neue Variante)
        $pnl = 0.0;
        if ($b['status'] === 'won') {
            $gross  = $stake * $odds;
            $profit = max(0, $gross - $stake);
            $taxAmt = $profit * $tax;
            $net    = $stake + ($profit - $taxAmt);
            $pnl    = $net - $stake;
        } elseif ($b['status'] === 'lost') {
            $pnl = -$stake;
        } else { // cashout
            $pnl = $cashout - $stake;
        }

        $frac = $stakeFractionFor($bid);
        $myPnl = $pnl * $frac;

        $legCount = count($betLegs);
        $perLeg   = $legCount > 0 ? $myPnl / $legCount : 0;

        foreach ($betLegs as $leg) {
            $team = trim($leg['team']);
            if ($team === '') continue;
            if (!isset($stats[$team])) $stats[$team] = ['cnt'=>0,'won'=>0,'lost'=>0,'pnl'=>0.0];
            $stats[$team]['cnt']++;
            if ($b['status'] === 'won')   $stats[$team]['won']++;
            if ($b['status'] === 'lost')  $stats[$team]['lost']++;
            $stats[$team]['pnl'] += $perLeg;
        }
    }

    // Sortiert als Liste rausgeben
    $out = [];
    foreach ($stats as $team => $s) {
        $out[] = [
            'team' => $team,
            'cnt'  => $s['cnt'],
            'won'  => $s['won'],
            'lost' => $s['lost'],
            'pnl'  => round($s['pnl'], 2),
        ];
    }
    usort($out, fn($a, $b) => $b['pnl'] <=> $a['pnl']);
    return $out;
}

// Validiert + normalisiert ein participants-Array.
// Input z.B.: ['Felix' => 30, 'Paul' => 12]
// Returns: list of ['user' => 'Felix', 'stake' => 30.0] OR null bei Fehler.
function normalizeParticipants($participants): ?array {
    if (!is_array($participants) || empty($participants)) return null;
    $users = loadUsers();
    $out   = [];
    foreach ($participants as $name => $stake) {
        $name  = trim((string)$name);
        $stake = is_numeric($stake) ? (float)$stake : 0.0;
        if ($name === '' || $stake <= 0) continue;
        if (!isset($users[$name])) continue; // Unbekannter User -> verwerfen
        $out[] = ['user' => $name, 'stake' => round($stake, 2)];
    }
    return count($out) >= 2 ? $out : null; // mind. 2 Teilnehmer fuer 'shared'
}

// ============================================================
//  FIXTURES (Issue #2 — TheOddsAPI Integration)
//  Server-seitiger Fetch + JSON-Cache. Kein cURL noetig (manche
//  XAMPP-Installs haben curl-Extension nicht aktiv) — wir nutzen
//  file_get_contents + stream_context.
// ============================================================
function fixturesCacheRead(): ?array {
    if (!file_exists(FIXTURES_CACHE_FILE)) return null;
    $raw = @file_get_contents(FIXTURES_CACHE_FILE);
    if ($raw === false) return null;
    $data = json_decode($raw, true);
    if (!is_array($data) || empty($data['fetched_at'])) return null;
    if (time() - (int)$data['fetched_at'] > FIXTURES_CACHE_TTL) return null;
    return $data;
}

function fixturesCacheWrite(array $data): void {
    $tmp = FIXTURES_CACHE_FILE . '.tmp';
    @file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX);
    @rename($tmp, FIXTURES_CACHE_FILE);
}

function fetchTheOddsApi(string $sportKey): ?array {
    if (THEODDSAPI_KEY === '') return null;
    $url = 'https://api.the-odds-api.com/v4/sports/'
         . rawurlencode($sportKey)
         . '/odds/?apiKey=' . rawurlencode(THEODDSAPI_KEY)
         . '&regions=eu&markets=h2h&oddsFormat=decimal&dateFormat=iso';

    $ctx = stream_context_create([
        'http' => [
            'method'        => 'GET',
            'timeout'       => FIXTURES_TIMEOUT_S,
            'ignore_errors' => true,
            'header'        => "Accept: application/json\r\nUser-Agent: WettPro/1.0\r\n",
        ],
        'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
    ]);

    $raw = @file_get_contents($url, false, $ctx);
    if ($raw === false) return null;
    $data = json_decode($raw, true);
    if (!is_array($data)) return null;
    return $data;
}

// Normalisiert TheOddsAPI-Events in unser internes Format.
// Ein Event -> { id, sport_key, league, home, away, kickoff(iso),
//                odds: {home: x, draw: y|null, away: z}, source }
function normalizeFixtureEvents(array $events, string $sportKey): array {
    $out = [];
    foreach ($events as $e) {
        if (empty($e['id']) || empty($e['commence_time'])) continue;
        $home = (string)($e['home_team'] ?? '');
        $away = (string)($e['away_team'] ?? '');
        if ($home === '' || $away === '') continue;

        // Beste H2H-Quoten ueber alle Bookies finden
        $best = ['home' => null, 'draw' => null, 'away' => null];
        foreach (($e['bookmakers'] ?? []) as $bm) {
            foreach (($bm['markets'] ?? []) as $m) {
                if (($m['key'] ?? '') !== 'h2h') continue;
                foreach (($m['outcomes'] ?? []) as $o) {
                    $name = (string)($o['name']  ?? '');
                    $px   = (float)($o['price'] ?? 0);
                    if ($px <= 1) continue;
                    if ($name === $home) {
                        if ($best['home'] === null || $px > $best['home']) $best['home'] = $px;
                    } elseif ($name === $away) {
                        if ($best['away'] === null || $px > $best['away']) $best['away'] = $px;
                    } elseif (strcasecmp($name, 'Draw') === 0 || strcasecmp($name, 'Unentschieden') === 0) {
                        if ($best['draw'] === null || $px > $best['draw']) $best['draw'] = $px;
                    }
                }
            }
        }

        $out[] = [
            'id'        => (string)$e['id'],
            'sport_key' => $sportKey,
            'league'    => (string)($e['sport_title'] ?? $sportKey),
            'home'      => $home,
            'away'      => $away,
            'kickoff'   => (string)$e['commence_time'],
            'odds'      => $best,
            'source'    => 'theoddsapi',
        ];
    }
    return $out;
}

function getFixturesData(bool $forceRefresh = false): array {
    if (!$forceRefresh) {
        $cached = fixturesCacheRead();
        if ($cached !== null) return $cached;
    }

    if (THEODDSAPI_KEY === '') {
        return [
            'fetched_at' => time(),
            'configured' => false,
            'events'     => [],
            'errors'     => ['Kein API-Key in config.php gesetzt (THEODDSAPI_KEY).'],
        ];
    }

    $events = [];
    $errors = [];
    foreach (FIXTURES_SPORTS as $sport) {
        $raw = fetchTheOddsApi($sport);
        if ($raw === null) {
            $errors[] = "Fetch fehlgeschlagen: {$sport}";
            continue;
        }
        $events = array_merge($events, normalizeFixtureEvents($raw, $sport));
    }

    // Nach Anstosszeit aufsteigend sortieren
    usort($events, fn($a, $b) => strcmp($a['kickoff'], $b['kickoff']));

    $data = [
        'fetched_at' => time(),
        'configured' => true,
        'events'     => $events,
        'errors'     => $errors,
    ];
    fixturesCacheWrite($data);
    return $data;
}

// ============================================================
//  WM DATA STORE — wm_data.json
//  Speichert Spielergebnisse + Wetteinsätze pro WM-Spiel
// ============================================================
function wmDataRead(): array {
    if (!file_exists(WM_DATA_FILE)) return [];
    $raw = @file_get_contents(WM_DATA_FILE);
    if ($raw === false) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function wmDataWrite(array $data): void {
    $tmp = WM_DATA_FILE . '.tmp';
    @file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), LOCK_EX);
    @rename($tmp, WM_DATA_FILE);
}

// ============================================================
//  CASINO STORE — casino.csv
//  Schema: id, date, game, provider, buyin, cashout, note, user
//  P&L pro Session = cashout - buyin (wird clientseitig berechnet)
// ============================================================
function casinoRead(): array {
    if (!file_exists(CASINO_FILE)) {
        $fp = @fopen(CASINO_FILE, 'w');
        if ($fp) {
            flock($fp, LOCK_EX);
            fputcsv($fp, CASINO_HEADER, ',', '"');
            flock($fp, LOCK_UN);
            fclose($fp);
        }
        return [];
    }
    $fp = @fopen(CASINO_FILE, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    fgetcsv($fp, 0, ',', '"'); // skip header
    $rows = [];
    $cols = count(CASINO_HEADER);
    while (($row = fgetcsv($fp, 0, ',', '"')) !== false) {
        if ($row === null) continue;
        if (count($row) === 1 && ($row[0] === null || $row[0] === '')) continue;
        if (count($row) < 6) continue;
        $padded = array_pad($row, $cols, '');
        $rows[] = array_combine(CASINO_HEADER, array_slice($padded, 0, $cols));
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return array_reverse($rows);
}

function casinoWrite(array $rows): void {
    $rows = array_reverse($rows);
    $tmp  = CASINO_FILE . '.tmp';
    $fp   = fopen($tmp, 'w');
    if (!$fp) return;
    flock($fp, LOCK_EX);
    fputcsv($fp, CASINO_HEADER, ',', '"');
    foreach ($rows as $r) fputcsv($fp, array_values($r), ',', '"');
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    @rename($tmp, CASINO_FILE);
}

function s(string $v): string { return htmlspecialchars(trim($v), ENT_QUOTES, 'UTF-8'); }
function f(mixed $v, int $dec = 2, float $min = 0.0, float $max = 1e9): float {
    $n = is_numeric($v) ? (float)$v : 0.0;
    if (!is_finite($n)) $n = 0.0;
    if ($n < $min) $n = $min;
    if ($n > $max) $n = $max;
    return round($n, $dec);
}
function validStatus(string $s): string { return in_array($s, ['open','won','lost','cashout','void'], true) ? $s : 'open'; }

function handleApi(string $a): void {
    if ($a === 'list') { echo json_encode(['bets' => csvRead(), 'shares' => sharesRead(), 'invites' => pendingInvitesForUser(currentUser()), 'user' => currentUser()]); return; }
    $b = json_decode(file_get_contents('php://input'), true) ?? [];

    if ($a === 'add') {
        $rows = array_reverse(csvRead());
        $id   = (string)(time() . random_int(100, 999));

        // Shared-Bet: wenn participants gesetzt und gueltig, ueberschreibt der
        // Gesamteinsatz den 'stake'-Wert. Sonst Standardwette.
        $participants = normalizeParticipants($b['participants'] ?? null);
        if ($participants !== null) {
            $totalStake = 0.0;
            foreach ($participants as $p) $totalStake += $p['stake'];
            $stakeVal = round($totalStake, 2);
        } else {
            $stakeVal = f($b['stake'] ?? 0);
        }

        $rows[] = [
            'id'       => $id,
            'date'     => $b['date']     ?? date('Y-m-d'),
            'sport'    => s($b['sport']  ?? ''),
            'desc'     => s($b['desc']   ?? ''),
            'league'   => s($b['league'] ?? ''),
            'market'   => s($b['market'] ?? ''),
            'stake'    => $stakeVal,
            'odds'     => f($b['odds']   ?? 0),
            'status'   => validStatus($b['status'] ?? 'open'),
            'bookie'   => s($b['bookie'] ?? ''),
            'note'     => s($b['note']   ?? ''),
            'user'     => currentUser(),
            'tax_rate' => f($b['tax_rate'] ?? 0, 4),
            'cashout'  => f($b['cashout']  ?? 0),
            'combo_id' => s($b['combo_id'] ?? ''),
        ];
        csvWrite($rows);

        // Shares + Invites persistieren
        // Eigener Anteil geht direkt in shares.csv. Andere Nutzer kriegen
        // pending Invites — ihr Share wird erst beim Accept geschrieben.
        if ($participants !== null) {
            $me        = currentUser();
            $allShares = sharesRead();
            $allInv    = invitesRead();
            $invitedCt = 0;
            foreach ($participants as $p) {
                if ($p['user'] === $me) {
                    $allShares[] = ['bet_id' => $id, 'user' => $me, 'stake' => $p['stake']];
                } else {
                    $allInv[] = [
                        'id'         => 'inv_' . time() . '_' . random_int(1000, 9999),
                        'bet_id'     => $id,
                        'from_user'  => $me,
                        'to_user'    => $p['user'],
                        'stake'      => $p['stake'],
                        'status'     => 'pending',
                        'created_at' => date('c'),
                    ];
                    $invitedCt++;
                }
            }
            sharesWrite($allShares);
            invitesWrite($allInv);
            auditLog('SHARED_BET_CREATED bet=' . $id . ' invited=' . $invitedCt, $me);
        }

        // Kombi-Legs: wenn Payload 'legs' enthaelt, in kombi_legs.csv speichern
        if (!empty($b['legs']) && is_array($b['legs'])) {
            $allLegs = kombiLegsRead();
            foreach ($b['legs'] as $idx => $leg) {
                if (!is_array($leg)) continue;
                $allLegs[] = [
                    'bet_id'  => $id,
                    'leg_idx' => (int)$idx,
                    'team'    => isset($leg['team']) ? s((string)$leg['team']) : '',
                    'desc'    => isset($leg['desc']) ? s((string)$leg['desc']) : '',
                    'odds'    => isset($leg['odds']) ? (float)$leg['odds'] : 0,
                ];
            }
            kombiLegsWrite($allLegs);
        }

        echo json_encode(['ok'=>true, 'id'=>$id, 'shared'=>$participants !== null, 'invited'=>($participants ? max(0, count($participants)-1) : 0)]); return;
    }
    if ($a === 'del') {
        $id = (string)($b['id'] ?? ''); $rows = csvRead();
        $rows = array_values(array_filter($rows, fn($r) => $r['id'] !== $id));
        csvWrite($rows);
        // Cascade: shares + invites + kombi_legs mit gleicher bet_id ebenfalls entfernen
        $shares = sharesRead();
        $shares = array_values(array_filter($shares, fn($s) => $s['bet_id'] !== $id));
        sharesWrite($shares);
        $inv = invitesRead();
        $inv = array_values(array_filter($inv, fn($x) => $x['bet_id'] !== $id));
        invitesWrite($inv);
        $kl = kombiLegsRead();
        $kl = array_values(array_filter($kl, fn($x) => $x['bet_id'] !== $id));
        kombiLegsWrite($kl);
        echo json_encode(['ok'=>true]); return;
    }
    if ($a === 'upd' || $a === 'upd_status') {
        $id = (string)($b['id'] ?? ''); $rows = csvRead();
        foreach ($rows as &$r) {
            if ($r['id'] !== $id) continue;
            if ($a === 'upd_status') {
                $r['status'] = validStatus($b['status'] ?? $r['status']);
            } else {
                foreach (['date','league','market','bookie','note','sport','desc'] as $f2) {
                    if (isset($b[$f2])) $r[$f2] = s($b[$f2]);
                }
                if (isset($b['stake']))    $r['stake']    = f($b['stake']);
                if (isset($b['odds']))     $r['odds']     = f($b['odds']);
                if (isset($b['tax_rate'])) $r['tax_rate'] = f($b['tax_rate'], 4);
                if (isset($b['cashout']))  $r['cashout']  = f($b['cashout']);
                if (isset($b['status']))   $r['status']   = validStatus($b['status']);
            }
        }
        csvWrite($rows); echo json_encode(['ok'=>true]); return;
    }
    if ($a === 'change_pw') {
        $res = changePassword(
            (string)($b['current'] ?? ''),
            (string)($b['new']     ?? ''),
            (string)($b['confirm'] ?? ''),
            (string)($b['_csrf']   ?? '')
        );
        if (!$res['ok']) http_response_code(400);
        // Bei Erfolg neuen CSRF mitschicken (Token wurde rotiert)
        if (!empty($res['ok'])) $res['csrf'] = csrfToken();
        echo json_encode($res); return;
    }
    if ($a === 'create_acct') {
        $res = createAccount(
            (string)($b['username'] ?? ''),
            (string)($b['password'] ?? ''),
            (string)($b['confirm']  ?? ''),
            (string)($b['_csrf']    ?? ''),
            isset($b['color']) ? (string)$b['color'] : null
        );
        if (!$res['ok']) http_response_code(400);
        echo json_encode($res); return;
    }
    if ($a === 'fixtures') {
        $force = !empty($b['refresh']);  // optional Force-Refresh
        // Auch fuer GET ohne Body funktionieren:
        if (!$force && isset($_GET['refresh'])) $force = !empty($_GET['refresh']);
        echo json_encode(getFixturesData($force));
        return;
    }
    if ($a === 'invite_accept' || $a === 'invite_decline') {
        $invId = (string)($b['invite_id'] ?? '');
        $me    = currentUser();
        if ($invId === '') { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'invite_id fehlt']); return; }
        $invites = invitesRead();
        $found = false;
        foreach ($invites as &$inv) {
            if ($inv['id'] !== $invId) continue;
            // Sicherheits-Check: nur der Adressat darf reagieren
            if ($inv['to_user'] !== $me) {
                http_response_code(403);
                echo json_encode(['ok'=>false,'error'=>'Nicht dein Invite.']);
                return;
            }
            if ($inv['status'] !== 'pending') {
                echo json_encode(['ok'=>false,'error'=>'Schon beantwortet.']);
                return;
            }
            if ($a === 'invite_accept') {
                $inv['status'] = 'accepted';
                $allShares = sharesRead();
                // Doppel-Add verhindern (defensiv)
                $already = false;
                foreach ($allShares as $s) {
                    if ($s['bet_id'] === $inv['bet_id'] && $s['user'] === $me) { $already = true; break; }
                }
                if (!$already) {
                    $allShares[] = ['bet_id' => $inv['bet_id'], 'user' => $me, 'stake' => $inv['stake']];
                    sharesWrite($allShares);
                }
                auditLog('INVITE_ACCEPTED bet=' . $inv['bet_id'], $me);
            } else {
                $inv['status'] = 'declined';
                auditLog('INVITE_DECLINED bet=' . $inv['bet_id'], $me);
            }
            $found = true;
            break;
        }
        unset($inv);
        if (!$found) { http_response_code(404); echo json_encode(['ok'=>false,'error'=>'Invite nicht gefunden']); return; }
        invitesWrite($invites);
        echo json_encode(['ok'=>true]); return;
    }
    if ($a === 'wm_load') {
        echo json_encode(['ok' => true, 'data' => wmDataRead()]);
        return;
    }
    if ($a === 'wm_save') {
        $matchId = s($b['match_id'] ?? '');
        if ($matchId === '') {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'match_id fehlt']);
            return;
        }
        $data = wmDataRead();
        $data[$matchId] = [
            'score1' => isset($b['score1']) && $b['score1'] !== '' ? (int)$b['score1'] : null,
            'score2' => isset($b['score2']) && $b['score2'] !== '' ? (int)$b['score2'] : null,
            'stake'  => isset($b['stake'])  && is_numeric($b['stake'])  ? (float)$b['stake']  : null,
            'pnl'    => isset($b['pnl'])    && is_numeric($b['pnl'])    ? (float)$b['pnl']    : null,
            'note'   => s($b['note'] ?? ''),
        ];
        wmDataWrite($data);
        echo json_encode(['ok' => true]);
        return;
    }
    if ($a === 'teams') {
        echo json_encode(['teams' => teamsRead()]); return;
    }
    if ($a === 'team_stats') {
        echo json_encode(['stats' => teamStats(currentUser())]); return;
    }
    if ($a === 'users') {
        // Nur Anzeigedaten — niemals Hashes herausgeben
        echo json_encode(['users' => userList()]); return;
    }
    if ($a === 'casino_list') {
        echo json_encode(['ok' => true, 'sessions' => casinoRead(), 'user' => currentUser()]); return;
    }
    if ($a === 'casino_add') {
        $rows = array_reverse(casinoRead());
        $id   = (string)(time() . random_int(100, 999));
        $rows[] = [
            'id'       => $id,
            'date'     => $b['date'] ?? date('Y-m-d'),
            'game'     => s($b['game']     ?? ''),
            'provider' => s($b['provider'] ?? ''),
            'buyin'    => f($b['buyin']    ?? 0),
            'cashout'  => f($b['cashout']  ?? 0),
            'note'     => s($b['note']     ?? ''),
            'user'     => currentUser(),
        ];
        casinoWrite($rows);
        echo json_encode(['ok' => true, 'id' => $id]); return;
    }
    if ($a === 'casino_del') {
        $id = (string)($b['id'] ?? '');
        $me = currentUser();
        $rows = casinoRead();
        $rows = array_values(array_filter($rows, fn($r) => !($r['id'] === $id && $r['user'] === $me)));
        casinoWrite($rows);
        echo json_encode(['ok' => true]); return;
    }
    if ($a === 'export') {
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="wetten_'.date('Y-m-d').'.csv"');
        $rows = csvRead(); $fp = fopen('php://output','w');
        fputcsv($fp, CSV_HEADER);
        foreach (array_reverse($rows) as $r) fputcsv($fp, array_values($r));
        fclose($fp); exit;
    }
    http_response_code(404); echo json_encode(['e'=>'unknown']);
}
?>
<!DOCTYPE html>
<html lang="de" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>WettPro</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:#f5f5f7; --surface:#ffffff; --surface2:#f2f2f4; --surface3:#e8e8ec;
  --t1:#0a0a0f; --t2:#5a5a72; --t3:#9898a8;
  --sep:rgba(0,0,0,0.08); --sep2:rgba(0,0,0,0.04);
  --blue:#2563eb; --blue-s:rgba(37,99,235,0.10);
  --green:#16a34a; --green-s:rgba(22,163,74,0.10);
  --red:#dc2626; --red-s:rgba(220,38,38,0.10);
  --amber:#d97706; --amber-s:rgba(217,119,6,0.10);
  --purple:#7c3aed; --purple-s:rgba(124,58,237,0.10);
  --teal:#0891b2;
  --sh0:0 1px 2px rgba(0,0,0,0.05);
  --sh1:0 1px 4px rgba(0,0,0,0.07),0 0 0 0.5px rgba(0,0,0,0.05);
  --sh2:0 4px 16px rgba(0,0,0,0.08),0 0 0 0.5px rgba(0,0,0,0.04);
  --r-sm:8px; --r-md:12px; --r-lg:16px; --r-xl:20px; --r-full:9999px;
  --font:'Inter',-apple-system,system-ui,sans-serif;
}
[data-theme="dark"] {
  --bg:#09090b; --surface:#141416; --surface2:#1e1e22; --surface3:#28282e;
  --t1:#fafafa; --t2:#a1a1b4; --t3:#52526a;
  --sep:rgba(255,255,255,0.08); --sep2:rgba(255,255,255,0.04);
  --blue:#3b82f6; --blue-s:rgba(59,130,246,0.14);
  --green:#22c55e; --green-s:rgba(34,197,94,0.14);
  --red:#f87171; --red-s:rgba(248,113,113,0.14);
  --amber:#fbbf24; --amber-s:rgba(251,191,36,0.14);
  --purple:#a78bfa; --purple-s:rgba(167,139,250,0.14);
  --sh0:0 1px 2px rgba(0,0,0,0.40);
  --sh1:0 1px 4px rgba(0,0,0,0.50),0 0 0 0.5px rgba(255,255,255,0.06);
  --sh2:0 4px 16px rgba(0,0,0,0.60),0 0 0 0.5px rgba(255,255,255,0.05);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;transition:background 0.3s;}
body{font-family:var(--font);background:var(--bg);color:var(--t1);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased;min-height:100vh;transition:background 0.25s,color 0.25s;}

/* LOGIN */
.login-page{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:var(--bg);}
.login-card{width:100%;max-width:400px;background:var(--surface);border-radius:var(--r-xl);box-shadow:var(--sh2);padding:44px 40px;border:0.5px solid var(--sep);}
.login-logo{display:flex;align-items:center;gap:10px;margin-bottom:8px;}
.login-logo-icon{width:42px;height:42px;background:var(--blue);border-radius:var(--r-md);display:flex;align-items:center;justify-content:center;font-size:22px;}
.login-logo-text{font-size:22px;font-weight:700;letter-spacing:-0.5px;color:var(--t1);}
.login-logo-text span{color:var(--blue);}
.login-sub{font-size:13px;color:var(--t2);margin-bottom:32px;}
.login-alert{border-radius:var(--r-md);padding:12px 14px;font-size:13px;margin-bottom:18px;line-height:1.5;}
.login-alert-err{background:var(--red-s);color:var(--red);border:0.5px solid color-mix(in srgb,var(--red) 30%,transparent);}
.login-alert-ok{background:var(--green-s);color:var(--green);border:0.5px solid color-mix(in srgb,var(--green) 30%,transparent);}
.lbl{display:block;font-size:12px;font-weight:500;color:var(--t2);margin-bottom:5px;letter-spacing:0.2px;}
.inp{width:100%;padding:11px 14px;background:var(--surface2);border:1px solid var(--sep);border-radius:var(--r-md);color:var(--t1);font-family:var(--font);font-size:14px;outline:none;transition:border-color 0.15s,box-shadow 0.15s;margin-bottom:14px;}
.inp:focus{border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-s);}
.inp::placeholder{color:var(--t3);}
select.inp option{background:var(--surface);}
.btn-login{width:100%;padding:12px;background:var(--blue);color:#fff;border:none;border-radius:var(--r-md);font-family:var(--font);font-size:15px;font-weight:600;cursor:pointer;letter-spacing:-0.2px;transition:opacity 0.15s,transform 0.1s;margin-top:4px;}
.btn-login:hover{opacity:0.9;}
.btn-login:active{transform:scale(0.985);}
.login-public{display:block;text-align:center;margin-top:18px;padding:11px 14px;background:var(--surface2);border:0.5px solid var(--sep);border-radius:var(--r-md);color:var(--t2);font-size:13px;font-weight:500;text-decoration:none;transition:all 0.15s;}
.login-public:hover{color:var(--blue);border-color:var(--blue);background:var(--blue-s);}
.login-footer{font-size:12px;color:var(--t3);text-align:center;margin-top:22px;}

/* APP */
.app{max-width:980px;margin:0 auto;padding:0 16px 80px;}
.topbar{position:sticky;top:0;z-index:200;background:color-mix(in srgb,var(--bg) 85%,transparent);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border-bottom:0.5px solid var(--sep);margin:0 -16px 24px;padding:0 24px;}
.topbar-inner{max-width:980px;margin:0 auto;height:56px;display:flex;align-items:center;gap:12px;}
.tb-brand{font-size:17px;font-weight:700;letter-spacing:-0.5px;color:var(--t1);flex-shrink:0;}
.tb-brand span{color:var(--blue);}
.tb-spacer{flex:1;}
.seg{display:flex;background:var(--surface2);border-radius:10px;padding:3px;gap:2px;border:0.5px solid var(--sep);}
.seg-btn{padding:5px 14px;font-size:12px;font-weight:500;border:none;border-radius:7px;cursor:pointer;background:transparent;color:var(--t2);transition:all 0.15s;white-space:nowrap;font-family:var(--font);}
.seg-btn.on{background:var(--surface);color:var(--t1);box-shadow:var(--sh0);}
.ib{width:34px;height:34px;border-radius:var(--r-sm);border:0.5px solid var(--sep);background:var(--surface);color:var(--t2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;transition:all 0.15s;flex-shrink:0;}
.ib:hover{background:var(--surface2);color:var(--t1);}
.tabs{display:flex;gap:0;border-bottom:0.5px solid var(--sep);margin-bottom:20px;overflow-x:auto;scrollbar-width:none;}
.tabs::-webkit-scrollbar{display:none;}
.tab{padding:10px 18px;font-size:13px;font-weight:500;border:none;background:transparent;color:var(--t2);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-0.5px;white-space:nowrap;font-family:var(--font);transition:color 0.15s;}
.tab:hover{color:var(--t1);}
.tab.on{color:var(--blue);border-bottom-color:var(--blue);}
.sec{display:none;}
.sec.on{display:block;overflow-x:hidden;}

/* CARDS */
.card{background:var(--surface);border-radius:var(--r-lg);border:0.5px solid var(--sep);box-shadow:var(--sh1);}
.card-pad{padding:18px 20px;}
.mtr-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:18px;}
.mtr{background:var(--surface);border-radius:var(--r-lg);border:0.5px solid var(--sep);box-shadow:var(--sh0);padding:16px;}
.mtr-lbl{font-size:11px;font-weight:500;color:var(--t3);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;}
.mtr-val{font-size:24px;font-weight:700;letter-spacing:-0.5px;font-variant-numeric:tabular-nums;}
.mtr-sub{font-size:11px;color:var(--t3);margin-top:3px;}
.cg{color:var(--green);} .cr{color:var(--red);} .cb{color:var(--blue);} .ca{color:var(--amber);} .cp{color:var(--purple);} .cn{color:var(--t1);}
.li{display:flex;align-items:center;gap:12px;padding:13px 18px;border-bottom:0.5px solid var(--sep2);transition:background 0.1s;}
.li:last-child{border-bottom:none;}
.li:hover{background:var(--surface2);}
.li-ico{width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;}
.li-body{flex:1;min-width:0;}
.li-title{font-size:13px;font-weight:500;color:var(--t1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.li-sub{font-size:11px;color:var(--t2);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.li-right{display:flex;align-items:center;gap:8px;flex-shrink:0;}
.li-val{font-size:14px;font-weight:600;font-variant-numeric:tabular-nums;text-align:right;min-width:72px;}
.bdg{font-size:10px;font-weight:600;padding:3px 8px;border-radius:var(--r-full);letter-spacing:0.3px;white-space:nowrap;}
.bdg-open{background:var(--amber-s);color:var(--amber);}
.bdg-won{background:var(--green-s);color:var(--green);}
.bdg-lost{background:var(--red-s);color:var(--red);}
.bdg-co{background:var(--blue-s);color:var(--blue);}
.t3-hint{color:var(--t3);font-size:11px;font-weight:500;}
.shared-toggle{display:inline-flex;align-items:center;gap:8px;font-size:13px;font-weight:500;color:var(--t2);cursor:pointer;user-select:none;}
.shared-toggle input{width:16px;height:16px;cursor:pointer;}
.shared-box{background:var(--surface2);border:0.5px solid var(--sep);border-radius:var(--r-md);padding:14px;margin-top:6px;}
.shared-hint{font-size:11px;color:var(--t3);margin-bottom:10px;line-height:1.4;}
.shared-row{display:flex;align-items:center;gap:10px;margin-bottom:8px;}
.shared-row .shared-name{flex:0 0 110px;font-size:13px;font-weight:600;color:var(--t1);display:flex;align-items:center;gap:6px;}
.shared-row .shared-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}
.shared-row .shared-stake{flex:1;}
.shared-row .shared-pct{flex:0 0 60px;text-align:right;font-size:12px;color:var(--t2);font-variant-numeric:tabular-nums;}
.shared-totals{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;color:var(--t1);padding-top:10px;border-top:0.5px solid var(--sep);margin-top:6px;}
.shared-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 6px;border-radius:6px;background:var(--purple-s);color:var(--purple);font-size:10px;font-weight:700;margin-left:6px;}
.bdg-void{background:var(--surface2);color:var(--t3);border:0.5px solid var(--sep);}
/* Bet action buttons (open bets) */
.bet-actions{display:flex;gap:4px;}
.ba-btn{width:30px;height:30px;border-radius:8px;border:0.5px solid var(--sep);background:var(--surface);cursor:pointer;font-size:14px;font-weight:700;display:inline-flex;align-items:center;justify-content:center;font-family:var(--font);transition:all 0.12s;padding:0;line-height:1;}
.ba-btn:hover{transform:translateY(-1px);box-shadow:var(--sh0);}
.ba-btn.ba-win {color:var(--green);background:var(--green-s);}
.ba-btn.ba-lose{color:var(--red);  background:var(--red-s);}
.ba-btn.ba-co  {color:var(--blue); background:var(--blue-s);}
.isel{font-size:11px;font-weight:500;border:0.5px solid var(--sep);background:var(--surface2);color:var(--t1);border-radius:var(--r-sm);padding:4px 7px;cursor:pointer;outline:none;font-family:var(--font);}
.delbtn{width:28px;height:28px;border-radius:50%;border:none;background:transparent;color:var(--t3);cursor:pointer;font-size:17px;line-height:1;display:flex;align-items:center;justify-content:center;transition:all 0.15s;}
.delbtn:hover{background:var(--red-s);color:var(--red);}

/* FORMS */
.fc{padding:0;}
.fg{display:grid;gap:12px;margin-bottom:13px;}
.fg2{grid-template-columns:1fr 1fr;} .fg3{grid-template-columns:1fr 1fr 1fr;} .fg1{grid-template-columns:1fr;}
.fl label{display:block;font-size:11px;font-weight:500;color:var(--t2);margin-bottom:5px;letter-spacing:0.2px;}
.fi{width:100%;padding:9px 12px;background:var(--surface2);border:0.5px solid var(--sep);border-radius:var(--r-md);color:var(--t1);font-family:var(--font);font-size:13px;outline:none;transition:border-color 0.15s,box-shadow 0.15s;}
.fi:focus{border-color:var(--blue);box-shadow:0 0 0 3px var(--blue-s);}
.fi::placeholder{color:var(--t3);}
.fi option{background:var(--surface);}
.cbox{background:color-mix(in srgb,var(--blue) 6%,var(--surface));border:0.5px solid color-mix(in srgb,var(--blue) 25%,transparent);border-radius:var(--r-md);padding:14px 16px;margin-bottom:14px;display:none;}
.cbox.show{display:block;}
.crow{display:flex;justify-content:space-between;font-size:13px;padding:3px 0;}
.crow:last-child{font-weight:600;font-size:14px;border-top:0.5px solid var(--sep);padding-top:8px;margin-top:4px;}
.clbl{color:var(--t2);}
.cval{font-weight:500;color:var(--t1);font-variant-numeric:tabular-nums;}
.txbox{background:var(--amber-s);border:0.5px solid color-mix(in srgb,var(--amber) 30%,transparent);border-radius:var(--r-md);padding:14px 16px;}
.txrow{display:flex;justify-content:space-between;font-size:13px;padding:3px 0;}
.txrow.ttl{font-weight:600;font-size:14px;border-top:0.5px solid var(--sep);padding-top:8px;margin-top:4px;}
.btn{padding:10px 20px;border-radius:var(--r-md);font-size:14px;font-weight:600;cursor:pointer;border:none;font-family:var(--font);transition:all 0.15s;display:inline-flex;align-items:center;justify-content:center;gap:6px;letter-spacing:-0.2px;}
.btn-p{background:var(--blue);color:#fff;}
.btn-p:hover{opacity:0.88;}
.btn-p:active{transform:scale(0.98);}
.btn-s{background:var(--surface2);color:var(--t1);border:0.5px solid var(--sep);}
.btn-s:hover{background:var(--surface3);}
.btn-d{background:var(--red-s);color:var(--red);}
.btn-full{width:100%;}
.btn-sm{padding:7px 14px;font-size:12px;border-radius:var(--r-sm);}
.fbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;}
.fsel{padding:7px 10px;font-size:12px;background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-sm);color:var(--t2);font-family:var(--font);cursor:pointer;outline:none;}
.stbl{width:100%;border-collapse:collapse;font-size:13px;}
.stbl th{font-weight:600;color:var(--t2);text-align:left;padding:10px 12px;border-bottom:0.5px solid var(--sep);font-size:11px;text-transform:uppercase;letter-spacing:0.4px;}
.stbl td{padding:9px 12px;border-bottom:0.5px solid var(--sep2);}
.stbl th{text-align:left;font-size:11px;font-weight:600;color:var(--t3);padding:9px 14px;border-bottom:0.5px solid var(--sep);text-transform:uppercase;letter-spacing:0.4px;white-space:nowrap;}
.stbl td{padding:11px 14px;border-bottom:0.5px solid var(--sep2);}
.stbl tr:last-child td{border-bottom:none;}
.stbl tr:hover td{background:var(--surface2);}
.pbar{height:4px;background:var(--surface3);border-radius:2px;overflow:hidden;display:inline-block;width:50px;vertical-align:middle;margin:0 4px;}
.pfill{height:100%;border-radius:2px;}
.chw{position:relative;width:100%;}
.chw-200{height:200px;} .chw-160{height:160px;} .chw-140{height:140px;}
.sh{font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:0.6px;margin:20px 0 10px;}
.combo-leg{background:var(--surface2);border-radius:var(--r-md);padding:10px 12px;display:flex;gap:10px;align-items:center;margin-bottom:8px;}
.leg-num{width:22px;height:22px;border-radius:50%;background:var(--blue);color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;}
.tool-card{background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-lg);box-shadow:var(--sh0);padding:18px 20px;margin-bottom:14px;}
.kelly-res{background:var(--green-s);border:0.5px solid color-mix(in srgb,var(--green) 25%,transparent);border-radius:var(--r-md);padding:14px 16px;margin-top:12px;}
.vb-box{border-radius:var(--r-md);padding:14px 16px;margin-top:12px;}
.ldot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--red);margin-right:3px;vertical-align:middle;animation:pulse 1.2s ease-in-out infinite;}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.25;}}
.taxbar{border-radius:var(--r-md);margin-bottom:16px;}
.chips{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:14px;}
.chip{font-size:12px;font-weight:500;padding:6px 13px;border-radius:var(--r-full);border:0.5px solid var(--sep);cursor:pointer;background:var(--surface);color:var(--t2);transition:all 0.15s;white-space:nowrap;}
.chip:hover{background:var(--surface2);color:var(--t1);}
.chip.on{background:var(--blue);color:#fff;border-color:var(--blue);}
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(12px);background:var(--t1);color:var(--bg);border-radius:var(--r-full);padding:10px 20px;font-size:13px;font-weight:500;box-shadow:var(--sh2);opacity:0;pointer-events:none;transition:all 0.2s cubic-bezier(0.34,1.56,0.64,1);white-space:nowrap;z-index:999;}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
.game-row{display:flex;align-items:center;gap:10px;padding:12px 18px;border-bottom:0.5px solid var(--sep2);transition:background 0.1s;}
.game-row:last-child{border-bottom:none;}
.game-row:hover{background:var(--surface2);}
.game-time{min-width:48px;text-align:center;font-size:11px;color:var(--t2);}
.game-teams{flex:1;min-width:0;}
.game-name{font-size:13px;font-weight:500;}
.game-league{font-size:11px;color:var(--t2);margin-top:1px;}
.odds-grp{display:flex;gap:5px;flex-shrink:0;}
.odds-btn{font-size:11px;font-weight:600;padding:5px 9px;border-radius:var(--r-sm);border:none;cursor:pointer;background:var(--blue-s);color:var(--blue);transition:all 0.15s;white-space:nowrap;}
.odds-btn:hover{background:var(--blue);color:#fff;}
.streak-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px;}
.streak-box{text-align:center;}
.streak-num{font-size:32px;font-weight:700;}
.streak-lbl{font-size:11px;color:var(--t2);margin-bottom:4px;}
.empty{text-align:center;padding:36px 16px;color:var(--t2);font-size:13px;}
.empty-ico{font-size:32px;margin-bottom:8px;}
.logout-form{display:inline;}

/* ============================================================
   PIKKIT KALENDER
   ============================================================ */
.cal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.cal-title {
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -0.5px;
}
.cal-title-sub {
  font-size: 12px;
  color: var(--t3);
  margin-left: 8px;
  font-weight: 500;
}
.cal-nav {
  display: flex;
  align-items: center;
  gap: 8px;
}
.cal-nav-btn {
  width: 32px; height: 32px;
  border-radius: var(--r-sm);
  border: 0.5px solid var(--sep);
  background: var(--surface);
  color: var(--t2);
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px;
  transition: all 0.15s;
}
.cal-nav-btn:hover { background: var(--surface2); color: var(--t1); }

/* Unit toggle */
.unit-seg {
  display: flex;
  background: var(--surface2);
  border-radius: 8px;
  padding: 2px;
  gap: 2px;
  border: 0.5px solid var(--sep);
}
.unit-btn {
  padding: 4px 12px;
  font-size: 11px;
  font-weight: 600;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  background: transparent;
  color: var(--t2);
  transition: all 0.15s;
  font-family: var(--font);
  letter-spacing: 0.2px;
}
.unit-btn.on {
  background: var(--surface);
  color: var(--t1);
  box-shadow: var(--sh0);
}

/* Calendar grid */
.cal-grid {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  gap: 4px;
}
.cal-dow {
  text-align: center;
  font-size: 10px;
  font-weight: 600;
  color: var(--t3);
  padding: 6px 0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.cal-day {
  aspect-ratio: 1;
  border-radius: var(--r-md);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 2px;
  cursor: default;
  transition: transform 0.1s;
  position: relative;
  min-height: 52px;
}
.cal-day.has-bets { cursor: pointer; }
.cal-day.has-bets:hover { transform: scale(1.04); }
.cal-day-num {
  font-size: 11px;
  font-weight: 600;
  line-height: 1;
}
.cal-day-val {
  font-size: 11px;
  font-weight: 700;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}
.cal-day.empty { background: transparent; }
.cal-day.today { outline: 2px solid var(--blue); outline-offset: -2px; }

/* Intensity colors — green */
.cal-win-1 { background: color-mix(in srgb, var(--green) 15%, var(--surface2)); }
.cal-win-2 { background: color-mix(in srgb, var(--green) 30%, var(--surface2)); }
.cal-win-3 { background: color-mix(in srgb, var(--green) 50%, var(--surface2)); }
.cal-win-4 { background: color-mix(in srgb, var(--green) 70%, var(--surface2)); }
.cal-win-5 { background: color-mix(in srgb, var(--green) 90%, var(--surface2)); }
/* Intensity colors — red */
.cal-loss-1 { background: color-mix(in srgb, var(--red) 15%, var(--surface2)); }
.cal-loss-2 { background: color-mix(in srgb, var(--red) 30%, var(--surface2)); }
.cal-loss-3 { background: color-mix(in srgb, var(--red) 50%, var(--surface2)); }
.cal-loss-4 { background: color-mix(in srgb, var(--red) 70%, var(--surface2)); }
.cal-loss-5 { background: color-mix(in srgb, var(--red) 90%, var(--surface2)); }
/* neutral / open */
.cal-neutral { background: var(--surface2); }

/* Bei kräftiger Einfärbung (3-5) weichen Schatten unter die helle Schrift legen,
   damit sie auf jedem Untergrund klar lesbar bleibt. */
.cal-win-3 .cal-day-num, .cal-win-4 .cal-day-num, .cal-win-5 .cal-day-num,
.cal-win-3 .cal-day-val, .cal-win-4 .cal-day-val, .cal-win-5 .cal-day-val,
.cal-loss-3 .cal-day-num, .cal-loss-4 .cal-day-num, .cal-loss-5 .cal-day-num,
.cal-loss-3 .cal-day-val, .cal-loss-4 .cal-day-val, .cal-loss-5 .cal-day-val {
  text-shadow: 0 1px 2px rgba(0,0,0,0.25);
}

/* Month summary row */
.cal-month-sum {
  display: flex;
  gap: 12px;
  margin-top: 14px;
  flex-wrap: wrap;
}
.cal-sum-pill {
  background: var(--surface);
  border: 0.5px solid var(--sep);
  border-radius: var(--r-full);
  padding: 6px 14px;
  font-size: 12px;
  font-weight: 600;
  display: flex;
  gap: 6px;
  align-items: center;
}
.cal-sum-lbl { color: var(--t3); font-weight: 500; }

/* Day detail popover */
.day-detail {
  background: var(--surface);
  border: 0.5px solid var(--sep);
  border-radius: var(--r-lg);
  box-shadow: var(--sh2);
  padding: 14px 16px;
  margin-top: 12px;
  animation: fadeIn 0.15s ease;
}
@keyframes fadeIn { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:translateY(0); } }
.day-detail-title {
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 10px;
  color: var(--t1);
}

@media (max-width: 640px) {
  .fg2,.fg3{grid-template-columns:1fr;}
  .mtr-grid{grid-template-columns:repeat(2,1fr);}
  .login-card{padding:32px 24px;}
  .odds-grp{display:none;}
  .topbar-inner{gap:6px;flex-wrap:wrap;height:auto;padding:8px 0;}
  .tb-brand{font-size:16px;}
  .me-pill{padding:4px 10px;font-size:12px;}
  .ib{width:30px;height:30px;font-size:14px;}
  .streak-num{font-size:24px;}

  /* Kompakter Kalender — kleinere Tageskacheln + Header */
  .cal-grid{gap:3px;}
  .cal-day{min-height:38px;border-radius:8px;}
  .cal-day-num{font-size:10px;}
  .cal-day-val{font-size:9px;font-weight:700;}
  .cal-dow{font-size:9px;padding:4px 0;}

  .cal-month-sum{gap:6px;}
  .cal-sum-pill{padding:4px 10px;font-size:11px;}

  /* Bet-Liste enger */
  .li{padding:10px;gap:8px;}
  .li-ico{width:34px;height:34px;font-size:16px;}
  .li-title{font-size:13px;}
  .li-sub{font-size:11px;}

  /* Action-Buttons kleiner aber noch gut tippbar */
  .ba-btn{width:32px;height:32px;}

  /* Tabs scrollbar/wickeln */
  .tabs{overflow-x:auto;flex-wrap:nowrap;-webkit-overflow-scrolling:touch;}
  .tab{flex:0 0 auto;}

  /* Karten enger, weniger Padding */
  .card-pad{padding:14px;}

  /* Modale auf voller Breite */
  .acct-card,.inv-card{padding:20px 16px;border-radius:14px;}

  /* Shared-Box auf Mobile */
  .shared-row{flex-wrap:wrap;}
  .shared-row .shared-name{flex-basis:100%;margin-bottom:4px;}
  .shared-row .shared-stake{flex:1;}
}

/* Account / Security Modal */
.acct-modal{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px;}
.acct-modal[hidden]{display:none;}
.acct-backdrop{position:absolute;inset:0;background:rgba(0,0,0,0.45);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);}
.acct-card{position:relative;background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-xl);box-shadow:var(--sh2);width:100%;max-width:440px;padding:28px 28px 24px;animation:fadeIn 0.18s ease;}
.acct-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;}
.acct-title{font-size:18px;font-weight:700;letter-spacing:-0.3px;}
.acct-tabs{display:flex;gap:4px;background:var(--surface2);border-radius:var(--r-sm);padding:4px;margin-bottom:18px;}
.acct-tab{flex:1;padding:8px 12px;font-size:13px;font-weight:600;border-radius:6px;border:none;background:transparent;color:var(--t2);cursor:pointer;font-family:var(--font);transition:all 0.15s;}
.acct-tab.on{background:var(--surface);color:var(--t1);box-shadow:var(--sh0);}
.acct-form .lbl{display:block;font-size:12px;font-weight:600;color:var(--t2);margin:8px 0 6px;}
.acct-form .inp{margin-bottom:0;}
.acct-form .inp + .lbl{margin-top:14px;}
.acct-color{height:42px;padding:6px;cursor:pointer;}
.acct-hint{font-size:11px;color:var(--t3);margin:14px 0 16px;line-height:1.45;}
.acct-msg{padding:10px 12px;border-radius:var(--r-sm);font-size:13px;font-weight:500;margin-bottom:14px;}
.acct-msg.err{background:var(--red-s);color:var(--red);}
.acct-msg.ok{background:var(--green-s);color:var(--green);}
/* Me-Pill (eingeloggter Nutzer als read-only Badge) */
.me-pill{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;background:var(--surface2);border:0.5px solid var(--sep);border-radius:var(--r-full);font-size:13px;font-weight:600;color:var(--t1);}
.me-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 2px color-mix(in srgb, var(--green) 30%, transparent);}

/* Invite-Bell + Counter Badge */
.invite-bell{position:relative;}
.invite-count{position:absolute;top:-4px;right:-4px;min-width:16px;height:16px;padding:0 4px;border-radius:8px;background:var(--red);color:#fff;font-size:9px;font-weight:700;display:flex;align-items:center;justify-content:center;line-height:1;border:2px solid var(--bg);}
.invite-count[hidden]{display:none;}

/* Invites Modal — gleicher Style wie acct-modal */
.inv-modal{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px;}
.inv-modal[hidden]{display:none;}
.inv-backdrop{position:absolute;inset:0;background:rgba(0,0,0,0.45);backdrop-filter:blur(4px);}
.inv-card{position:relative;background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-xl);box-shadow:var(--sh2);width:100%;max-width:520px;max-height:80vh;overflow-y:auto;padding:24px;animation:fadeIn 0.18s ease;}
.inv-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.inv-title{font-size:18px;font-weight:700;}
.inv-empty{padding:32px 16px;text-align:center;color:var(--t3);font-size:13px;}
.inv-row{padding:14px;background:var(--surface2);border:0.5px solid var(--sep);border-radius:var(--r-md);margin-bottom:10px;}
.inv-row-head{display:flex;justify-content:space-between;align-items:start;margin-bottom:8px;gap:12px;}
.inv-row-title{font-size:14px;font-weight:600;color:var(--t1);}
.inv-row-meta{font-size:11px;color:var(--t3);margin-top:2px;}
.inv-row-stake{font-size:14px;font-weight:700;color:var(--blue);white-space:nowrap;}
.inv-row-actions{display:flex;gap:8px;margin-top:10px;}
.inv-row-actions .btn{flex:1;}
@media (max-width:640px){
  .acct-card{padding:22px 20px;}
}

/* ============================================================
   WM 2026 — Turnieroptik
   ============================================================ */
.wm-banner{display:flex;align-items:center;gap:12px;padding:18px 0 10px;margin-bottom:4px;position:relative;}
.wm-banner::after{content:none;}
.wm-banner-icon{font-size:28px;flex-shrink:0;line-height:1;}
.wm-title{font-size:20px;font-weight:800;color:var(--t1);letter-spacing:-0.5px;}
.wm-sub{font-size:12px;color:var(--t2);margin-top:3px;}
.wm-tabs{display:flex;gap:0;border-bottom:0.5px solid var(--sep);margin-bottom:18px;overflow-x:auto;scrollbar-width:none;}
.wm-tabs::-webkit-scrollbar{display:none;}
.wm-tab{padding:10px 18px;font-size:13px;font-weight:500;border:none;background:transparent;color:var(--t2);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-0.5px;white-space:nowrap;font-family:var(--font);transition:color 0.15s;}
.wm-tab.on{color:#16a34a;border-bottom-color:#16a34a;}
.wm-panel{display:none;}
.wm-panel.on{display:block;}

/* Group grid */
.wm-group-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(400px,1fr));gap:14px;margin-bottom:18px;}
.wm-group-card{background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-lg);box-shadow:var(--sh1);overflow:hidden;}
.wm-group-header{background:linear-gradient(135deg,#15803d,#22c55e);padding:10px 14px;display:flex;align-items:center;justify-content:space-between;}
.wm-group-name{font-size:13px;font-weight:700;color:#fff;letter-spacing:0.5px;}
.wm-group-md{font-size:10px;color:rgba(255,255,255,0.7);font-weight:500;}

/* Group table */
.wm-tbl{width:100%;border-collapse:collapse;font-size:12px;}
.wm-tbl th{font-weight:600;color:var(--t3);text-align:center;padding:7px 5px 5px;border-bottom:0.5px solid var(--sep);font-size:10px;text-transform:uppercase;letter-spacing:0.3px;}
.wm-tbl th:first-child{text-align:left;padding-left:12px;}
.wm-tbl td{padding:7px 5px;border-bottom:0.5px solid var(--sep2);text-align:center;font-variant-numeric:tabular-nums;font-size:12px;}
.wm-tbl td:first-child{text-align:left;padding-left:12px;font-weight:600;display:flex;align-items:center;gap:5px;}
.wm-tbl tr:last-child td{border-bottom:none;}
.wm-tbl tr:nth-child(-n+2) td{background:rgba(34,197,94,0.05);}
.wm-pos{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:50%;font-size:9px;font-weight:700;flex-shrink:0;}
.wm-p1{background:#fbbf24;color:#78350f;} .wm-p2{background:#9ca3af;color:#111;} .wm-p3{background:var(--surface3);color:var(--t2);} .wm-p4{background:var(--surface3);color:var(--t3);}
.wm-pts{font-weight:700;color:var(--t1);}

/* Game rows */
.wm-games{border-top:0.5px solid var(--sep);padding:6px 0;}
.wm-md-label{font-size:10px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:0.4px;padding:4px 12px 2px;}
.wm-game{display:flex;align-items:center;gap:6px;padding:5px 10px;font-size:11px;transition:background 0.1s;}
.wm-game:hover{background:var(--surface2);}
.wm-game-date{color:var(--t3);min-width:52px;flex-shrink:0;font-size:10px;}
.wm-game-home{flex:1;text-align:right;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.wm-game-away{flex:1;text-align:left;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.wm-score-wrap{display:flex;align-items:center;gap:3px;flex-shrink:0;}
.wm-sinp{width:30px;text-align:center;padding:3px 4px;background:var(--surface2);border:0.5px solid var(--sep);border-radius:6px;color:var(--t1);font-family:var(--font);font-size:12px;font-weight:700;}
.wm-sinp:focus{border-color:#16a34a;box-shadow:0 0 0 2px rgba(22,163,74,0.2);outline:none;}
.wm-ssep{color:var(--t3);font-weight:700;font-size:11px;}
.wm-sbtn{padding:3px 7px;font-size:10px;font-weight:600;border:none;border-radius:5px;background:#15803d;color:#fff;cursor:pointer;white-space:nowrap;transition:opacity 0.12s;flex-shrink:0;}
.wm-sbtn:hover{opacity:0.85;}
.wm-bbtn{padding:3px 7px;font-size:10px;font-weight:600;border:0.5px solid var(--sep);border-radius:5px;background:var(--surface2);color:var(--t2);cursor:pointer;flex-shrink:0;transition:all 0.12s;}
.wm-bbtn:hover{background:var(--blue-s);color:var(--blue);border-color:var(--blue);}
.wm-played{color:var(--green);font-weight:700;font-size:12px;padding:0 4px;}

/* Bracket */
.wm-bracket-outer{overflow-x:auto;padding-bottom:8px;max-width:100%;}
.wm-bracket{display:flex;gap:0;padding:12px 0;}
.wm-br-col{display:flex;flex-direction:column;min-width:160px;padding:0 6px;}
.wm-br-col-hdr{text-align:center;font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:0.5px;padding:0 4px 10px;white-space:nowrap;}
.wm-br-matches{display:flex;flex-direction:column;justify-content:space-around;height:100%;}
.wm-ko{background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-md);overflow:hidden;box-shadow:var(--sh0);margin:4px 0;cursor:pointer;transition:border-color 0.15s;}
.wm-ko:hover{border-color:#16a34a;}
.wm-ko-t{padding:6px 10px;font-size:11px;font-weight:500;display:flex;justify-content:space-between;align-items:center;gap:4px;min-height:32px;}
.wm-ko-t:first-child{border-bottom:0.5px solid var(--sep2);}
.wm-ko-t.win{background:rgba(34,197,94,0.1);font-weight:700;color:var(--green);}
.wm-ko-t.tbd{color:var(--t3);font-style:italic;}
.wm-ko-sc{font-size:13px;font-weight:700;min-width:14px;text-align:center;font-variant-numeric:tabular-nums;}
.wm-ko-final{border:1.5px solid #d97706;box-shadow:0 0 12px rgba(217,119,6,0.2);}

/* Champion */
.wm-champion{background:linear-gradient(135deg,#78350f,#d97706,#fbbf24);border-radius:var(--r-xl);padding:18px 22px;text-align:center;margin-bottom:16px;}
.wm-champ-lbl{font-size:11px;font-weight:600;color:rgba(255,255,255,0.65);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;}
.wm-champ-name{font-size:26px;font-weight:800;color:#fff;letter-spacing:-0.5px;}
.wm-champ-sub{font-size:11px;color:rgba(255,255,255,0.55);margin-top:3px;}

/* WM Bet form inside match */
.wm-bet-form{background:var(--surface2);border-top:0.5px solid var(--sep);padding:8px 12px;display:none;}
.wm-bet-form.open{display:flex;gap:8px;flex-wrap:wrap;align-items:center;}
.wm-bet-row{display:flex;gap:6px;align-items:center;flex-wrap:wrap;}
.wm-binp{width:72px;padding:4px 8px;background:var(--surface);border:0.5px solid var(--sep);border-radius:6px;color:var(--t1);font-family:var(--font);font-size:12px;}
.wm-binp:focus{border-color:var(--blue);outline:none;}

/* Responsive */
@media(max-width:640px){
  .wm-group-grid{grid-template-columns:1fr;}
  .wm-banner{padding:14px 0 8px;}
  .wm-title{font-size:16px;}
  .wm-bracket{min-width:680px;}
  .wm-br-col{min-width:130px;}
}
</style>
</head>
<body>

<?php if (!$loggedIn): ?>
<div class="login-page">
  <div class="login-card">
    <div class="login-logo">
      <div class="login-logo-icon">🎯</div>
      <div class="login-logo-text">Wett<span>Pro</span></div>
    </div>
    <div class="login-sub">Privater Bereich · hallo.cloud/bet</div>
    <?php if ($loginError): ?>
      <div class="login-alert login-alert-err">⚠️ <?= htmlspecialchars($loginError) ?></div>
    <?php elseif (($_GET['bye']??'')==='1'): ?>
      <div class="login-alert login-alert-ok">✓ Erfolgreich ausgeloggt.</div>
    <?php elseif (($_GET['e']??'')==='auth'): ?>
      <div class="login-alert login-alert-err">Sitzung abgelaufen. Bitte neu anmelden.</div>
    <?php endif; ?>
    <form method="POST" action="index.php" autocomplete="off">
      <input type="hidden" name="_action" value="login">
      <input type="hidden" name="_csrf" value="<?= htmlspecialchars($csrf) ?>">
      <label class="lbl" for="un">Benutzer</label>
      <select name="username" id="un" class="inp">
        <?php foreach (userList() as $u): ?>
          <option value="<?= htmlspecialchars($u['name'], ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($u['display'], ENT_QUOTES, 'UTF-8') ?></option>
        <?php endforeach; ?>
      </select>
      <label class="lbl" for="pw">Passwort</label>
      <input type="password" name="password" id="pw" class="inp" placeholder="••••••••••••" autocomplete="current-password" required>
      <button type="submit" class="btn-login">Einloggen →</button>
    </form>
    <a href="public.php" class="login-public">🌐 Öffentliche Wett-Übersicht ansehen</a>
    <div class="login-footer">Nur für autorisierte Nutzer · <?= date('Y') ?></div>
  </div>
</div>

<?php else: ?>

<div class="topbar">
  <div class="topbar-inner">
    <div class="tb-brand" onclick="go('dash')" style="cursor:pointer;user-select:none;" title="Zum Dashboard">Wett<span>Pro</span></div>
    <div class="tb-spacer"></div>
    <div class="me-pill" title="Eingeloggt als"><span class="me-dot"></span><?= htmlspecialchars($me, ENT_QUOTES, 'UTF-8') ?></div>
    <button class="ib invite-bell" id="invite-bell" onclick="openInvitesModal()" title="Wett-Anfragen">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
      <span class="invite-count" id="invite-count" hidden>0</span>
    </button>
    <a class="ib" href="public.php" target="_blank" rel="noopener" title="Öffentliche Ansicht">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
    </a>
    <button class="ib" id="theme-btn" onclick="toggleTheme()" title="Dark/Light Mode">
      <span id="theme-ico">☀️</span>
    </button>
    <button class="ib" onclick="exportCSV()" title="CSV Export">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
    </button>
    <button class="ib" onclick="openAccountModal()" title="Account / Passwort">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
    </button>
    <form method="POST" class="logout-form">
      <input type="hidden" name="_action" value="logout">
      <button type="submit" class="ib" title="Ausloggen">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </button>
    </form>
  </div>
</div>

<div class="app">

  <!-- METRICS -->
  <div class="mtr-grid" id="mtr-grid">
    <div class="mtr"><div class="mtr-lbl">P&L Gesamt</div><div class="mtr-val cn" id="m-pnl">–</div><div class="mtr-sub">abgeschl. Wetten</div></div>
    <div class="mtr"><div class="mtr-lbl">ROI</div><div class="mtr-val cn" id="m-roi">–</div><div class="mtr-sub" id="m-roi-s">abgeschl. Wetten</div></div>
    <div class="mtr"><div class="mtr-lbl">Trefferquote</div><div class="mtr-val cn" id="m-win">–</div><div class="mtr-sub" id="m-win-s">–</div></div>
    <div class="mtr"><div class="mtr-lbl">Ø Quote</div><div class="mtr-val cn" id="m-odds">–</div><div class="mtr-sub">gewonnene</div></div>
    <div class="mtr"><div class="mtr-lbl">Einsatz Total</div><div class="mtr-val cn" id="m-stake">–</div><div class="mtr-sub" id="m-stake-s">offen: –</div></div>
  </div>

  <!-- TABS -->
  <div class="tabs">
    <button class="tab on"  onclick="go('kalender')">Kalender</button>
    <button class="tab"     onclick="go('dash')">Dashboard</button>
    <button class="tab"     onclick="go('spiele')">Spiele</button>
    <button class="tab"     onclick="go('add')">+ Wette</button>
    <button class="tab"     onclick="go('kombi')">Kombi</button>
    <button class="tab"     onclick="go('hist')">Verlauf</button>
    <button class="tab"     onclick="go('stats')">Statistiken</button>
    <button class="tab"     onclick="go('tools')">Tools</button>
    <button class="tab"     onclick="go('wm')">WM 2026</button>
    <button class="tab"     onclick="go('casino')">Casino</button>
  </div>

  <!-- ====================================================
       TAB: KALENDER (Pikkit Style)
  ==================================================== -->
  <div class="sec on" id="sec-kalender">
    <div class="cal-header">
      <div>
        <span class="cal-title" id="cal-month-title">–</span>
        <span class="cal-title-sub" id="cal-month-pnl"></span>
      </div>
      <div style="display:flex;gap:8px;align-items:center;">
        <div class="unit-seg">
          <button class="unit-btn on" id="u-eur" onclick="setUnit('eur')">€</button>
          <button class="unit-btn" id="u-unit" onclick="setUnit('unit')">Units</button>
        </div>
        <div class="cal-nav">
          <button class="cal-nav-btn" onclick="calPrev()">‹</button>
          <button class="cal-nav-btn" onclick="calToday()" style="font-size:11px;font-weight:600;width:auto;padding:0 10px;">Heute</button>
          <button class="cal-nav-btn" onclick="calNext()">›</button>
        </div>
      </div>
    </div>

    <div class="card card-pad" style="margin-bottom:12px;">
      <div class="cal-grid" id="cal-grid"></div>
      <div class="cal-month-sum" id="cal-sum"></div>
    </div>

    <div id="day-detail-wrap"></div>

    <div class="sh">Tages-Wetten</div>
    <div class="card" id="cal-bet-list">
      <div class="empty"><div class="empty-ico">📅</div>Tag anklicken für Details</div>
    </div>
  </div>

  <!-- ====================================================
       TAB: DASHBOARD
  ==================================================== -->
  <div class="sec" id="sec-dash">
    <div class="sh">Bankroll-Verlauf</div>
    <div class="card card-pad" style="margin-bottom:16px;">
      <div class="chw chw-200"><canvas id="c-bankroll"></canvas></div>
    </div>
    <div class="sh">Monats-Performance</div>
    <div class="card card-pad" style="margin-bottom:16px;">
      <div class="chw chw-160"><canvas id="c-months"></canvas></div>
    </div>
    <div class="sh">Letzte Wetten</div>
    <div class="card" id="dash-list"></div>
  </div>

  <!-- ====================================================
       TAB: SPIELE
  ==================================================== -->
  <div class="sec" id="sec-spiele">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;gap:8px;flex-wrap:wrap;">
      <span class="sh" style="margin:0;">Kommende Spiele</span>
      <div style="display:flex;align-items:center;gap:8px;">
        <span id="fix-status" style="font-size:11px;color:var(--t3);">—</span>
        <button class="btn btn-s btn-sm" onclick="refreshFixtures()" title="Cache umgehen und API neu laden">Aktualisieren</button>
      </div>
    </div>
    <div class="chips" id="sport-chips"></div>
    <div class="card" id="games-list"></div>
    <div style="font-size:11px;color:var(--t3);text-align:center;margin-top:8px;">Auf Quote tippen → Wette wird vorausgefüllt</div>
  </div>

  <!-- ====================================================
       TAB: WETTE HINZUFÜGEN
  ==================================================== -->
  <div class="sec" id="sec-add">
    <div class="cbox" id="cbox">
      <div style="font-size:11px;font-weight:600;color:var(--t2);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px;">Live-Kalkulation</div>
      <div id="cbox-content"></div>
    </div>
    <div class="card card-pad" style="margin-bottom:14px;">
      <div class="fc">
        <div class="fg fg2">
          <div class="fl"><label>Datum</label><input class="fi" type="date" id="f-date"></div>
          <div class="fl"><label>Sportart</label>
            <select class="fi" id="f-sport">
              <option>Fußball</option><option>Tennis</option><option>Basketball</option>
              <option>Eishockey</option><option>American Football</option><option>Baseball</option>
              <option>MMA / Boxen</option><option>Sonstiges</option>
            </select>
          </div>
        </div>
        <div class="fg fg1">
          <div class="fl"><label>Tipp / Beschreibung</label>
            <input class="fi" type="text" id="f-desc" placeholder="z.B. Bayern – Dortmund, Heimsieg">
          </div>
        </div>
        <div class="fg fg2">
          <div class="fl"><label>Liga / Wettbewerb</label><input class="fi" type="text" id="f-league" placeholder="Champions League"></div>
          <div class="fl"><label>Markt</label>
            <select class="fi" id="f-market">
              <option>1X2</option><option>Über/Unter</option><option>Handicap</option>
              <option>Beide Teams treffen</option><option>Ergebniswette</option>
              <option>Outright</option><option>Sonstiges</option>
            </select>
          </div>
        </div>
        <div class="fg fg3">
          <div class="fl"><label>Einsatz (€) <span id="f-stake-hint" class="t3-hint" style="display:none">(auto = Summe der Anteile)</span></label><input class="fi" type="number" id="f-stake" placeholder="10.00" step="0.01" min="0" oninput="liveCalc()"></div>
          <div class="fl"><label>Quote</label><input class="fi" type="number" id="f-odds" placeholder="1.85" step="0.01" min="1" oninput="liveCalc()"></div>
          <div class="fl"><label>Status</label>
            <select class="fi" id="f-status">
              <option value="open">Offen</option><option value="won">Gewonnen</option>
              <option value="lost">Verloren</option><option value="cashout">Cashout</option>
            </select>
          </div>
        </div>
        <!-- Shared Bets Toggle + Teilnehmer -->
        <div class="fg fg1">
          <div class="fl">
            <label class="shared-toggle">
              <input type="checkbox" id="f-shared" onchange="toggleSharedForm()">
              <span>Geteilte Wette (mit anderen Nutzern)</span>
            </label>
          </div>
        </div>
        <div id="f-shared-box" class="shared-box" style="display:none;">
          <div class="shared-hint">Anteil pro Nutzer in € eintragen. Der Gesamteinsatz oben wird automatisch aus der Summe berechnet.</div>
          <div id="f-participants"></div>
          <div class="shared-totals">
            <span class="t3-hint">Summe:</span>
            <span id="f-shared-total">0.00 €</span>
            <span class="t3-hint" style="margin-left:auto;">Dein Anteil:</span>
            <span id="f-shared-mine">0%</span>
          </div>
        </div>
        <div class="fg fg3">
          <div class="fl"><label>Buchmacher</label>
            <select class="fi" id="f-bookie">
              <option data-tax="0">BWIN</option>
              <option data-tax="0">Bet365</option><option data-tax="0">Tipico</option>
              <option data-tax="0">Unibet</option><option data-tax="0">Betway</option>
              <option data-tax="0">Interwetten</option><option data-tax="0">Sonstiges</option>
            </select>
          </div>
          <div class="fl"><label>Cashout (€)</label><input class="fi" type="number" id="f-cashout" placeholder="optional" step="0.01" min="0"></div>
        </div>
        <div class="fg fg1">
          <div class="fl"><label>Notiz</label><input class="fi" type="text" id="f-note" placeholder="z.B. Value-Bet, Verletzungen..."></div>
        </div>
      </div>
    </div>
    <div style="display:flex;gap:10px;align-items:center;">
      <button class="btn btn-p" style="flex:1;" onclick="saveBet()">Wette speichern</button>
      <button class="btn btn-s btn-sm" onclick="resetForm()">Reset</button>
    </div>
    <div id="f-err" style="font-size:12px;color:var(--red);margin-top:8px;text-align:center;min-height:18px;"></div>
  </div>

  <!-- ====================================================
       TAB: KOMBI
  ==================================================== -->
  <div class="sec" id="sec-kombi">
    <div class="sh">Kombiwette berechnen &amp; speichern</div>
    <div class="card card-pad" style="margin-bottom:14px;">
      <div style="font-size:13px;font-weight:600;margin-bottom:12px;">Tipps (Legs)</div>
      <div id="kombi-legs"></div>
      <button class="btn btn-s btn-sm" onclick="addLeg()">+ Tipp hinzufügen</button>
    </div>
    <div class="card card-pad" id="kombi-result" style="display:none;margin-bottom:14px;">
      <div class="fg fg2" style="margin-bottom:12px;">
        <div class="fl"><label>Einsatz (€)</label><input class="fi" type="number" id="k-stake" placeholder="10.00" step="0.01" oninput="calcKombi()"></div>
        <div class="fl"><label>Buchmacher</label>
          <select class="fi" id="k-bookie" onchange="calcKombi()">
            <option data-tax="0">BWIN</option><option data-tax="0">Bet365</option>
            <option data-tax="0">Tipico</option><option data-tax="0">Sonstiges</option>
          </select>
        </div>
      </div>
      <div class="cbox show" id="k-calc"></div>
      <button class="btn btn-p btn-full" style="margin-top:12px;" onclick="saveKombi()">Kombiwette speichern</button>
    </div>
  </div>

  <!-- ====================================================
       TAB: VERLAUF
  ==================================================== -->
  <div class="sec" id="sec-hist">
    <div class="fbar">
      <select class="fsel" id="flt-sport" onchange="renderHist()">
        <option value="">Alle Sportarten</option>
        <option>Fußball</option><option>Tennis</option><option>Basketball</option>
        <option>Eishockey</option><option>American Football</option><option>MMA / Boxen</option>
      </select>
      <select class="fsel" id="flt-status" onchange="renderHist()">
        <option value="">Alle Status</option>
        <option value="open">Offen</option><option value="won">Gewonnen</option>
        <option value="lost">Verloren</option><option value="cashout">Cashout</option>
      </select>
      <select class="fsel" id="flt-bookie" onchange="renderHist()">
        <option value="">Alle Buchmacher</option>
        <option>BWIN</option><option>Bet365</option><option>Tipico</option>
        <option>Unibet</option><option>Betway</option><option>Sonstiges</option>
      </select>
      <select class="fsel" id="flt-user" onchange="renderHist()">
        <option value="">Alle Nutzer</option>
        <option>Felix</option><option>Paul</option>
      </select>
      <select class="fsel" id="flt-sort" onchange="renderHist()">
        <option value="dd">Neueste zuerst</option>
        <option value="da">Älteste zuerst</option>
        <option value="sd">Einsatz ↓</option>
        <option value="od">Quote ↓</option>
        <option value="pd">P&L ↓</option>
      </select>
    </div>
    <div id="hist-list"></div>
  </div>

  <!-- ====================================================
       TAB: STATISTIKEN
  ==================================================== -->
  <div class="sec" id="sec-stats">
    <div class="sh">Nach Sportart</div>
    <div class="card" style="margin-bottom:16px;overflow:auto;">
      <table class="stbl"><thead><tr>
        <th>Sport</th><th>Wetten</th><th>G/V</th><th>Ø Quote</th><th>Einsatz</th><th>P&L</th><th>ROI</th>
      </tr></thead><tbody id="tb-sport"></tbody></table>
    </div>
    <div class="sh">Performance nach Wochentag</div>
    <div class="card card-pad" style="margin-bottom:16px;">
      <div class="chw chw-140"><canvas id="c-weekday"></canvas></div>
    </div>
    <div class="sh">Nach Buchmacher</div>
    <div class="card" style="margin-bottom:16px;overflow:auto;">
      <table class="stbl"><thead><tr>
        <th>Buchmacher</th><th>Wetten</th><th>Einsatz</th><th>P&L</th><th>ROI</th>
      </tr></thead><tbody id="tb-bookie"></tbody></table>
    </div>
    <div class="sh">Nach Nutzer</div>
    <div class="card" style="margin-bottom:16px;overflow:auto;">
      <table class="stbl"><thead><tr>
        <th>Nutzer</th><th>Wetten</th><th>Einsatz</th><th>P&L</th><th>ROI</th>
      </tr></thead><tbody id="tb-user"></tbody></table>
    </div>
    <div class="sh">Performance nach Quotenbereich</div>
    <div class="card" style="overflow:auto;">
      <table class="stbl"><thead><tr>
        <th>Quotenbereich</th><th>Wetten</th><th>Trefferquote</th><th>P&L</th><th>ROI</th>
      </tr></thead><tbody id="tb-odds"></tbody></table>
    </div>

    <!-- ====================================================
         Team-Stats: nur Kombi-Wetten mit Team-Tag in legs
    ==================================================== -->
    <div style="display:flex;align-items:center;justify-content:space-between;margin:24px 0 8px;">
      <span class="sh" style="margin:0;">Beste Teams</span>
      <span class="t3-hint">Aus Kombi-Legs · sortiert nach P&L</span>
    </div>
    <div class="card" style="margin-bottom:16px;overflow:auto;">
      <table class="stbl"><thead><tr>
        <th>Team</th><th>Wetten</th><th>G</th><th>V</th><th>P&L</th>
      </tr></thead><tbody id="tb-team-best"><tr><td colspan="5" style="text-align:center;color:var(--t3);padding:14px;">Lade…</td></tr></tbody></table>
    </div>

    <div style="display:flex;align-items:center;justify-content:space-between;margin:24px 0 8px;">
      <span class="sh" style="margin:0;">Teams die uns oft verkaufen</span>
      <span class="t3-hint">Sortiert nach negativem P&L</span>
    </div>
    <div class="card" style="overflow:auto;">
      <table class="stbl"><thead><tr>
        <th>Team</th><th>Wetten</th><th>G</th><th>V</th><th>P&L</th>
      </tr></thead><tbody id="tb-team-worst"><tr><td colspan="5" style="text-align:center;color:var(--t3);padding:14px;">Lade…</td></tr></tbody></table>
    </div>
  </div>

  <!-- ====================================================
       TAB: TOOLS
  ==================================================== -->
  <div class="sec" id="sec-tools">
    <div class="sh">Kelly-Kriterium Rechner</div>
    <div class="tool-card">
      <div class="fg fg3" style="margin-bottom:0;">
        <div class="fl"><label>Bankroll (€)</label><input class="fi" type="number" id="kl-bank" placeholder="1000" oninput="calcKelly()"></div>
        <div class="fl"><label>Wahrscheinlichkeit (%)</label><input class="fi" type="number" id="kl-prob" placeholder="55" oninput="calcKelly()"></div>
        <div class="fl"><label>Quote</label><input class="fi" type="number" id="kl-odds" placeholder="2.00" step="0.01" oninput="calcKelly()"></div>
      </div>
      <div class="kelly-res" id="kl-res" style="display:none;">
        <div class="crow"><span class="clbl">Kelly-Einsatz (100%)</span><span class="cval cg" id="kl-full">–</span></div>
        <div class="crow"><span class="clbl">Half-Kelly (empfohlen)</span><span class="cval cg" id="kl-half">–</span></div>
        <div class="crow" style="border-top:0.5px solid var(--sep);padding-top:8px;margin-top:4px;font-weight:600;font-size:14px;"><span class="clbl">Quarter-Kelly (konservativ)</span><span class="cval cg" id="kl-qtr">–</span></div>
      </div>
    </div>
    <div class="sh">Quote umrechnen</div>
    <div class="tool-card">
      <div class="fg fg2" style="margin-bottom:0;">
        <div class="fl"><label>Dezimal</label><input class="fi" type="number" id="cv-dec" placeholder="2.50" step="0.01" oninput="calcConv()"></div>
        <div class="fl"><label>Implied Prob.</label><input class="fi" id="cv-prob" readonly style="cursor:default;background:var(--surface3);"></div>
      </div>
      <div class="fg fg2" style="margin-top:12px;margin-bottom:0;">
        <div class="fl"><label>US Odds</label><input class="fi" id="cv-us" readonly style="cursor:default;background:var(--surface3);"></div>
        <div class="fl"><label>Fractional (UK)</label><input class="fi" id="cv-frac" readonly style="cursor:default;background:var(--surface3);"></div>
      </div>
    </div>
    <div class="sh">Value-Bet Erkennung</div>
    <div class="tool-card">
      <div class="fg fg2" style="margin-bottom:0;">
        <div class="fl"><label>Angebotene Quote</label><input class="fi" type="number" id="vb-odds" placeholder="2.20" step="0.01" oninput="calcVB()"></div>
        <div class="fl"><label>Deine Wahrscheinlichkeit (%)</label><input class="fi" type="number" id="vb-prob" placeholder="55" oninput="calcVB()"></div>
      </div>
      <div class="vb-box" id="vb-res" style="display:none;"></div>
    </div>
    <div class="sh">Streak-Analyse</div>
    <div class="tool-card" id="streak-box"></div>
  </div>

  <!-- ====================================================
       TAB: WM 2026
  ==================================================== -->
  <div class="sec" id="sec-wm">

    <!-- WM Banner -->
    <div class="wm-banner">
      <div class="wm-banner-icon">⚽</div>
      <div>
        <div class="wm-title">FIFA WM 2026</div>
        <div class="wm-sub">USA · Mexiko · Kanada &nbsp;·&nbsp; 11. Juni – 19. Juli 2026</div>
      </div>
    </div>

    <!-- WM Dashboard Metrics -->
    <div class="mtr-grid" id="wm-mtr">
      <div class="mtr"><div class="mtr-lbl">WM P&amp;L</div><div class="mtr-val cn" id="wm-m-pnl">–</div><div class="mtr-sub">eigene WM-Wetten</div></div>
      <div class="mtr"><div class="mtr-lbl">Trefferquote WM</div><div class="mtr-val cn" id="wm-m-wr">–</div><div class="mtr-sub" id="wm-m-wr-s">abgeschl. Wetten</div></div>
      <div class="mtr"><div class="mtr-lbl">Spiele gespielt</div><div class="mtr-val cn" id="wm-m-played">–</div><div class="mtr-sub" id="wm-m-open">offen: –</div></div>
      <div class="mtr"><div class="mtr-lbl">Weltmeister</div><div class="mtr-val" id="wm-m-champ" style="font-size:14px;">–</div><div class="mtr-sub">laut Turnierstand</div></div>
    </div>

    <!-- WM Sub-Tabs -->
    <div class="wm-tabs">
      <button class="wm-tab on"  onclick="wmTab('groups')">⚽ Gruppen</button>
      <button class="wm-tab"     onclick="wmTab('bracket')">🏆 Turnierbaum</button>
      <button class="wm-tab"     onclick="wmTab('bets')">💰 WM-Wetten</button>
    </div>

    <!-- PANEL: Gruppen -->
    <div class="wm-panel on" id="wm-panel-groups">
      <div id="wm-groups-container">
        <div class="empty"><div class="empty-ico">⚽</div>Lade WM-Daten…</div>
      </div>
    </div>

    <!-- PANEL: Turnierbaum -->
    <div class="wm-panel" id="wm-panel-bracket">
      <div id="wm-champion-box"></div>
      <div class="wm-bracket-outer">
        <div class="wm-bracket" id="wm-bracket-container"></div>
      </div>
    </div>

    <!-- PANEL: WM-Wetten -->
    <div class="wm-panel" id="wm-panel-bets">
      <div id="wm-bets-container">
        <div class="empty"><div class="empty-ico">💰</div>Lade WM-Wetten…</div>
      </div>
    </div>

  </div>

  <!-- ====================================================
       TAB: CASINO
  ==================================================== -->
  <div class="sec" id="sec-casino">

    <div class="wm-banner">
      <div class="wm-banner-icon">🎰</div>
      <div>
        <div class="wm-title">Casino</div>
        <div class="wm-sub">Slots · Roulette · Blackjack · Poker — Sessions tracken</div>
      </div>
    </div>

    <!-- Casino Metrics -->
    <div class="mtr-grid" id="casino-mtr">
      <div class="mtr"><div class="mtr-lbl">Casino P&amp;L</div><div class="mtr-val cn" id="ca-m-pnl">–</div><div class="mtr-sub">alle Sessions</div></div>
      <div class="mtr"><div class="mtr-lbl">Sessions</div><div class="mtr-val cn" id="ca-m-cnt">–</div><div class="mtr-sub" id="ca-m-wr">Gewinnquote: –</div></div>
      <div class="mtr"><div class="mtr-lbl">Einsatz Total</div><div class="mtr-val cn" id="ca-m-buyin">–</div><div class="mtr-sub">gesamter Buy-In</div></div>
      <div class="mtr"><div class="mtr-lbl">Beste Session</div><div class="mtr-val cn" id="ca-m-best">–</div><div class="mtr-sub" id="ca-m-best-s">–</div></div>
    </div>

    <!-- Add Session -->
    <div class="sh">Neue Session</div>
    <div class="card card-pad" style="margin-bottom:16px;">
      <div class="fc">
        <div class="fg fg2">
          <div class="fl"><label>Datum</label><input class="fi" type="date" id="ca-date"></div>
          <div class="fl"><label>Spiel</label>
            <select class="fi" id="ca-game">
              <option>Slots</option><option>Roulette</option><option>Blackjack</option>
              <option>Poker</option><option>Baccarat</option><option>Crash / Aviator</option>
              <option>Sonstiges</option>
            </select>
          </div>
        </div>
        <div class="fg">
          <div class="fl"><label>Anbieter / Casino</label><input class="fi" type="text" id="ca-provider" placeholder="z.B. Bwin, Stake, Pokerstars"></div>
        </div>
        <div class="fg fg2">
          <div class="fl"><label>Buy-In (€)</label><input class="fi" type="number" step="0.01" min="0" id="ca-buyin" placeholder="0.00" oninput="caLiveCalc()"></div>
          <div class="fl"><label>Auszahlung (€)</label><input class="fi" type="number" step="0.01" min="0" id="ca-cashout" placeholder="0.00" oninput="caLiveCalc()"></div>
        </div>
        <div class="fg">
          <div class="fl"><label>Notiz (optional)</label><input class="fi" type="text" id="ca-note" placeholder="z.B. Bonus, Freispiele…"></div>
        </div>
        <div id="ca-calc" style="font-size:13px;font-weight:600;margin:4px 0 10px;color:var(--t2);">Ergebnis: –</div>
        <button class="btn btn-p btn-full" onclick="casinoAdd()">Session speichern</button>
      </div>
    </div>

    <!-- Session List -->
    <div class="sh">Sessions</div>
    <div class="card" id="casino-list">
      <div class="empty"><div class="empty-ico">🎰</div>Lade Sessions…</div>
    </div>
  </div>

</div>

<!-- INVITES MODAL ================================================= -->
<div class="inv-modal" id="inv-modal" hidden>
  <div class="inv-backdrop" onclick="closeInvitesModal()"></div>
  <div class="inv-card" role="dialog" aria-modal="true" aria-labelledby="inv-title">
    <div class="inv-head">
      <div class="inv-title" id="inv-title">Wett-Anfragen</div>
      <button class="ib" onclick="closeInvitesModal()" title="Schließen">×</button>
    </div>
    <div id="inv-list"></div>
  </div>
</div>

<!-- ACCOUNT / SECURITY MODAL ===================================== -->
<div class="acct-modal" id="acct-modal" hidden>
  <div class="acct-backdrop" onclick="closeAccountModal()"></div>
  <div class="acct-card" role="dialog" aria-modal="true" aria-labelledby="acct-title">
    <div class="acct-head">
      <div class="acct-title" id="acct-title">Account</div>
      <button class="ib" onclick="closeAccountModal()" title="Schließen" aria-label="Schließen">×</button>
    </div>
    <div class="acct-tabs">
      <button class="acct-tab on" data-tab="pw" onclick="acctTab('pw')">Passwort ändern</button>
      <button class="acct-tab"    data-tab="new" onclick="acctTab('new')">Neuer Account</button>
    </div>

    <!-- Passwort ändern -->
    <form id="pw-form" class="acct-form" autocomplete="off" onsubmit="return submitPwChange(event)">
      <div id="pw-msg" class="acct-msg" hidden></div>
      <label class="lbl" for="pw-cur">Aktuelles Passwort</label>
      <input type="password" id="pw-cur" class="inp" autocomplete="current-password" required>
      <label class="lbl" for="pw-new">Neues Passwort</label>
      <input type="password" id="pw-new" class="inp" autocomplete="new-password" minlength="<?= PW_MIN_LEN ?>" required>
      <label class="lbl" for="pw-cnf">Neues Passwort bestätigen</label>
      <input type="password" id="pw-cnf" class="inp" autocomplete="new-password" minlength="<?= PW_MIN_LEN ?>" required>
      <div class="acct-hint">Min. <?= PW_MIN_LEN ?> Zeichen, mind. 3 Zeichen-Arten (a-z, A-Z, 0-9, Sonderzeichen).</div>
      <button class="btn btn-p btn-full" type="submit">Passwort ändern</button>
    </form>

    <!-- Neuen Account anlegen -->
    <form id="new-form" class="acct-form" autocomplete="off" onsubmit="return submitNewAccount(event)" hidden>
      <div id="new-msg" class="acct-msg" hidden></div>
      <label class="lbl" for="new-un">Benutzername</label>
      <input type="text" id="new-un" class="inp" autocomplete="off" pattern="[A-Za-z][A-Za-z0-9_\-]*" minlength="<?= UN_MIN_LEN ?>" maxlength="<?= UN_MAX_LEN ?>" required>
      <label class="lbl" for="new-pw">Passwort</label>
      <input type="password" id="new-pw" class="inp" autocomplete="new-password" minlength="<?= PW_MIN_LEN ?>" required>
      <label class="lbl" for="new-cnf">Passwort bestätigen</label>
      <input type="password" id="new-cnf" class="inp" autocomplete="new-password" minlength="<?= PW_MIN_LEN ?>" required>
      <label class="lbl" for="new-color">Farbe (optional)</label>
      <input type="color" id="new-color" class="inp acct-color" value="#7f6af8">
      <div class="acct-hint">Nur eingeloggte Nutzer können Accounts anlegen. Der neue Nutzer loggt sich anschließend separat ein.</div>
      <button class="btn btn-p btn-full" type="submit">Account anlegen</button>
    </form>
  </div>
</div>

<div id="toast"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script>
const CSRF   = <?= json_encode($csrf) ?>;
const ME_INIT= <?= json_encode($me) ?>;
let CSRF_TOKEN = CSRF;  // wird nach Passwort-Wechsel serverseitig rotiert und hier mit aktualisiert

const EMOJI   = {Fußball:'⚽',Tennis:'🎾',Basketball:'🏀',Eishockey:'🏒','American Football':'🏈',Baseball:'⚾','MMA / Boxen':'🥊',Sonstiges:'🎯'};
const SPORT_BG= {Fußball:'rgba(37,99,235,0.10)',Tennis:'rgba(22,163,74,0.10)',Basketball:'rgba(217,119,6,0.10)',Eishockey:'rgba(124,58,237,0.10)','American Football':'rgba(220,38,38,0.10)',Baseball:'rgba(8,145,178,0.10)','MMA / Boxen':'rgba(220,38,38,0.10)',Sonstiges:'rgba(100,100,120,0.10)'};

const DEMO_GAMES = [
  {id:'g01',home:'Bayern München',away:'Dortmund',league:'Bundesliga',sport:'Fußball',time:'18:30',live:false,h:1.82,d:3.70,a:4.30},
  {id:'g02',home:'Arsenal',away:'Chelsea',league:'Premier League',sport:'Fußball',time:'LIVE 58\'',live:true,h:2.05,d:3.40,a:3.60},
  {id:'g03',home:'Real Madrid',away:'FC Barcelona',league:'La Liga',sport:'Fußball',time:'21:00',live:false,h:2.15,d:3.35,a:3.20},
  {id:'g04',home:'Inter Mailand',away:'AC Milan',league:'Serie A',sport:'Fußball',time:'20:45',live:false,h:2.30,d:3.20,a:3.10},
  {id:'g05',home:'Paris SG',away:'Marseille',league:'Ligue 1',sport:'Fußball',time:'21:00',live:false,h:1.60,d:3.80,a:5.50},
  {id:'g06',home:'Djokovic',away:'Alcaraz',league:'Roland Garros SF',sport:'Tennis',time:'14:00',live:false,h:1.62,d:null,a:2.30},
  {id:'g07',home:'Sinner',away:'Zverev',league:'Roland Garros SF',sport:'Tennis',time:'11:00',live:false,h:1.55,d:null,a:2.50},
  {id:'g08',home:'Boston Celtics',away:'Miami Heat',league:'NBA Playoffs',sport:'Basketball',time:'01:30',live:false,h:1.52,d:null,a:2.60},
  {id:'g09',home:'OKC Thunder',away:'Dallas Mavericks',league:'NBA Playoffs',sport:'Basketball',time:'22:00',live:false,h:1.70,d:null,a:2.15},
  {id:'g10',home:'Tampa Bay',away:'Boston Bruins',league:'NHL Playoffs',sport:'Eishockey',time:'LIVE P2',live:true,h:2.25,d:null,a:1.68},
  {id:'g11',home:'Manchester City',away:'Liverpool',league:'Premier League',sport:'Fußball',time:'17:30',live:false,h:1.90,d:3.60,a:3.90},
];

let allBets    = [];
let allShares  = [];   // [{bet_id, user, stake}, ...] aus shares.csv
let allInvites = [];   // pending Invites fuer den eingeloggten Nutzer
let activeUser = ME_INIT;
let activeSport= 'all';
let comboLegs  = [];
let charts     = {};

// Calendar state
let calYear, calMonth, calUnit = 'eur', calSelectedDay = null;
const now = new Date();
calYear  = now.getFullYear();
calMonth = now.getMonth(); // 0-based

// ============================================================
//  THEME
// ============================================================
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  document.getElementById('theme-ico').textContent = t==='dark'?'☀️':'🌙';
  localStorage.setItem('wtp_theme', t);
}
function toggleTheme() {
  applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');
}
(function(){
  const saved = localStorage.getItem('wtp_theme');
  const pref  = window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
  applyTheme(saved||pref);
})();

// ============================================================
//  TOAST
// ============================================================
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(()=>el.classList.remove('show'), 2400);
}

// ============================================================
//  USER
// ============================================================
function setUser(u) {
  // Strikte User-Trennung: Umschalten ist deaktiviert. activeUser ist
  // immer der eingeloggte Nutzer (ME_INIT). Funktion bleibt als no-op
  // erhalten, falls irgendwo im alten Code noch jemand setUser aufruft.
  if (u !== activeUser) toast('Strikte User-Trennung — keine Umschaltung möglich');
}

// ============================================================
//  TABS
// ============================================================
const TAB_IDS = ['kalender','dash','spiele','add','kombi','hist','stats','tools','wm','casino'];

function go(id) {
  document.querySelectorAll('.tab').forEach((b,i)=>b.classList.toggle('on',TAB_IDS[i]===id));
  document.querySelectorAll('.sec').forEach(s=>s.classList.remove('on'));
  document.getElementById('sec-'+id).classList.add('on');
  if (id==='kalender') renderKalender();
  if (id==='dash')     renderDash();
  if (id==='spiele')   renderSpiele();
  if (id==='hist')     renderHist();
  if (id==='stats')    renderStats();
  if (id==='tools')    renderTools();
  if (id==='kombi')    initKombi();
  if (id==='wm')       renderWM();
  if (id==='casino')   renderCasino();
}

// ============================================================
//  API
// ============================================================
async function api(action, body) {
  try {
    const opts = body
      ? {method:'POST',headers:{'Content-Type':'application/json','Cache-Control':'no-store'},body:JSON.stringify({...body,_csrf:CSRF_TOKEN}),cache:'no-store'}
      : {method:'GET',headers:{'Cache-Control':'no-store'},cache:'no-store'};
    const url = '?a=' + action + (body ? '' : '&_t=' + Date.now());
    const r = await fetch(url, opts);
    if (r.status === 401) { location.href = 'index.php?e=auth'; return null; }
    let data = null;
    const text = await r.text();
    try { data = text ? JSON.parse(text) : null; } catch(_) { data = null; }
    if (!r.ok) {
      // 4xx/5xx — lautes Feedback statt stillem Schlucken
      const reason = (data && (data.e || data.error)) || ('HTTP ' + r.status);
      toast('Fehler: ' + reason);
      console.error('API ' + action + ' fehlgeschlagen', r.status, text);
      return data || { ok:false, error: reason, status: r.status };
    }
    return data;
  } catch(e) { toast('Netzwerkfehler'); console.error(e); return null; }
}

async function loadBets() {
  const d = await api('list');
  if (!d) return;
  allBets    = d.bets    || [];
  allShares  = d.shares  || [];
  allInvites = d.invites || [];
  refreshInviteBadge();
  renderAll();
}

function exportCSV(){window.location.href='?a=export';}

// ============================================================
//  CALCULATIONS — BWIN TAX (FIXED)
//  tax_rate ist in der CSV als Dezimalzahl gespeichert (z.B. 0.05 für 5%)
//  BWIN/DE-Wettsteuer = 5 % vom EINSATZ (nicht vom Gewinn!).
//  Formel:
//    gross = stake * odds         (Brutto-Auszahlung)
//    tax   = stake * taxRate      (Steuer auf Einsatz)
//    net   = gross - tax          (Netto-Auszahlung)
//    PnL   = net - stake          (Gewinn nach Steuer)
// ============================================================
function taxedReturn(stake, odds, taxRate) {
  // Tax wird auf den GEWINN berechnet (nicht auf den Einsatz).
  // Beispiel: Einsatz 100, Quote 2.80 -> gross=280, profit=180,
  // taxRate=0.05 -> tax=9, netProfit=171, netPayout=271.
  const gross     = stake * odds;
  const profit    = Math.max(0, gross - stake);    // bei Verlust gibts auch keine Steuer
  const tax       = profit * taxRate;
  const netProfit = profit - tax;
  const net       = stake + netProfit;             // Netto-Auszahlung
  return { gross, profit, tax, net, netProfit };
}

// ============================================================
//  SHARED BETS — Helper
//  Eine Bet ist 'shared' wenn fuer ihre id Eintraege in shares.csv stehen.
//  Standard-Wetten haben keine Eintraege; Eigentuemer = bet.user, Anteil = 1.
// ============================================================
function getBetShares(betId) {
  return allShares.filter(s => s.bet_id === betId);
}

function getMyShareFraction(b) {
  const shares = getBetShares(b.id);
  if (shares.length === 0) {
    // Standard-Wette: nur der Owner sieht die ganze P&L
    return b.user === activeUser ? 1.0 : 0.0;
  }
  const me = shares.find(s => s.user === activeUser);
  if (!me) return 0.0;
  const total = shares.reduce((sum, s) => sum + (+s.stake || 0), 0);
  return total > 0 ? (+me.stake) / total : 0;
}

function myStakeForBet(b) {
  const shares = getBetShares(b.id);
  if (shares.length === 0) return b.user === activeUser ? (+b.stake || 0) : 0;
  const me = shares.find(s => s.user === activeUser);
  return me ? +me.stake : 0;
}

function myPnLForBet(b) {
  return +(calcPnL(b) * getMyShareFraction(b)).toFixed(2);
}

function isSharedBet(b) {
  return getBetShares(b.id).length > 0;
}

// 'Beteiligt' = Owner einer Solo-Wette ODER explizit als Share-Eintrag drin.
// Dient als Filter, damit fremde Solo-Wetten nicht mit 0,00 € rumstehen.
function userInvolvedInBet(b, user) {
  user = user || activeUser;
  const shares = getBetShares(b.id);
  if (shares.length === 0) return b.user === user;
  return shares.some(s => s.user === user);
}

function myBets() {
  return allBets.filter(b => userInvolvedInBet(b, activeUser));
}

function calcPnL(b) {
  const stake   = +b.stake    || 0;
  const odds    = +b.odds     || 0;
  const taxRate = +b.tax_rate || 0;  // aus CSV: bereits Dezimal (0.05)
  const cashout = +b.cashout  || 0;
  if (b.status==='void') return 0;
  // Cashout: explizite Auszahlung (kann <stake oder >stake sein) → P&L = Cashout - Einsatz
  if (b.status==='cashout' || (cashout>0 && b.status==='open')) return +(cashout - stake).toFixed(2);
  if (b.status==='won')  return +(taxedReturn(stake, odds, taxRate).net - stake).toFixed(2);
  if (b.status==='lost') return -stake;
  return 0;
}

function fmtPnL(v)  { return (v>=0?'+':'')+((+v).toFixed(2))+' €'; }
function fmtAbs(v)  { return (+v).toFixed(2)+' €'; }
// Units: 1 Unit = durchschnittlicher Einsatz aller abgeschlossenen Wetten
function getUnitSize() {
  const settled = myBets().filter(b=>b.status==='won'||b.status==='lost');
  if (!settled.length) return 10;
  return settled.reduce((s,b)=>s+(+b.stake),0)/settled.length;
}
function toUnits(eur) { return eur/getUnitSize(); }
function fmtUnit(v)   { return (v>=0?'+':'')+toUnits(v).toFixed(2)+'u'; }
function fmtDisp(v)   { return calUnit==='unit' ? fmtUnit(v) : fmtPnL(v); }

// ============================================================
//  METRICS
// ============================================================
function updateMetrics() {
  // Alle Metriken auf 'meine Wetten' und 'mein Anteil' umrechnen.
  const myArr      = myBets();
  const settled    = myArr.filter(b=>b.status==='won'||b.status==='lost'||b.status==='cashout');
  const won        = settled.filter(b=>b.status==='won');
  // Einsatz/Tax: bei Shared Bets nur mein Anteil zaehlt.
  const myStake    = (b) => myStakeForBet(b);
  const allStake   = myArr.filter(b=>b.status!=='void').reduce((s,b)=>s+myStake(b),0);
  const openStake  = myArr.filter(b=>b.status==='open').reduce((s,b)=>s+myStake(b),0);
  const settledStk = settled.reduce((s,b)=>s+myStake(b),0);
  const pnl        = myArr.reduce((s,b)=>s+myPnLForBet(b),0);
  const roi        = settledStk>0 ? pnl/settledStk*100 : 0;
  const winRate    = settled.length ? won.length/settled.length*100 : 0;
  const avgOdds    = won.length ? won.reduce((s,b)=>s+(+b.odds),0)/won.length : 0;
  // Tax anteilig nach myShareFraction
  const set=(id,v,cls)=>{const e=document.getElementById(id);e.textContent=v;e.className='mtr-val '+cls;};
  set('m-pnl',   fmtPnL(pnl),         pnl>=0?'cg':'cr');
  set('m-roi',   roi.toFixed(1)+'%',   roi>=0?'cg':'cr');
  set('m-win',   winRate.toFixed(0)+'%','cb');
  set('m-odds',  avgOdds.toFixed(2)+'x','cn');
  set('m-stake', fmtAbs(allStake),     'cn');
  document.getElementById('m-stake-s').textContent='offen: '+fmtAbs(openStake);
  document.getElementById('m-win-s').textContent=won.length+'/'+settled.length+' abg.';
  document.getElementById('m-roi-s').textContent='aus '+settled.length+' Wetten';
}

// ============================================================
//  BET ITEM HTML
// ============================================================
function betHTML(b, del=true) {
  // 'pnl' fuer die Anzeige ist immer 'mein Anteil' — Standard-Wetten haben
  // Anteil = 100% wenn ich Owner bin, sonst 0%.
  const pnl     = myPnLForBet(b);
  const pstr    = (b.status!=='open'&&b.status!=='void') ? fmtPnL(pnl) : '—';
  const pcls    = pnl>0?'cg':pnl<0?'cr':'cn';
  const bcls    = {won:'bdg-won',lost:'bdg-lost',open:'bdg-open',cashout:'bdg-co',void:'bdg-void'}[b.status]||'bdg-void';
  const blbl    = {won:'Gewonnen',lost:'Verloren',open:'Offen',cashout:'Cashout',void:'Void'}[b.status]||b.status;
  const shared  = isSharedBet(b);
  const myFrac  = getMyShareFraction(b);
  const sharedBadge = shared ? `<span class="shared-badge" title="Geteilte Wette — dein Anteil">⤞ ${(myFrac*100).toFixed(0)}%</span>` : '';
  const ico  = EMOJI[b.sport]||'🎯';
  const ibg  = SPORT_BG[b.sport]||'rgba(100,100,120,0.10)';
  return `<div class="li">
    <div class="li-ico" style="background:${ibg};">${ico}</div>
    <div class="li-body">
      <div class="li-title">${b.desc}${sharedBadge}</div>
      <div class="li-sub">${b.date} · ${b.sport} · ${b.bookie} · ${(+b.odds).toFixed(2)}x · ${(+b.stake).toFixed(2)} € · ${b.user}</div>
    </div>
    <div class="li-right">
      <div>
        <div class="li-val ${pcls}">${pstr}</div>
        <div style="text-align:right;margin-top:3px;"><span class="bdg ${bcls}">${blbl}</span></div>
      </div>
      ${b.status === 'open'
        ? `<div class="bet-actions">
            <button class="ba-btn ba-win"  onclick="settleBet('${b.id}','won')"     title="Gewonnen">✓</button>
            <button class="ba-btn ba-lose" onclick="settleBet('${b.id}','lost')"    title="Verloren">✗</button>
            <button class="ba-btn ba-co"   onclick="settleBet('${b.id}','cashout')" title="Cashout">⤴</button>
          </div>`
        : `<select class="isel" onchange="settleBet('${b.id}',this.value)">
            ${['won','lost','cashout'].map(s =>
              `<option value="${s}"${b.status===s?' selected':''}>${{won:'Gew.',lost:'Verl.',cashout:'Cashout'}[s]}</option>`
            ).join('')}
          </select>`}
      ${del?`<button class="delbtn" onclick="delBet('${b.id}')">×</button>`:''}
    </div>
  </div>`;
}

// ============================================================
//  PIKKIT KALENDER
// ============================================================
function setUnit(u) {
  calUnit = u;
  document.getElementById('u-eur').classList.toggle('on', u==='eur');
  document.getElementById('u-unit').classList.toggle('on', u==='unit');
  renderKalender();
}

function calPrev()  { calMonth--; if(calMonth<0){calMonth=11;calYear--;} renderKalender(); }
function calNext()  { calMonth++; if(calMonth>11){calMonth=0;calYear++;} renderKalender(); }
function calToday() { calYear=now.getFullYear(); calMonth=now.getMonth(); calSelectedDay=null; renderKalender(); }

function renderKalender() {
  // Build day→bets map for this month
  const dayMap = {};
  myBets().forEach(b => {
    const d = new Date(b.date+'T00:00:00');
    if (d.getFullYear()===calYear && d.getMonth()===calMonth) {
      const k = d.getDate();
      if (!dayMap[k]) dayMap[k] = [];
      dayMap[k].push(b);
    }
  });

  // Month PnL
  let monthPnl = 0;
  Object.values(dayMap).forEach(bets => bets.forEach(b => { monthPnl += myPnLForBet(b); }));

  // Determine max abs pnl for intensity scale
  const dayPnls = Object.keys(dayMap).map(d => {
    let p=0; dayMap[d].forEach(b=>{ p+=myPnLForBet(b); }); return Math.abs(p);
  });
  const maxAbs = Math.max(...dayPnls, 0.01);

  // Header
  const monthNames=['Jänner','Februar','März','April','Mai','Juni','Juli','August','September','Oktober','November','Dezember'];
  document.getElementById('cal-month-title').textContent = monthNames[calMonth]+' '+calYear;
  const sub = document.getElementById('cal-month-pnl');
  sub.textContent = (calUnit==='unit' ? fmtUnit(monthPnl) : fmtPnL(monthPnl));
  sub.style.color = monthPnl>=0 ? 'var(--green)' : 'var(--red)';

  // Days of week header
  const dows = ['Mo','Di','Mi','Do','Fr','Sa','So'];
  const firstDay = new Date(calYear, calMonth, 1).getDay(); // 0=Sun
  const daysInMonth = new Date(calYear, calMonth+1, 0).getDate();
  // Convert Sunday=0 to Monday=0 grid
  const offset = (firstDay+6)%7;
  const todayStr = now.toISOString().slice(0,10);

  let html = dows.map(d=>`<div class="cal-dow">${d}</div>`).join('');

  // Empty cells before first day
  for (let i=0; i<offset; i++) html += `<div class="cal-day empty"></div>`;

  for (let day=1; day<=daysInMonth; day++) {
    const dateStr = calYear+'-'+String(calMonth+1).padStart(2,'0')+'-'+String(day).padStart(2,'0');
    const bets    = dayMap[day]||[];
    const isToday = dateStr===todayStr;
    const isSel   = calSelectedDay===day;

    let pnl=0, hasBets=bets.length>0;
    bets.forEach(b=>{ pnl+=myPnLForBet(b); });

    let colorCls = 'cal-neutral', intensity = 0;
    if (hasBets) {
      intensity = Math.min(5, Math.ceil(Math.abs(pnl)/maxAbs*5));
      colorCls = pnl>=0 ? `cal-win-${intensity}` : `cal-loss-${intensity}`;
    }

    const dispVal = hasBets ? (calUnit==='unit' ? fmtUnit(pnl).replace('+','') : fmtPnL(pnl).replace('+','').replace(' €','')) : '';
    // Bei kräftigem Hintergrund (Intensität >=3) weiße Schrift,
    // sonst farbige Schrift auf hellem Hintergrund.
    const strongBg = intensity >= 3;
    const valColor = strongBg ? '#fff' : (pnl>=0 ? 'var(--green)' : 'var(--red)');
    const numColor = !hasBets ? 'var(--t3)' : (strongBg ? '#fff' : (pnl>=0 ? 'var(--green)' : 'var(--red)'));

    html += `<div class="cal-day ${colorCls}${isToday?' today':''}${isSel?' today':''}"
      ${hasBets?`onclick="calSelectDay(${day})"`:''} style="${hasBets?'':'cursor:default;'}${isSel?'outline:2px solid var(--blue);outline-offset:-2px;':''}">
      <div class="cal-day-num" style="color:${numColor}">${day}</div>
      ${hasBets?`<div class="cal-day-val" style="color:${valColor}">${dispVal}</div>`:''}
    </div>`;
  }

  document.getElementById('cal-grid').innerHTML = html;

  // Month summary
  const settled = Object.values(dayMap).flat().filter(b=>b.status==='won'||b.status==='lost');
  const won = settled.filter(b=>b.status==='won');
  const totalStake = Object.values(dayMap).flat().reduce((s,b)=>s+(+b.stake),0);
  const wr = settled.length ? (won.length/settled.length*100).toFixed(0)+'%' : '–';
  document.getElementById('cal-sum').innerHTML = `
    <div class="cal-sum-pill"><span class="cal-sum-lbl">Wetten</span><span>${Object.values(dayMap).flat().length}</span></div>
    <div class="cal-sum-pill"><span class="cal-sum-lbl">Einsatz</span><span>${fmtAbs(totalStake)}</span></div>
    <div class="cal-sum-pill"><span class="cal-sum-lbl">P&L</span><span style="color:${monthPnl>=0?'var(--green)':'var(--red)'}">${fmtPnL(monthPnl)}</span></div>
    <div class="cal-sum-pill"><span class="cal-sum-lbl">Trefferquote</span><span>${wr}</span></div>
  `;

  // If day selected, show bets
  if (calSelectedDay) showDayBets(calSelectedDay, dayMap[calSelectedDay]||[]);
  else {
    document.getElementById('cal-bet-list').innerHTML = '<div class="empty"><div class="empty-ico">📅</div>Tag anklicken für Details</div>';
  }
}

function calSelectDay(day) {
  calSelectedDay = calSelectedDay===day ? null : day;
  renderKalender();
}

function showDayBets(day, bets) {
  const dateStr = calYear+'-'+String(calMonth+1).padStart(2,'0')+'-'+String(day).padStart(2,'0');
  const el = document.getElementById('cal-bet-list');
  if (!bets.length) {
    el.innerHTML='<div class="empty"><div class="empty-ico">🔍</div>Keine Wetten an diesem Tag</div>';
    return;
  }
  let pnl=0; bets.forEach(b=>{ pnl+=myPnLForBet(b); });
  el.innerHTML = `
    <div style="padding:12px 18px 8px;display:flex;justify-content:space-between;align-items:center;border-bottom:0.5px solid var(--sep2);">
      <span style="font-size:12px;font-weight:600;color:var(--t2);">${dateStr}</span>
      <span style="font-size:13px;font-weight:700;color:${pnl>=0?'var(--green)':'var(--red)'};">${fmtPnL(pnl)}</span>
    </div>
    ${bets.map(b=>betHTML(b,true)).join('')}`;
}

// ============================================================
//  CHARTS
// ============================================================
const CHART_OPTS = {
  responsive:true, maintainAspectRatio:false,
  plugins:{legend:{display:false}},
  scales:{
    x:{ticks:{color:'#9898a8',font:{size:10},maxRotation:0},grid:{color:'rgba(128,128,128,0.07)'}},
    y:{ticks:{color:'#9898a8',font:{size:10},callback:v=>v.toFixed(0)+' €'},grid:{color:'rgba(128,128,128,0.07)'}}
  }
};

function mkChart(id,type,labels,data,colors,lineColor) {
  if (charts[id]) charts[id].destroy();
  const ctx = document.getElementById(id).getContext('2d');
  if (type==='line') {
    charts[id]=new Chart(ctx,{type,data:{labels,datasets:[{data,borderColor:lineColor,backgroundColor:lineColor+'18',fill:true,tension:0.38,pointRadius:data.length<40?3:0,pointBackgroundColor:lineColor}]},options:CHART_OPTS});
  } else {
    charts[id]=new Chart(ctx,{type,data:{labels,datasets:[{data,backgroundColor:colors,borderRadius:6,borderSkipped:false}]},options:CHART_OPTS});
  }
}

// ============================================================
//  DASHBOARD
// ============================================================
function renderDash() {
  updateMetrics();
  const _mine = myBets();
  const sorted=[..._mine].filter(b=>b.status!=='open'&&b.status!=='void').sort((a,b)=>a.date.localeCompare(b.date));
  let run=0; const lbls=[],dat=[];
  sorted.forEach(b=>{run+=myPnLForBet(b);lbls.push(b.date.slice(5));dat.push(+run.toFixed(2));});
  if(!lbls.length){lbls.push('Start');dat.push(0);}
  mkChart('c-bankroll','line',lbls,dat,[],(dat[dat.length-1]||0)>=0?'#22c55e':'#f87171');

  const months={};
  _mine.filter(b=>b.status!=='open'&&b.status!=='void').forEach(b=>{
    const m=b.date.slice(0,7); months[m]=(months[m]||0)+myPnLForBet(b);
  });
  const mlbls=Object.keys(months).sort();
  const mdat=mlbls.map(m=>+months[m].toFixed(2));
  mkChart('c-months','bar',mlbls.length?mlbls:['–'],mdat.length?mdat:[0],mdat.map(v=>v>=0?'#22c55e':'#f87171'),null);

  const r=_mine.slice(0,8);
  document.getElementById('dash-list').innerHTML=r.length?r.map(b=>betHTML(b,false)).join(''):'<div class="empty"><div class="empty-ico">📋</div>Noch keine Wetten</div>';
}

// ============================================================
//  SPIELE
// ============================================================
// ============================================================
//  SPIELE — Live-API (TheOddsAPI) mit Demo-Fallback
// ============================================================
// Internes Format pro Game:
//   {id, source, sport, league, home, away, kickoff (Date|null),
//    time (display), odds: {home, draw|null, away}}
let _fixtures = [];          // letzte geladene Liste
let _fixturesStatus = '';    // Anzeige-Status

function fmtKickoff(iso) {
  // Heute -> "HH:MM", sonst -> "DD.MM HH:MM"
  if (!iso) return '–';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '–';
  const today = new Date();
  const same = d.getFullYear()===today.getFullYear() && d.getMonth()===today.getMonth() && d.getDate()===today.getDate();
  const hh = String(d.getHours()).padStart(2,'0');
  const mm = String(d.getMinutes()).padStart(2,'0');
  if (same) return hh+':'+mm;
  return String(d.getDate()).padStart(2,'0')+'.'+String(d.getMonth()+1).padStart(2,'0')+' '+hh+':'+mm;
}

function normalizeApiFixture(ev) {
  return {
    id:      'api_' + ev.id,
    source:  'api',
    sport:   'Fußball',         // bisher nur Soccer in FIXTURES_SPORTS
    league:  ev.league || '',
    home:    ev.home,
    away:    ev.away,
    kickoff: ev.kickoff,
    time:    fmtKickoff(ev.kickoff),
    odds:    {
      home: ev.odds && ev.odds.home != null ? +ev.odds.home : null,
      draw: ev.odds && ev.odds.draw != null ? +ev.odds.draw : null,
      away: ev.odds && ev.odds.away != null ? +ev.odds.away : null,
    },
  };
}

function normalizeDemoGame(g) {
  return {
    id:      'demo_' + g.id,
    source:  'demo',
    sport:   g.sport,
    league:  g.league,
    home:    g.home,
    away:    g.away,
    kickoff: null,
    time:    g.live ? 'LIVE' : g.time,
    odds:    { home: +g.h, draw: g.d != null ? +g.d : null, away: +g.a },
    live:    !!g.live,
  };
}

async function loadFixtures(force) {
  const url = '?a=fixtures' + (force ? '&refresh=1' : '') + '&_t=' + Date.now();
  try {
    const r = await fetch(url, {credentials:'same-origin', cache:'no-store', headers:{'Cache-Control':'no-store'}});
    if (!r.ok) return null;
    return await r.json();
  } catch (e) { return null; }
}

async function renderSpiele() {
  const list = document.getElementById('games-list');
  const stat = document.getElementById('fix-status');
  list.innerHTML = '<div class="empty">Lade Spiele …</div>';
  stat.textContent = '…';

  const data = await loadFixtures(false);
  let items = [];
  let banner = '';

  if (data && data.configured && Array.isArray(data.events) && data.events.length) {
    items = data.events.map(normalizeApiFixture);
    const ago = Math.max(0, Math.floor((Date.now()/1000 - data.fetched_at)/60));
    stat.textContent = items.length + ' Events · vor ' + ago + ' Min geladen';
    if (data.errors && data.errors.length) {
      banner = '<div class="empty" style="color:var(--amber);">Hinweis: ' + data.errors.join(' / ') + '</div>';
    }
  } else if (data && !data.configured) {
    items = DEMO_GAMES.map(normalizeDemoGame);
    stat.textContent = 'Demo (kein API-Key in config.php)';
    banner = '<div class="empty" style="color:var(--t3);">Setze <code>THEODDSAPI_KEY</code> in <code>config.php</code> für echte Daten.</div>';
  } else {
    items = DEMO_GAMES.map(normalizeDemoGame);
    stat.textContent = 'Demo (API nicht erreichbar)';
    banner = '<div class="empty" style="color:var(--amber);">API-Antwort ungültig — Demo-Daten geladen.</div>';
  }

  _fixtures = items;
  _fixturesStatus = stat.textContent;

  // Sport-Chips dynamisch aus den geladenen Daten
  const sports = ['all', ...new Set(items.map(g=>g.sport))];
  document.getElementById('sport-chips').innerHTML = sports.map(s =>
    `<button class="chip ${activeSport===s?'on':''}" onclick="setSport('${s}')">${s==='all'?'Alle':s}</button>`
  ).join('');

  const filtered = activeSport==='all' ? items : items.filter(g=>g.sport===activeSport);

  if (!filtered.length) {
    list.innerHTML = banner || '<div class="empty">Keine Spiele.</div>';
    return;
  }

  list.innerHTML = banner + filtered.map(g => {
    const oh = g.odds.home != null ? g.odds.home.toFixed(2) : '–';
    const od = g.odds.draw != null ? g.odds.draw.toFixed(2) : null;
    const oa = g.odds.away != null ? g.odds.away.toFixed(2) : '–';
    const liveDot = g.live ? `<span class="ldot"></span><div style="font-size:10px;font-weight:600;color:var(--red);">LIVE</div>` : `<div>${g.time}</div>`;
    return `
      <div class="game-row">
        <div class="game-time">${liveDot}</div>
        <div class="game-teams">
          <div class="game-name">${g.home} – ${g.away}</div>
          <div class="game-league">${g.league} · ${EMOJI[g.sport]||'🎯'} ${g.sport}</div>
        </div>
        <div class="odds-grp">
          <button class="odds-btn" onclick="prefill('${g.id}',1)">1 ${oh}</button>
          ${od!=null?`<button class="odds-btn" onclick="prefill('${g.id}',0)">X ${od}</button>`:''}
          <button class="odds-btn" onclick="prefill('${g.id}',2)">2 ${oa}</button>
        </div>
      </div>`;
  }).join('');
}

function setSport(s){ activeSport = s; renderSpiele(); }

async function refreshFixtures() {
  toast('Aktualisiere …');
  await loadFixtures(true);  // server-seitig Cache invalidieren
  await renderSpiele();
}

function prefill(id, outcome) {
  const g = _fixtures.find(x => x.id === id);
  if (!g) return;
  let desc = g.home + ' – ' + g.away;
  let odds = g.odds.home;
  if (outcome === 0)      { desc += ' (X)';          odds = g.odds.draw; }
  else if (outcome === 2) { desc += ' (' + g.away + ')'; odds = g.odds.away; }
  else                    { desc += ' (' + g.home + ')'; }
  if (odds == null) { toast('Keine Quote verfügbar'); return; }

  document.getElementById('f-desc').value   = desc;
  document.getElementById('f-odds').value   = odds.toFixed(2);
  document.getElementById('f-league').value = g.league || '';
  const sel = document.getElementById('f-sport');
  for (const opt of sel.options) {
    if (opt.text.startsWith(g.sport) || opt.value === g.sport) { sel.value = opt.value; break; }
  }
  go('add');
  liveCalc();
  setTimeout(() => document.getElementById('f-stake').focus(), 150);
}

// ============================================================
//  LIVE CALC — TAX FIX
//  Im Formular: Nutzer gibt z.B. "5" ein → /100 = 0.05
// ============================================================
function liveCalc() {
  const stake = +document.getElementById('f-stake').value;
  const odds  = +document.getElementById('f-odds').value;
  const box   = document.getElementById('cbox');
  if (stake>0 && odds>=1) {
    const gross  = stake * odds;
    const profit = gross - stake;
    box.classList.add('show');
    document.getElementById('cbox-content').innerHTML=`
      <div class="crow"><span class="clbl">Auszahlung</span><span class="cval">${fmtAbs(gross)}</span></div>
      <div class="crow"><span class="clbl">Gewinn</span><span class="cval cg">+${fmtAbs(profit)}</span></div>`;
  } else {
    box.classList.remove('show');
  }
}

// ============================================================
//  SAVE BET
//  tax_rate wird als Dezimal gespeichert: 5 % → 0.05
// ============================================================
// ============================================================
//  SHARED BETS — Form UI
// ============================================================
let _USERS_CACHE = null;
async function getKnownUsers() {
  if (_USERS_CACHE) return _USERS_CACHE;
  try {
    const r = await fetch('?a=users&_t=' + Date.now(), {credentials:'same-origin', cache:'no-store', headers:{'Cache-Control':'no-store'}});
    if (!r.ok) return _USERS_CACHE = [];
    const d = await r.json();
    return _USERS_CACHE = d.users || [];
  } catch (e) { return _USERS_CACHE = []; }
}

async function toggleSharedForm() {
  const on  = document.getElementById('f-shared').checked;
  const box = document.getElementById('f-shared-box');
  const stakeHint = document.getElementById('f-stake-hint');
  const stakeInp  = document.getElementById('f-stake');
  if (on) {
    const users = await getKnownUsers();
    if (users.length < 2) {
      document.getElementById('f-shared').checked = false;
      toast('Mindestens 2 Nutzer noetig fuer geteilte Wetten');
      return;
    }
    const me = activeUser;
    const cont = document.getElementById('f-participants');
    cont.innerHTML = users.map(u => `
      <div class="shared-row">
        <div class="shared-name">
          <span class="shared-dot" style="background:${u.color};"></span>
          <span>${u.display}${u.name===me?' (du)':''}</span>
        </div>
        <input class="fi shared-stake" type="number" data-user="${u.name}" placeholder="0.00" step="0.01" min="0" value="${u.name===me?'10':'0'}" oninput="recalcShared()">
        <div class="shared-pct" data-pct-for="${u.name}">0%</div>
      </div>
    `).join('');
    box.style.display = 'block';
    stakeHint.style.display = 'inline';
    stakeInp.readOnly = true;
    recalcShared();
  } else {
    box.style.display = 'none';
    stakeHint.style.display = 'none';
    stakeInp.readOnly = false;
  }
}

function getSharedParticipants() {
  // Liefert {Felix: 30, Paul: 12, ...} aus den eingegebenen Stakes (>0).
  const out = {};
  document.querySelectorAll('#f-participants .shared-stake').forEach(inp => {
    const name = inp.dataset.user;
    const val  = parseFloat(String(inp.value).replace(',', '.')) || 0;
    if (val > 0) out[name] = +val.toFixed(2);
  });
  return out;
}

function recalcShared() {
  const parts = getSharedParticipants();
  let total = 0;
  Object.values(parts).forEach(v => total += v);
  document.getElementById('f-shared-total').textContent = total.toFixed(2) + ' €';
  document.getElementById('f-stake').value = total > 0 ? total.toFixed(2) : '';
  document.querySelectorAll('[data-pct-for]').forEach(el => {
    const u   = el.getAttribute('data-pct-for');
    const v   = parts[u] || 0;
    const pct = total > 0 ? (v / total * 100) : 0;
    el.textContent = pct.toFixed(0) + '%';
  });
  const myShare = parts[activeUser] || 0;
  const myPct   = total > 0 ? (myShare / total * 100) : 0;
  document.getElementById('f-shared-mine').textContent = myPct.toFixed(0) + '%';
  liveCalc();
}

async function saveBet() {
  const desc  = document.getElementById('f-desc').value.trim();
  const stake = +document.getElementById('f-stake').value;
  const odds  = +document.getElementById('f-odds').value;
  const err   = document.getElementById('f-err');
  const isShared = document.getElementById('f-shared').checked;
  const participants = isShared ? getSharedParticipants() : null;
  if (isShared && Object.keys(participants).length < 2) {
    err.textContent = 'Mindestens 2 Nutzer mit Anteil > 0 noetig.'; return;
  }
  if (!desc||!stake||!odds||stake<=0||odds<1){err.textContent='Bitte Beschreibung, Einsatz und Quote ausfüllen.';return;}
  err.textContent='';
  const res = await api('add',{
    participants,
    date:    document.getElementById('f-date').value||new Date().toISOString().slice(0,10),
    sport:   document.getElementById('f-sport').value,
    desc, stake, odds,
    league:  document.getElementById('f-league').value,
    market:  document.getElementById('f-market').value,
    status:  document.getElementById('f-status').value,
    bookie:  document.getElementById('f-bookie').value,
    note:    document.getElementById('f-note').value,
    tax_rate: 0,
    cashout: +document.getElementById('f-cashout').value||0,
    combo_id:'',
    user:    activeUser,
  });
  if (res?.ok) {
    if (res.invited && res.invited > 0) {
      toast('✓ Wette gespeichert · ' + res.invited + ' Anfrage(n) versendet');
    } else {
      toast('✓ Wette gespeichert');
    }
    resetForm();
    await loadBets();
    go('hist');
  } else {
    const reason = (res && (res.error || res.e)) || 'Unbekannter Fehler';
    err.textContent = 'Fehler beim Speichern: ' + reason;
    toast('Save fehlgeschlagen: ' + reason);
  }
}

function resetForm() {
  ['f-desc','f-league','f-note','f-stake','f-odds','f-cashout'].forEach(id=>document.getElementById(id).value='');
  const sh = document.getElementById('f-shared');
  if (sh && sh.checked) { sh.checked = false; toggleSharedForm(); }
  const stakeInp = document.getElementById('f-stake'); if (stakeInp) stakeInp.readOnly = false;
  document.getElementById('f-status').value='open';
  document.getElementById('cbox').classList.remove('show');
  document.getElementById('f-err').textContent='';
}

// ============================================================
//  DELETE / UPDATE STATUS
// ============================================================
async function delBet(id) {
  if(!confirm('Wette wirklich löschen?')) return;
  const res=await api('del',{id});
  if(res?.ok){toast('Gelöscht');await loadBets();renderHist();}
}

async function updStatus(id,status) {
  // Legacy: nur fuer Code-Pfade die das noch nutzen.
  const res=await api('upd_status',{id,status});
  if(res?.ok){toast('Status aktualisiert');await loadBets();}
}

async function settleBet(id, status) {
  // Bei Cashout: nach Betrag fragen. Akzeptiert auch , als Dezimaltrenner.
  let cashoutAmt = 0;
  if (status === 'cashout') {
    const ans = prompt('Cashout-Betrag in € (was hast du tatsaechlich zurueckbekommen?):', '0');
    if (ans === null) return;
    cashoutAmt = parseFloat(String(ans).replace(',', '.'));
    if (!isFinite(cashoutAmt) || cashoutAmt < 0) {
      toast('Ungueltiger Betrag');
      return;
    }
  } else if (status !== 'won' && status !== 'lost') {
    toast('Status nicht erlaubt');
    return;
  }
  // upd schreibt status + cashout in einem Schritt.
  const res = await api('upd', { id, status, cashout: cashoutAmt });
  if (res?.ok) { toast('✓ Status: ' + ({won:'Gewonnen',lost:'Verloren',cashout:'Cashout'}[status])); await loadBets(); }
}

// ============================================================
//  HISTORY
// ============================================================
function renderHist() {
  const fs  = document.getElementById('flt-sport').value;
  const fst = document.getElementById('flt-status').value;
  const fb  = document.getElementById('flt-bookie').value;
  const fu  = document.getElementById('flt-user').value;
  const srt = document.getElementById('flt-sort').value;
  let arr=allBets.filter(b=>userInvolvedInBet(b,activeUser)&&(!fs||b.sport===fs)&&(!fst||b.status===fst)&&(!fb||b.bookie===fb)&&(!fu||b.user===fu));
  arr.sort((a,b)=>{
    if(srt==='dd') return b.date.localeCompare(a.date);
    if(srt==='da') return a.date.localeCompare(b.date);
    if(srt==='sd') return +b.stake-+a.stake;
    if(srt==='od') return +b.odds-+a.odds;
    if(srt==='pd') return myPnLForBet(b)-myPnLForBet(a);
    return 0;
  });
  const el=document.getElementById('hist-list');
  el.innerHTML=arr.length
    ?`<div class="card">${arr.map(b=>betHTML(b,true)).join('')}</div>`
    :'<div class="card"><div class="empty"><div class="empty-ico">🔍</div>Keine Wetten gefunden</div></div>';
}

// ============================================================
//  STATS
// ============================================================
async function renderTeamStats() {
  const bestEl  = document.getElementById('tb-team-best');
  const worstEl = document.getElementById('tb-team-worst');
  if (!bestEl || !worstEl) return;
  try {
    const r = await fetch('?a=team_stats&_t=' + Date.now(), {credentials:'same-origin', cache:'no-store'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const all = (d.stats || []).filter(s => s.cnt > 0);

    if (!all.length) {
      const empty = '<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:14px;">Noch keine Kombi-Wetten mit Team-Tag.</td></tr>';
      bestEl.innerHTML  = empty;
      worstEl.innerHTML = empty;
      return;
    }

    // Beste = pnl >= 0, sortiert absteigend
    // Schlechteste = pnl < 0, sortiert aufsteigend (negativste zuerst)
    const best  = all.filter(s => s.pnl >= 0).sort((a,b)=>b.pnl-a.pnl).slice(0, 10);
    const worst = all.filter(s => s.pnl <  0).sort((a,b)=>a.pnl-b.pnl).slice(0, 10);

    const row = (s) => `
      <tr>
        <td>${s.team}</td>
        <td>${s.cnt}</td>
        <td><span class="cg">${s.won}</span></td>
        <td><span class="cr">${s.lost}</span></td>
        <td class="${s.pnl>=0?'cg':'cr'}">${(s.pnl>=0?'+':'') + s.pnl.toFixed(2)} €</td>
      </tr>`;

    bestEl.innerHTML  = best.length  ? best.map(row).join('')  : '<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:14px;">Noch keine Plus-Teams.</td></tr>';
    worstEl.innerHTML = worst.length ? worst.map(row).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:14px;">Bislang keine Verlust-Teams.</td></tr>';
  } catch (e) {
    bestEl.innerHTML  = '<tr><td colspan="5" style="color:var(--red);padding:14px;text-align:center;">Fehler: '+e.message+'</td></tr>';
    worstEl.innerHTML = '';
  }
}

function renderStats() {
  const days=Array(7).fill(null).map(()=>({pnl:0,cnt:0}));
  allBets.filter(b=>b.status!=='open'&&b.status!=='void').forEach(b=>{
    const d=new Date(b.date).getDay(); days[d].pnl+=myPnLForBet(b); days[d].cnt++;
  });
  mkChart('c-weekday','bar',['So','Mo','Di','Mi','Do','Fr','Sa'],days.map(d=>+d.pnl.toFixed(2)),days.map(d=>d.pnl>=0?'#22c55e':'#f87171'),null);

  const groupBy=key=>{
    const m={};
    allBets.forEach(b=>{
      const k=b[key]||'?';
      if(!m[k]) m[k]={cnt:0,won:0,lost:0,stake:0,pnl:0,odds:[],tax:0};
      const r=m[k]; r.cnt++; r.stake+=(+b.stake); r.odds.push(+b.odds);
      if(b.status==='won'){r.won++;r.pnl+=myPnLForBet(b);r.tax+=taxedReturn(+b.stake,+b.odds,+b.tax_rate||0).tax;}
      else if(b.status==='lost'){r.lost++;r.pnl+=myPnLForBet(b);}
    });
    return m;
  };
  const pcls=v=>v>=0?'cg':'cr';
  const nodata=cols=>`<tr><td colspan="${cols}" style="padding:14px;color:var(--t3);font-size:12px;">Noch keine Daten</td></tr>`;

  const sm=groupBy('sport');
  document.getElementById('tb-sport').innerHTML=Object.keys(sm).length
    ?Object.entries(sm).map(([k,r])=>{
        const roi=r.stake>0?r.pnl/r.stake*100:0;
        const avg=r.odds.length?r.odds.reduce((a,b)=>a+b,0)/r.odds.length:0;
        const pct=r.cnt>0?r.won/r.cnt*100:0;
        return `<tr><td>${EMOJI[k]||'🎯'} ${k}</td><td>${r.cnt}</td>
          <td>${r.won}G/${r.lost}V <span class="pbar"><span class="pfill" style="width:${pct.toFixed(0)}%;background:${pct>=50?'var(--green)':'var(--red)'}"></span></span> ${pct.toFixed(0)}%</td>
          <td>${avg.toFixed(2)}x</td><td>${fmtAbs(r.stake)}</td>
          <td class="${pcls(r.pnl)}">${fmtPnL(r.pnl)}</td><td class="${pcls(roi)}">${roi.toFixed(1)}%</td></tr>`;
      }).join('')
    :nodata(7);

  const bm=groupBy('bookie');
  document.getElementById('tb-bookie').innerHTML=Object.keys(bm).length
    ?Object.entries(bm).map(([k,r])=>{
        const roi=r.stake>0?r.pnl/r.stake*100:0;
        return `<tr><td>${k}</td><td>${r.cnt}</td><td>${fmtAbs(r.stake)}</td>
          <td class="${pcls(r.pnl)}">${fmtPnL(r.pnl)}</td><td class="${pcls(roi)}">${roi.toFixed(1)}%</td></tr>`;
      }).join('')
    :nodata(5);

  const um=groupBy('user');
  document.getElementById('tb-user').innerHTML=Object.keys(um).length
    ?Object.entries(um).map(([k,r])=>{
        const roi=r.stake>0?r.pnl/r.stake*100:0;
        return `<tr><td>${k}</td><td>${r.cnt}</td><td>${fmtAbs(r.stake)}</td>
          <td class="${pcls(r.pnl)}">${fmtPnL(r.pnl)}</td><td class="${pcls(roi)}">${roi.toFixed(1)}%</td></tr>`;
      }).join('')
    :nodata(5);

  const ranges=[
    {l:'1.01–1.50',min:1.01,max:1.50},{l:'1.51–2.00',min:1.51,max:2.00},
    {l:'2.01–3.00',min:2.01,max:3.00},{l:'3.01–5.00',min:3.01,max:5.00},
    {l:'5.01+',min:5.01,max:9999},
  ];
  document.getElementById('tb-odds').innerHTML=ranges.map(rg=>{
    const bets=allBets.filter(b=>{const o=+b.odds;return o>=rg.min&&o<=rg.max&&(b.status==='won'||b.status==='lost');});
    if(!bets.length) return `<tr><td>${rg.l}</td><td colspan="4" style="color:var(--t3)">–</td></tr>`;
    const won=bets.filter(b=>b.status==='won');
    const pnl=bets.reduce((s,b)=>s+myPnLForBet(b),0);
    const stake=bets.reduce((s,b)=>s+(+b.stake),0);
    const rate=won.length/bets.length*100;
    const roi=stake>0?pnl/stake*100:0;
    return `<tr><td>${rg.l}</td><td>${bets.length}</td>
      <td><span class="pbar"><span class="pfill" style="width:${rate.toFixed(0)}%;background:${rate>=50?'var(--green)':'var(--red)'}"></span></span> ${rate.toFixed(0)}%</td>
      <td class="${pcls(pnl)}">${fmtPnL(pnl)}</td><td class="${pcls(roi)}">${roi.toFixed(1)}%</td></tr>`;
  }).join('');
  renderTeamStats();
}

// ============================================================
//  KOMBI
// ============================================================
function initKombi() { if(!comboLegs.length) comboLegs=[{desc:'',odds:'',team:''}]; renderLegs(); }
function addLeg()    { comboLegs.push({desc:'',odds:'',team:''}); renderLegs(); }
function removeLeg(i){ comboLegs.splice(i,1); if(!comboLegs.length) comboLegs=[{desc:'',odds:'',team:''}]; renderLegs(); }

// Lazy-loaded Team-Liste
let _TEAMS = null;
async function getTeams() {
  if (_TEAMS) return _TEAMS;
  try {
    const r = await fetch('?a=teams&_t='+Date.now(), {credentials:'same-origin', cache:'no-store'});
    if (!r.ok) return _TEAMS = [];
    const d = await r.json();
    return _TEAMS = (d.teams || []);
  } catch(e) { return _TEAMS = []; }
}

function renderLegs() {
  // Async-Render: Teams nachladen, dann mit datalist
  getTeams().then(teams => {
    const dlOptions = teams.map(t => `<option value="${(t.name||'').replace(/"/g,'&quot;')}">${t.league||''}</option>`).join('');
    document.getElementById('kombi-legs').innerHTML = `
      <datalist id="teams-dl">${dlOptions}</datalist>
      ` + comboLegs.map((l,i) => `
        <div class="combo-leg">
          <div class="leg-num">${i+1}</div>
          <input class="fi" list="teams-dl" style="flex:0 0 160px;" placeholder="Team (optional)" value="${(l.team||'').replace(/"/g,'&quot;')}" oninput="comboLegs[${i}].team=this.value">
          <input class="fi" style="flex:1;" placeholder="Tipp / Beschreibung" value="${(l.desc||'').replace(/"/g,'&quot;')}" oninput="comboLegs[${i}].desc=this.value">
          <input class="fi" style="width:88px;" type="number" placeholder="Quote" value="${l.odds}" step="0.01" min="1" oninput="comboLegs[${i}].odds=this.value;calcKombi()">
          <button class="delbtn" onclick="removeLeg(${i})">×</button>
        </div>`).join('');
  });
  const valid=comboLegs.filter(l=>+l.odds>=1);
  const res=document.getElementById('kombi-result');
  if(valid.length>=2){res.style.display='block';calcKombi();}
  else res.style.display='none';
}

function calcKombi() {
  const stake=+document.getElementById('k-stake').value;
  const sel=document.getElementById('k-bookie');
  const tax=+(sel.options[sel.selectedIndex].dataset.tax||'0')/100;
  const valid=comboLegs.filter(l=>+l.odds>=1);
  const combo=valid.reduce((a,l)=>a*(+l.odds),1);
  const box=document.getElementById('k-calc');
  if(!stake||stake<=0){
    box.innerHTML=`<div class="crow"><span class="clbl">Gesamt-Quote</span><span class="cval">${combo.toFixed(2)}x</span></div>`;
    return;
  }
  const gross = stake * combo;
  const profit = gross - stake;
  box.innerHTML=`
    <div class="crow"><span class="clbl">Gesamt-Quote (${valid.length} Tipps)</span><span class="cval">${combo.toFixed(2)}x</span></div>
    <div class="crow"><span class="clbl">Einsatz</span><span class="cval">${fmtAbs(stake)}</span></div>
    <div class="crow"><span class="clbl">Auszahlung</span><span class="cval cg">${fmtAbs(gross)}</span></div>
    <div class="crow"><span class="clbl">Gewinn</span><span class="cval cg">+${fmtAbs(profit)}</span></div>`;
}

async function saveKombi() {
  const stake=+document.getElementById('k-stake').value;
  const sel=document.getElementById('k-bookie');
  const tax=+(sel.options[sel.selectedIndex].dataset.tax||'0')/100;
  const valid=comboLegs.filter(l=>+l.odds>=1&&l.desc.trim());
  if(!valid.length||!stake||stake<=0){toast('Bitte alle Felder ausfüllen');return;}
  const combo=valid.reduce((a,l)=>a*(+l.odds),1);
  const cid='combo_'+Date.now();
  // Legs-Payload mit Teams mitschicken — Server speichert in kombi_legs.csv.
  const legsPayload = valid.map(l => ({
    team: (l.team || '').trim(),
    desc: (l.desc || '').trim(),
    odds: +l.odds || 0,
  }));
  const res=await api('add',{
    date:new Date().toISOString().slice(0,10),sport:'Fußball',
    desc:valid.map(l=>l.desc).join(' | '),league:'',market:'Kombiwette',
    stake,odds:combo,status:'open',bookie:sel.value,
    note:valid.length+'-fach Kombi',user:activeUser,
    tax_rate:tax,cashout:0,combo_id:cid,
    legs: legsPayload,
  });
  if (res?.ok) {
    toast('✓ Kombiwette gespeichert');
    comboLegs = [{desc:'',odds:'',team:''}];
    renderLegs();
    await loadBets();
    go('hist');
  } else {
    const reason = (res && (res.error || res.e)) || 'Unbekannter Fehler';
    toast('Kombi-Save fehlgeschlagen: ' + reason);
  }
}

// ============================================================
//  TOOLS
// ============================================================
function renderTools(){renderStreak();}

function calcKelly() {
  const bank=+document.getElementById('kl-bank').value;
  const prob=+document.getElementById('kl-prob').value/100;
  const odds=+document.getElementById('kl-odds').value;
  const res=document.getElementById('kl-res');
  if(!bank||!prob||!odds||odds<1||prob<=0||prob>=1){res.style.display='none';return;}
  const k=((odds-1)*prob-(1-prob))/(odds-1);
  if(k<=0){res.style.display='none';toast('Kein Value — Kelly = 0');return;}
  res.style.display='block';
  document.getElementById('kl-full').textContent=fmtAbs(k*bank);
  document.getElementById('kl-half').textContent=fmtAbs(k*bank*0.5);
  document.getElementById('kl-qtr').textContent=fmtAbs(k*bank*0.25);
}

function calcTax() {
  const stake=+document.getElementById('tx-stake').value;
  const odds=+document.getElementById('tx-odds').value;
  const res=document.getElementById('tx-res');
  if(!stake||!odds||stake<=0||odds<1){res.style.display='none';return;}
  const r=taxedReturn(stake,odds,0.05);
  res.style.display='block';
  res.innerHTML=`
    <div class="txrow"><span style="color:var(--t2)">Einsatz</span><span>${fmtAbs(stake)}</span></div>
    <div class="txrow"><span style="color:var(--t2)">Brutto-Auszahlung</span><span>${fmtAbs(r.gross)}</span></div>
    <div class="txrow"><span style="color:var(--t2)">Brutto-Gewinn</span><span>+${fmtAbs(r.profit)}</span></div>
    <div class="txrow"><span style="color:var(--t2)">Tax auf Gewinn (5%)</span><span style="color:var(--amber)">− ${fmtAbs(r.tax)}</span></div>
    <div class="txrow ttl"><span>Netto-Auszahlung</span><span style="color:var(--green)">+${fmtAbs(r.net)}</span></div>`;
}

function calcConv() {
  const o=+document.getElementById('cv-dec').value;
  if(!o||o<1) return;
  document.getElementById('cv-prob').value=(1/o*100).toFixed(1)+'%';
  document.getElementById('cv-us').value=o>=2?'+'+Math.round((o-1)*100):'-'+Math.round(100/(o-1));
  const num=Math.round((o-1)*100),den=100,g=(a,b)=>b?g(b,a%b):a,gc=g(num,den);
  document.getElementById('cv-frac').value=(num/gc)+'/'+(den/gc);
}

function calcVB() {
  const odds=+document.getElementById('vb-odds').value;
  const prob=+document.getElementById('vb-prob').value/100;
  const res=document.getElementById('vb-res');
  if(!odds||!prob||odds<1||prob<=0){res.style.display='none';return;}
  const ev=prob*(odds-1)-(1-prob);
  const fair=1/prob;
  const edge=(odds/fair-1)*100;
  const isV=ev>0;
  res.style.display='block';
  res.style.background=isV?'var(--green-s)':'var(--red-s)';
  res.style.border=`0.5px solid ${isV?'color-mix(in srgb,var(--green) 25%,transparent)':'color-mix(in srgb,var(--red) 25%,transparent)'}`;
  res.innerHTML=`
    <div style="font-weight:700;font-size:14px;margin-bottom:10px;color:${isV?'var(--green)':'var(--red)'};">${isV?'✓ Value Bet!':'✗ Kein Value'}</div>
    <div class="crow"><span class="clbl">Angebotene Quote</span><span class="cval">${odds.toFixed(2)}</span></div>
    <div class="crow"><span class="clbl">Faire Quote</span><span class="cval">${fair.toFixed(2)}</span></div>
    <div class="crow"><span class="clbl">Edge</span><span class="cval ${isV?'cg':'cr'}">${edge>=0?'+':''}${edge.toFixed(1)}%</span></div>
    <div class="crow" style="border-top:0.5px solid var(--sep);padding-top:8px;margin-top:4px;font-weight:600;font-size:14px;">
      <span class="clbl">Expected Value</span><span class="cval ${isV?'cg':'cr'}">${ev>=0?'+':''}${(ev*100).toFixed(1)}%</span>
    </div>`;
}

function renderStreak() {
  const settled=[...allBets].filter(b=>b.status==='won'||b.status==='lost').sort((a,b)=>a.date.localeCompare(b.date));
  const el=document.getElementById('streak-box');
  if(!settled.length){el.innerHTML='<div class="empty">Noch keine abgeschlossenen Wetten</div>';return;}
  let maxW=0,maxL=0,curW=0,curL=0,lastStatus='';
  settled.forEach(b=>{
    if(b.status==='won'){curW++;curL=0;maxW=Math.max(maxW,curW);}
    else{curL++;curW=0;maxL=Math.max(maxL,curL);}
    lastStatus=b.status;
  });
  const last6=settled.slice(-6).map(b=>
    `<span style="display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:50%;background:${b.status==='won'?'var(--green-s)':'var(--red-s)'};color:${b.status==='won'?'var(--green)':'var(--red)'};font-weight:700;font-size:11px;">${b.status==='won'?'W':'L'}</span>`
  ).join('');
  el.innerHTML=`
    <div class="streak-grid">
      <div class="streak-box"><div class="streak-lbl">Max. Siegesserie</div><div class="streak-num cg">${maxW}</div></div>
      <div class="streak-box"><div class="streak-lbl">Max. Niederlagenserie</div><div class="streak-num cr">${maxL}</div></div>
      <div class="streak-box"><div class="streak-lbl">Aktuelle Serie</div><div class="streak-num ${lastStatus==='won'?'cg':'cr'}">${lastStatus==='won'?curW:curL}${lastStatus==='won'?'W':'L'}</div></div>
    </div>
    <div style="font-size:11px;color:var(--t2);margin-bottom:8px;">Letzte 6 Wetten</div>
    <div style="display:flex;gap:6px;">${last6}</div>`;
}

// ============================================================
//  RENDER ALL
// ============================================================
function renderAll() {
  updateMetrics();
  const active=document.querySelector('.tab.on');
  const tabs=document.querySelectorAll('.tab');
  const idx=Array.from(tabs).indexOf(active);
  if(idx>=0){
    const id=TAB_IDS[idx];
    if(id==='kalender') renderKalender();
    if(id==='dash')     renderDash();
    if(id==='hist')     renderHist();
    if(id==='stats')    renderStats();
    if(id==='tools')    renderTools();
    if(id==='wm')       renderWMMetrics();
    if(id==='casino')   renderCasinoMetrics();
  } else { renderKalender(); }
}

// ============================================================
//  INVITES MODAL — Wett-Anfragen annehmen / ablehnen
// ============================================================
function refreshInviteBadge() {
  const c   = (allInvites || []).length;
  const el  = document.getElementById('invite-count');
  if (!el) return;
  if (c > 0) { el.textContent = String(c); el.hidden = false; }
  else       { el.hidden = true; }
}

function openInvitesModal() {
  renderInvitesList();
  document.getElementById('inv-modal').hidden = false;
  document.body.style.overflow = 'hidden';
}
function closeInvitesModal() {
  document.getElementById('inv-modal').hidden = true;
  document.body.style.overflow = '';
}

function fmtInviteAge(iso) {
  const t = new Date(iso).getTime();
  if (!t) return '';
  const diff = Math.max(0, Math.floor((Date.now()-t)/1000));
  if (diff < 60)    return 'gerade eben';
  if (diff < 3600)  return Math.floor(diff/60) + ' Min';
  if (diff < 86400) return Math.floor(diff/3600) + ' Std';
  return Math.floor(diff/86400) + ' Tg';
}

function renderInvitesList() {
  const list = document.getElementById('inv-list');
  if (!allInvites || !allInvites.length) {
    list.innerHTML = '<div class="inv-empty">Keine offenen Wett-Anfragen.</div>';
    return;
  }
  list.innerHTML = allInvites.map(inv => {
    // Bet Lookup, falls schon in allBets (sollte sein, da daten.csv geladen wurde)
    const bet = (allBets||[]).find(b => b.id === inv.bet_id);
    const desc = bet ? bet.desc : '(Bet ' + inv.bet_id + ')';
    const meta = bet ? (bet.date + ' · ' + bet.sport + ' · ' + bet.bookie + ' · Quote ' + (+bet.odds).toFixed(2)) : '';
    const safeId = inv.id.replace(/'/g, "\\'");
    return `
      <div class="inv-row">
        <div class="inv-row-head">
          <div>
            <div class="inv-row-title">${desc}</div>
            <div class="inv-row-meta">Von <strong>${inv.from_user}</strong> · ${fmtInviteAge(inv.created_at)} her</div>
            ${meta ? `<div class="inv-row-meta">${meta}</div>` : ''}
          </div>
          <div class="inv-row-stake">${(+inv.stake).toFixed(2)} €</div>
        </div>
        <div class="inv-row-actions">
          <button class="btn btn-p btn-sm"  onclick="acceptInvite('${safeId}')">Annehmen</button>
          <button class="btn btn-d btn-sm"  onclick="declineInvite('${safeId}')">Ablehnen</button>
        </div>
      </div>`;
  }).join('');
}

async function acceptInvite(invId) {
  const res = await api('invite_accept', { invite_id: invId });
  if (res?.ok) {
    toast('✓ Anfrage angenommen — Anteil verbucht');
    await loadBets();
    renderInvitesList();
    if (!allInvites.length) closeInvitesModal();
  } else {
    toast('Fehler: ' + ((res && (res.error||res.e)) || 'unbekannt'));
  }
}

async function declineInvite(invId) {
  if (!confirm('Anfrage wirklich ablehnen?')) return;
  const res = await api('invite_decline', { invite_id: invId });
  if (res?.ok) {
    toast('Anfrage abgelehnt');
    await loadBets();
    renderInvitesList();
    if (!allInvites.length) closeInvitesModal();
  } else {
    toast('Fehler: ' + ((res && (res.error||res.e)) || 'unbekannt'));
  }
}

// ESC schliesst auch den Invites-Modal
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !document.getElementById('inv-modal').hidden) closeInvitesModal();
});

// ============================================================
//  ACCOUNT / SECURITY MODAL
// ============================================================

function openAccountModal(){
  acctTab('pw');
  resetAcctForms();
  document.getElementById('acct-modal').hidden = false;
  document.body.style.overflow = 'hidden';
  setTimeout(()=>document.getElementById('pw-cur').focus(), 50);
}
function closeAccountModal(){
  document.getElementById('acct-modal').hidden = true;
  document.body.style.overflow = '';
  resetAcctForms();
}
function acctTab(name){
  document.querySelectorAll('.acct-tab').forEach(b=>b.classList.toggle('on', b.dataset.tab===name));
  document.getElementById('pw-form').hidden  = (name !== 'pw');
  document.getElementById('new-form').hidden = (name !== 'new');
}
function resetAcctForms(){
  ['pw-cur','pw-new','pw-cnf','new-un','new-pw','new-cnf'].forEach(id=>{ const e=document.getElementById(id); if(e) e.value=''; });
  ['pw-msg','new-msg'].forEach(id=>{ const e=document.getElementById(id); if(e){ e.hidden=true; e.textContent=''; e.className='acct-msg'; } });
}
function showAcctMsg(id, ok, text){
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className   = 'acct-msg ' + (ok ? 'ok' : 'err');
  el.hidden      = false;
}
async function postJson(url, payload){
  const r = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload),
    credentials: 'same-origin',
  });
  let data = null;
  try { data = await r.json(); } catch(_){}
  return { status: r.status, data };
}

async function submitPwChange(ev){
  ev.preventDefault();
  const cur = document.getElementById('pw-cur').value;
  const nw  = document.getElementById('pw-new').value;
  const cnf = document.getElementById('pw-cnf').value;
  if (nw !== cnf) { showAcctMsg('pw-msg', false, 'Die beiden neuen Passwörter stimmen nicht überein.'); return false; }
  const { status, data } = await postJson('?a=change_pw', {
    _csrf: CSRF_TOKEN, current: cur, new: nw, confirm: cnf,
  });
  if (data && data.ok) {
    if (data.csrf) CSRF_TOKEN = data.csrf;  // neuer Token nach Rotation
    showAcctMsg('pw-msg', true, 'Passwort geändert.');
    document.getElementById('pw-cur').value = '';
    document.getElementById('pw-new').value = '';
    document.getElementById('pw-cnf').value = '';
    setTimeout(closeAccountModal, 1200);
  } else {
    showAcctMsg('pw-msg', false, (data && data.error) || 'Fehler ('+status+').');
  }
  return false;
}

async function submitNewAccount(ev){
  ev.preventDefault();
  const un  = document.getElementById('new-un').value.trim();
  const pw  = document.getElementById('new-pw').value;
  const cnf = document.getElementById('new-cnf').value;
  const col = document.getElementById('new-color').value;
  if (pw !== cnf) { showAcctMsg('new-msg', false, 'Die beiden Passwörter stimmen nicht überein.'); return false; }
  const { status, data } = await postJson('?a=create_acct', {
    _csrf: CSRF_TOKEN, username: un, password: pw, confirm: cnf, color: col,
  });
  if (data && data.ok) {
    showAcctMsg('new-msg', true, 'Account "'+ (data.username||un) +'" angelegt. Lade Seite neu …');
    document.getElementById('new-un').value  = '';
    document.getElementById('new-pw').value  = '';
    document.getElementById('new-cnf').value = '';
    setTimeout(()=>location.reload(), 1100);  // damit der neue Nutzer in Dropdowns auftaucht
  } else {
    showAcctMsg('new-msg', false, (data && data.error) || 'Fehler ('+status+').');
  }
  return false;
}

// ESC schließt Modal
document.addEventListener('keydown', (e)=>{
  if (e.key === 'Escape' && !document.getElementById('acct-modal').hidden) closeAccountModal();
});

// ============================================================
//  WM 2026 — FIFA Weltmeisterschaft
// ============================================================

// --- Gruppen-Definition ---
const WM_GROUPS = {
  A:{name:'Gruppe A',teams:['USA','Panama','Bolivien','Albanien']},
  B:{name:'Gruppe B',teams:['Mexiko','Jamaika','Venezuela','Neuseeland']},
  C:{name:'Gruppe C',teams:['Kanada','Honduras','Uruguay','Marokko']},
  D:{name:'Gruppe D',teams:['Brasilien','Ecuador','Japan','Algerien']},
  E:{name:'Gruppe E',teams:['Argentinien','Chile','Kolumbien','Senegal']},
  F:{name:'Gruppe F',teams:['Deutschland','Österreich','Schweiz','Südkorea']},
  G:{name:'Gruppe G',teams:['Frankreich','Belgien','Dänemark','Elfenbeinküste']},
  H:{name:'Gruppe H',teams:['Spanien','Portugal','Niederlande','Ägypten']},
  I:{name:'Gruppe I',teams:['England','Schottland','Türkei','Iran']},
  J:{name:'Gruppe J',teams:['Italien','Serbien','Tschechien','Australien']},
  K:{name:'Gruppe K',teams:['Kroatien','Ukraine','Ungarn','Nigeria']},
  L:{name:'Gruppe L',teams:['Polen','Rumänien','Georgien','Indonesien']},
};

// Spielplan generieren: 6 Spiele pro Gruppe (MD1: 0-1/2-3, MD2: 0-2/1-3, MD3: 0-3/1-2)
const WM_SCHEDULE = (function(){
  const sched = [];
  const gKeys = Object.keys(WM_GROUPS);
  gKeys.forEach((gk, gi) => {
    const t = WM_GROUPS[gk].teams;
    const md1 = 11 + Math.floor(gi/2);
    const md2 = 17 + Math.floor(gi/2);
    const md3 = 24 + Math.floor(gi/3);
    const dpad = d => String(d).padStart(2,'0');
    const dates = [
      `2026-06-${dpad(md1)}`,`2026-06-${dpad(md1)}`,
      `2026-06-${dpad(md2)}`,`2026-06-${dpad(md2)}`,
      `2026-06-${dpad(md3)}`,`2026-06-${dpad(md3)}`,
    ];
    const times = ['18:00','21:00','18:00','21:00','18:00','21:00'];
    const pairs = [[0,1],[2,3],[0,2],[1,3],[0,3],[1,2]];
    const mds   = [1,1,2,2,3,3];
    pairs.forEach(([a,b], idx) => {
      sched.push({id:`g${gk}${idx+1}`,group:gk,date:dates[idx],time:times[idx],md:mds[idx],t1:t[a],t2:t[b]});
    });
  });
  return sched;
})();

// K.o.-Runden Template
const WM_KO = [
  {id:'r32', label:'Runde der letzten 32', date:'28. Juni – 2. Juli', matches:[
    {id:'r32_1', p1:'1A',p2:'2B'},{id:'r32_2', p1:'1B',p2:'2A'},
    {id:'r32_3', p1:'1C',p2:'2D'},{id:'r32_4', p1:'1D',p2:'2C'},
    {id:'r32_5', p1:'1E',p2:'2F'},{id:'r32_6', p1:'1F',p2:'2E'},
    {id:'r32_7', p1:'1G',p2:'2H'},{id:'r32_8', p1:'1H',p2:'2G'},
    {id:'r32_9', p1:'1I',p2:'2J'},{id:'r32_10',p1:'1J',p2:'2I'},
    {id:'r32_11',p1:'1K',p2:'2L'},{id:'r32_12',p1:'1L',p2:'2K'},
    {id:'r32_13',p1:'3.Gr.(TBD)',p2:'3.Gr.(TBD)'},{id:'r32_14',p1:'3.Gr.(TBD)',p2:'3.Gr.(TBD)'},
    {id:'r32_15',p1:'3.Gr.(TBD)',p2:'3.Gr.(TBD)'},{id:'r32_16',p1:'3.Gr.(TBD)',p2:'3.Gr.(TBD)'},
  ]},
  {id:'r16', label:'Achtelfinale', date:'3.–6. Juli', matches:[
    {id:'r16_1',p1:'W:r32_1', p2:'W:r32_2'},{id:'r16_2',p1:'W:r32_3', p2:'W:r32_4'},
    {id:'r16_3',p1:'W:r32_5', p2:'W:r32_6'},{id:'r16_4',p1:'W:r32_7', p2:'W:r32_8'},
    {id:'r16_5',p1:'W:r32_9', p2:'W:r32_10'},{id:'r16_6',p1:'W:r32_11',p2:'W:r32_12'},
    {id:'r16_7',p1:'W:r32_13',p2:'W:r32_14'},{id:'r16_8',p1:'W:r32_15',p2:'W:r32_16'},
  ]},
  {id:'qf', label:'Viertelfinale', date:'9.–10. Juli', matches:[
    {id:'qf_1',p1:'W:r16_1',p2:'W:r16_2'},{id:'qf_2',p1:'W:r16_3',p2:'W:r16_4'},
    {id:'qf_3',p1:'W:r16_5',p2:'W:r16_6'},{id:'qf_4',p1:'W:r16_7',p2:'W:r16_8'},
  ]},
  {id:'sf', label:'Halbfinale', date:'14.–15. Juli', matches:[
    {id:'sf_1',p1:'W:qf_1',p2:'W:qf_2'},{id:'sf_2',p1:'W:qf_3',p2:'W:qf_4'},
  ]},
  {id:'tp', label:'Spiel um Platz 3', date:'18. Juli', matches:[
    {id:'tp_1',p1:'L:sf_1',p2:'L:sf_2'},
  ]},
  {id:'final', label:'🏆 Finale', date:'19. Juli', matches:[
    {id:'final_1',p1:'W:sf_1',p2:'W:sf_2'},
  ]},
];

let wmData = {};
let wmActiveTab = 'groups';
let wmLoaded = false;

// --- Slot-Auflösung ---
function wmResolveSlot(slot) {
  if (!slot) return '?';
  // Gruppenposition z.B. "1A", "2B", "3C"
  const gpM = slot.match(/^([123])([A-L])$/);
  if (gpM) {
    const pos = parseInt(gpM[1]) - 1;
    const gk  = gpM[2];
    const tbl = wmCalcTable(gk);
    return tbl[pos] ? tbl[pos].team : slot;
  }
  // Drittplatzierte (noch nicht aufgelöst)
  if (slot.startsWith('3.Gr')) return '3. Platz (TBD)';
  // K.o.-Sieger "W:r32_1"
  const wM = slot.match(/^W:(.+)$/);
  if (wM) {
    const mid = wM[1];
    const res = wmData[mid];
    if (!res || res.score1 === null || res.score1 === undefined || res.score2 === null || res.score2 === undefined) return '?';
    const km = wmFindKoMatch(mid);
    if (!km) return '?';
    const s1 = parseInt(res.score1), s2 = parseInt(res.score2);
    const t1 = wmResolveSlot(km.p1), t2 = wmResolveSlot(km.p2);
    if (s1 > s2) return t1;
    if (s2 > s1) return t2;
    return t1; // draw → treat as t1 (penalties assumed)
  }
  // K.o.-Verlierer "L:sf_1"
  const lM = slot.match(/^L:(.+)$/);
  if (lM) {
    const mid = lM[1];
    const res = wmData[mid];
    if (!res || res.score1 === null || res.score1 === undefined || res.score2 === null || res.score2 === undefined) return '?';
    const km = wmFindKoMatch(mid);
    if (!km) return '?';
    const s1 = parseInt(res.score1), s2 = parseInt(res.score2);
    const t1 = wmResolveSlot(km.p1), t2 = wmResolveSlot(km.p2);
    if (s1 > s2) return t2;
    if (s2 > s1) return t1;
    return t2;
  }
  return slot;
}

function wmFindKoMatch(id) {
  for (const r of WM_KO) for (const m of r.matches) if (m.id === id) return m;
  return null;
}

function wmGetWinner(matchId) {
  const res = wmData[matchId];
  if (!res || res.score1 == null || res.score2 == null) return null;
  const km = wmFindKoMatch(matchId);
  if (!km) {
    // Gruppenspiel
    const gm = WM_SCHEDULE.find(m => m.id === matchId);
    if (!gm) return null;
    const s1 = parseInt(res.score1), s2 = parseInt(res.score2);
    return s1 > s2 ? gm.t1 : (s2 > s1 ? gm.t2 : null);
  }
  return wmResolveSlot('W:' + matchId);
}

// --- Gruppentabelle berechnen ---
function wmCalcTable(gk) {
  const teams = WM_GROUPS[gk].teams;
  const tbl = {};
  teams.forEach(t => { tbl[t] = {team:t,sp:0,w:0,u:0,n:0,tore:0,gt:0,td:0,pts:0}; });
  WM_SCHEDULE.filter(m => m.group === gk).forEach(m => {
    const r = wmData[m.id];
    if (!r || r.score1 == null || r.score2 == null) return;
    const s1 = parseInt(r.score1), s2 = parseInt(r.score2);
    tbl[m.t1].sp++; tbl[m.t1].tore += s1; tbl[m.t1].gt += s2;
    tbl[m.t2].sp++; tbl[m.t2].tore += s2; tbl[m.t2].gt += s1;
    if (s1 > s2) { tbl[m.t1].w++; tbl[m.t1].pts += 3; tbl[m.t2].n++; }
    else if (s2 > s1) { tbl[m.t2].w++; tbl[m.t2].pts += 3; tbl[m.t1].n++; }
    else { tbl[m.t1].u++; tbl[m.t1].pts++; tbl[m.t2].u++; tbl[m.t2].pts++; }
  });
  Object.values(tbl).forEach(t => { t.td = t.tore - t.gt; });
  return Object.values(tbl).sort((a,b) => b.pts-a.pts || b.td-a.td || b.tore-a.tore);
}

// --- Daten laden / speichern ---
async function wmLoadData() {
  const d = await api('wm_load');
  if (d && d.ok) { wmData = d.data || {}; wmLoaded = true; }
}

async function wmSaveResult(matchId, score1, score2, stake, pnl, note) {
  const res = await api('wm_save', {
    match_id: matchId,
    score1: score1 !== '' ? score1 : null,
    score2: score2 !== '' ? score2 : null,
    stake:  stake  !== '' ? parseFloat(String(stake).replace(',','.'))  : null,
    pnl:    pnl    !== '' ? parseFloat(String(pnl).replace(',','.'))    : null,
    note:   note || '',
  });
  if (res?.ok) {
    wmData[matchId] = {score1: score1!==''?parseInt(score1):null, score2: score2!==''?parseInt(score2):null,
      stake: stake!==''?parseFloat(String(stake).replace(',','.')):null,
      pnl:   pnl!==''?parseFloat(String(pnl).replace(',','.')):null, note: note||''};
    toast('✓ Ergebnis gespeichert');
    renderWMMetrics();
    renderWMGroupsContainer();
    if (wmActiveTab === 'bracket') renderWMBracket();
    if (wmActiveTab === 'bets') renderWMBets();
  } else { toast('Fehler beim Speichern'); }
}

// --- Sub-Tab wechseln ---
function wmTab(name) {
  wmActiveTab = name;
  document.querySelectorAll('.wm-tab').forEach((b,i) => b.classList.toggle('on', ['groups','bracket','bets'][i]===name));
  document.querySelectorAll('.wm-panel').forEach(p => p.classList.remove('on'));
  document.getElementById('wm-panel-'+name).classList.add('on');
  if (name==='bracket') renderWMBracket();
  if (name==='bets')    renderWMBets();
}

// ============================================================
//  CASINO — Session-Tracking (casino.csv)
// ============================================================
let casinoSessions = [];
let casinoLoaded   = false;

function caPnl(s) { return (+s.cashout || 0) - (+s.buyin || 0); }

async function casinoLoadData() {
  const d = await api('casino_list');
  casinoSessions = (d && d.sessions) || [];
  casinoLoaded = true;
}

function caLiveCalc() {
  const bi = +document.getElementById('ca-buyin').value || 0;
  const co = +document.getElementById('ca-cashout').value || 0;
  const pnl = co - bi;
  const el = document.getElementById('ca-calc');
  el.textContent = 'Ergebnis: ' + fmtPnL(pnl);
  el.style.color = pnl > 0 ? 'var(--green)' : (pnl < 0 ? 'var(--red)' : 'var(--t2)');
}

async function renderCasino() {
  if (!casinoLoaded) await casinoLoadData();
  if (!document.getElementById('ca-date').value) {
    document.getElementById('ca-date').value = new Date().toISOString().slice(0,10);
  }
  caLiveCalc();
  renderCasinoMetrics();
  renderCasinoList();
}

function renderCasinoMetrics() {
  const setv = (id,v,cls)=>{ const e=document.getElementById(id); if(!e) return; e.textContent=v; if(cls!==undefined) e.className='mtr-val '+cls; };
  const sub  = (id,v)=>{ const e=document.getElementById(id); if(e) e.textContent=v; };
  const n = casinoSessions.length;
  const totalPnl = casinoSessions.reduce((a,s)=>a+caPnl(s),0);
  const totalBuyin = casinoSessions.reduce((a,s)=>a+(+s.buyin||0),0);
  const wins = casinoSessions.filter(s=>caPnl(s)>0).length;
  let best = null;
  casinoSessions.forEach(s=>{ if(best===null || caPnl(s)>caPnl(best)) best=s; });

  setv('ca-m-pnl', fmtPnL(totalPnl), totalPnl>0?'cg':totalPnl<0?'cr':'cn');
  setv('ca-m-cnt', String(n), 'cn');
  sub('ca-m-wr', 'Gewinnquote: ' + (n ? Math.round(wins/n*100) : 0) + '%');
  setv('ca-m-buyin', fmtAbs(totalBuyin), 'cn');
  setv('ca-m-best', best ? fmtPnL(caPnl(best)) : '–', best && caPnl(best)>0?'cg':best && caPnl(best)<0?'cr':'cn');
  sub('ca-m-best-s', best ? (best.game + (best.provider? ' · '+best.provider:'')) : '–');
}

function renderCasinoList() {
  const box = document.getElementById('casino-list');
  if (!casinoSessions.length) {
    box.innerHTML = '<div class="empty"><div class="empty-ico">🎰</div>Noch keine Casino-Sessions</div>';
    return;
  }
  box.innerHTML = casinoSessions.map(s=>{
    const pnl = caPnl(s);
    const cls = pnl>0?'cg':(pnl<0?'cr':'cn');
    const ico = pnl>=0?'🟢':'🔴';
    return `<div class="li">
      <div class="li-ico" style="background:var(--surface2);">${ico}</div>
      <div class="li-body">
        <div class="li-title">${s.game}${s.provider? ' · '+s.provider:''}</div>
        <div class="li-sub">${s.date} · Buy-In ${fmtAbs(+s.buyin)} → Auszahlung ${fmtAbs(+s.cashout)}${s.note? ' · '+s.note:''}</div>
      </div>
      <div class="li-right">
        <div class="li-val ${cls}">${fmtPnL(pnl)}</div>
        <button class="delbtn" onclick="casinoDel('${s.id}')">×</button>
      </div>
    </div>`;
  }).join('');
}

async function casinoAdd() {
  const buyin   = +document.getElementById('ca-buyin').value || 0;
  const cashout = +document.getElementById('ca-cashout').value || 0;
  const payload = {
    date:     document.getElementById('ca-date').value || new Date().toISOString().slice(0,10),
    game:     document.getElementById('ca-game').value,
    provider: document.getElementById('ca-provider').value.trim(),
    buyin, cashout,
    note:     document.getElementById('ca-note').value.trim(),
  };
  const r = await api('casino_add', payload);
  if (r && r.ok) {
    toast('Session gespeichert');
    document.getElementById('ca-buyin').value = '';
    document.getElementById('ca-cashout').value = '';
    document.getElementById('ca-provider').value = '';
    document.getElementById('ca-note').value = '';
    caLiveCalc();
    await casinoLoadData();
    renderCasinoMetrics();
    renderCasinoList();
  }
}

async function casinoDel(id) {
  if (!confirm('Diese Session löschen?')) return;
  const r = await api('casino_del', { id });
  if (r && r.ok) {
    await casinoLoadData();
    renderCasinoMetrics();
    renderCasinoList();
  }
}

// --- Haupt-Render ---
async function renderWM() {
  if (!wmLoaded) await wmLoadData();
  renderWMMetrics();
  renderWMGroupsContainer();
  if (wmActiveTab==='bracket') renderWMBracket();
  if (wmActiveTab==='bets')    renderWMBets();
}

// --- Metriken ---
function renderWMMetrics() {
  // Weltmeister ermitteln
  const res = wmData['final_1'];
  const champ = (res && res.score1 != null && res.score2 != null) ? wmResolveSlot('W:final_1') : null;
  const champEl = document.getElementById('wm-m-champ');
  if (champEl) champEl.textContent = champ && champ!=='?' ? '🏆 '+champ : '–';

  // Spielstatistik
  const played = WM_SCHEDULE.filter(m => wmData[m.id] && wmData[m.id].score1 != null).length;
  const open   = WM_SCHEDULE.length - played;
  const playedEl = document.getElementById('wm-m-played');
  const openEl   = document.getElementById('wm-m-open');
  if (playedEl) playedEl.textContent = played;
  if (openEl)   openEl.textContent   = 'offen: ' + open;

  // WM Wetten: alle Wetten mit league='WM 2026'
  const wmBets = allBets.filter(b => (b.league||'').toUpperCase().includes('WM'));
  const settled = wmBets.filter(b => b.status==='won'||b.status==='lost'||b.status==='cashout');
  const wonB    = settled.filter(b => b.status==='won');
  const pnl     = wmBets.reduce((s,b) => s + myPnLForBet(b), 0);
  const wr      = settled.length ? wonB.length/settled.length*100 : 0;
  const pnlEl   = document.getElementById('wm-m-pnl');
  const wrEl    = document.getElementById('wm-m-wr');
  const wrSEl   = document.getElementById('wm-m-wr-s');
  if (pnlEl) { pnlEl.textContent = fmtPnL(pnl); pnlEl.className='mtr-val '+(pnl>=0?'cg':'cr'); }
  if (wrEl)  { wrEl.textContent  = wr.toFixed(0)+'%'; wrEl.className='mtr-val cb'; }
  if (wrSEl) wrSEl.textContent   = wonB.length+'/'+settled.length+' WM-Wetten';

  // Auch WM-Wetten aus wm_data.json berücksichtigen (direkte Spielwetten)
  const wmGameStake = Object.values(wmData).reduce((s,d) => s+(d.stake||0), 0);
  const wmGamePnl   = Object.values(wmData).reduce((s,d) => s+(d.pnl||0), 0);
  if (wmBets.length === 0 && wmGameStake > 0) {
    if (pnlEl) { pnlEl.textContent = fmtPnL(wmGamePnl); pnlEl.className='mtr-val '+(wmGamePnl>=0?'cg':'cr'); }
  }
}

// --- Gruppen ---
function renderWMGroupsContainer() {
  const cont = document.getElementById('wm-groups-container');
  if (!cont) return;
  const gKeys = Object.keys(WM_GROUPS);
  let html = '<div class="wm-group-grid">';
  gKeys.forEach(gk => { html += renderGroupCard(gk); });
  html += '</div>';
  cont.innerHTML = html;
}

function renderGroupCard(gk) {
  const g    = WM_GROUPS[gk];
  const tbl  = wmCalcTable(gk);
  const games = WM_SCHEDULE.filter(m => m.group === gk);
  const played = games.filter(m => wmData[m.id] && wmData[m.id].score1 != null).length;

  // Tabelle
  let tblHTML = `<table class="wm-tbl"><thead><tr>
    <th style="text-align:left;">Team</th>
    <th title="Spiele">Sp</th><th title="Siege">S</th><th title="Unentschieden">U</th><th title="Niederlagen">N</th>
    <th title="Tore">T</th><th title="Tordifferenz">TD</th><th title="Punkte">Pts</th>
  </tr></thead><tbody>`;
  const posCls = ['wm-p1','wm-p2','wm-p3','wm-p4'];
  tbl.forEach((r, i) => {
    tblHTML += `<tr>
      <td><span class="wm-pos ${posCls[i]}">${i+1}</span>${r.team}</td>
      <td>${r.sp}</td><td>${r.w}</td><td>${r.u}</td><td>${r.n}</td>
      <td>${r.tore}:${r.gt}</td><td class="${r.td>0?'cg':r.td<0?'cr':'cn'}">${r.td>0?'+':''}${r.td}</td>
      <td class="wm-pts">${r.pts}</td>
    </tr>`;
  });
  tblHTML += '</tbody></table>';

  // Spiele
  let mds = [1,2,3];
  let gamesHTML = '<div class="wm-games">';
  mds.forEach(md => {
    const mdGames = games.filter(m => m.md === md);
    gamesHTML += `<div class="wm-md-label">Spieltag ${md}</div>`;
    mdGames.forEach(m => {
      const res = wmData[m.id] || {};
      const s1  = res.score1 != null ? res.score1 : '';
      const s2  = res.score2 != null ? res.score2 : '';
      const done = res.score1 != null && res.score2 != null;
      const w1 = done && parseInt(res.score1) > parseInt(res.score2);
      const w2 = done && parseInt(res.score2) > parseInt(res.score1);
      gamesHTML += `<div class="wm-game" id="wg-${m.id}">
        <div class="wm-game-date">${m.date.slice(5).replace('-','.')}</div>
        <div class="wm-game-home" style="${w1?'color:var(--green)':w2?'color:var(--t3)':''}">${m.t1}</div>
        <div class="wm-score-wrap">
          <input class="wm-sinp" type="number" min="0" max="99" id="s1-${m.id}" value="${s1}" placeholder="–" oninput="wmScoreInput('${m.id}')">
          <span class="wm-ssep">:</span>
          <input class="wm-sinp" type="number" min="0" max="99" id="s2-${m.id}" value="${s2}" placeholder="–" oninput="wmScoreInput('${m.id}')">
          <button class="wm-sbtn" onclick="wmSaveGame('${m.id}')">✓</button>
          <button class="wm-bbtn" onclick="wmBetOnGame('${m.id}')">€</button>
        </div>
        <div class="wm-game-away" style="${w2?'color:var(--green)':w1?'color:var(--t3)':''}">${m.t2}</div>
      </div>`;
    });
  });
  gamesHTML += '</div>';

  return `<div class="wm-group-card">
    <div class="wm-group-header">
      <span class="wm-group-name">${g.name}</span>
      <span class="wm-group-md">${played}/6 gespielt</span>
    </div>
    <div>${tblHTML}</div>
    ${gamesHTML}
  </div>`;
}

function wmScoreInput(mid) {
  // Live-Feedback: Highlight wenn beide Felder ausgefüllt
  const s1 = document.getElementById('s1-'+mid);
  const s2 = document.getElementById('s2-'+mid);
  if (s1 && s2 && s1.value !== '' && s2.value !== '') {
    s1.style.borderColor = '#16a34a'; s2.style.borderColor = '#16a34a';
  } else {
    if (s1) s1.style.borderColor = ''; if (s2) s2.style.borderColor = '';
  }
}

function wmSaveGame(mid) {
  const s1 = document.getElementById('s1-'+mid)?.value ?? '';
  const s2 = document.getElementById('s2-'+mid)?.value ?? '';
  wmSaveResult(mid, s1, s2, '', '', '');
}

function wmBetOnGame(mid) {
  const gm = WM_SCHEDULE.find(m => m.id === mid) || wmFindKoMatch(mid);
  if (!gm) return;
  document.getElementById('f-desc').value   = (gm.t1 || '') + ' – ' + (gm.t2 || '') + ', ' + gm.id;
  document.getElementById('f-league').value = 'WM 2026';
  document.getElementById('f-sport').value  = 'Fußball';
  go('add');
  setTimeout(() => document.getElementById('f-stake').focus(), 150);
}

// --- Turnierbaum ---
function renderWMBracket() {
  const champBox = document.getElementById('wm-champion-box');
  const bracketEl = document.getElementById('wm-bracket-container');
  if (!bracketEl) return;

  // Weltmeister?
  const res = wmData['final_1'];
  const champ = (res && res.score1 != null && res.score2 != null) ? wmResolveSlot('W:final_1') : null;
  if (champ && champ !== '?') {
    champBox.innerHTML = `<div class="wm-champion">
      <div class="wm-champ-lbl">🏆 Weltmeister 2026</div>
      <div class="wm-champ-name">${champ}</div>
      <div class="wm-champ-sub">FIFA WM 2026 – USA / Mexiko / Kanada</div>
    </div>`;
  } else { champBox.innerHTML = ''; }

  let html = '';
  WM_KO.forEach(round => {
    html += `<div class="wm-br-col">
      <div class="wm-br-col-hdr">${round.label}<br><span style="font-size:9px;font-weight:400;">${round.date}</span></div>
      <div class="wm-br-matches">`;
    round.matches.forEach(m => {
      const t1 = wmResolveSlot(m.p1);
      const t2 = wmResolveSlot(m.p2);
      const r  = wmData[m.id] || {};
      const s1 = r.score1 != null ? r.score1 : '';
      const s2 = r.score2 != null ? r.score2 : '';
      const done = r.score1 != null && r.score2 != null;
      const w1 = done && parseInt(r.score1) > parseInt(r.score2);
      const w2 = done && parseInt(r.score2) > parseInt(r.score1);
      const tbd1 = (t1==='?'||t1.includes('TBD'));
      const tbd2 = (t2==='?'||t2.includes('TBD'));
      const isFinal = round.id === 'final';
      html += `<div class="wm-ko${isFinal?' wm-ko-final':''}" onclick="wmKoClick('${m.id}')">
        <div class="wm-ko-t${w1?' win':''}${tbd1?' tbd':''}">
          <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;">${t1}</span>
          <span class="wm-ko-sc">${s1}</span>
        </div>
        <div class="wm-ko-t${w2?' win':''}${tbd2?' tbd':''}">
          <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;">${t2}</span>
          <span class="wm-ko-sc">${s2}</span>
        </div>
      </div>`;
    });
    html += '</div></div>';
  });
  bracketEl.innerHTML = html;
}

function wmKoClick(mid) {
  const km = wmFindKoMatch(mid);
  if (!km) return;
  const t1 = wmResolveSlot(km.p1);
  const t2 = wmResolveSlot(km.p2);
  if (t1==='?' || t2==='?') { toast('Teams noch nicht ermittelt'); return; }
  const r  = wmData[mid] || {};
  const s1 = prompt(`${t1} – Tore:`, r.score1 != null ? r.score1 : '');
  if (s1 === null) return;
  const s2 = prompt(`${t2} – Tore:`, r.score2 != null ? r.score2 : '');
  if (s2 === null) return;
  wmSaveResult(mid, s1, s2, '', '', '');
  renderWMBracket();
}

// --- WM-Wetten Statistik ---
function renderWMBets() {
  const cont = document.getElementById('wm-bets-container');
  if (!cont) return;

  // WM-Wetten aus daten.csv (league contains 'WM')
  const wmBets  = allBets.filter(b => (b.league||'').toUpperCase().includes('WM'));
  const settled = wmBets.filter(b => b.status==='won'||b.status==='lost'||b.status==='cashout');
  const wonB    = settled.filter(b => b.status==='won');
  const pnl     = wmBets.reduce((s,b) => s+myPnLForBet(b),0);
  const stake   = wmBets.reduce((s,b) => s+(+b.stake),0);
  const wr      = settled.length ? wonB.length/settled.length*100 : 0;
  const roi     = stake>0 ? pnl/stake*100 : 0;

  // WM-Spielwetten aus wm_data.json
  const gWagers = Object.entries(wmData).filter(([,d]) => d.stake && d.stake > 0);
  const gStake  = gWagers.reduce((s,[,d]) => s+(d.stake||0), 0);
  const gPnl    = gWagers.reduce((s,[,d]) => s+(d.pnl||0), 0);

  cont.innerHTML = `
    <div class="sh">WM 2026 – Gesamt-Statistik</div>
    <div class="mtr-grid" style="margin-bottom:18px;">
      <div class="mtr"><div class="mtr-lbl">WM Gesamtgewinn</div><div class="mtr-val ${pnl>=0?'cg':'cr'}">${fmtPnL(pnl)}</div><div class="mtr-sub">nach Tax</div></div>
      <div class="mtr"><div class="mtr-lbl">WM Einsatz</div><div class="mtr-val cn">${fmtAbs(stake)}</div><div class="mtr-sub">${wmBets.length} Wetten</div></div>
      <div class="mtr"><div class="mtr-lbl">Trefferquote WM</div><div class="mtr-val cb">${wr.toFixed(0)}%</div><div class="mtr-sub">${wonB.length}/${settled.length} abg.</div></div>
      <div class="mtr"><div class="mtr-lbl">ROI WM</div><div class="mtr-val ${roi>=0?'cg':'cr'}">${roi.toFixed(1)}%</div><div class="mtr-sub">auf Einsatz</div></div>
    </div>
    ${gStake>0?`<div class="sh">WM-Spielwetten (direkt erfasst)</div>
    <div class="card card-pad" style="margin-bottom:18px;">
      <div class="crow"><span class="clbl">Gesamt-Einsatz</span><span class="cval">${fmtAbs(gStake)}</span></div>
      <div class="crow"><span class="clbl">Reingewinn</span><span class="cval ${gPnl>=0?'cg':'cr'}">${fmtPnL(gPnl)}</span></div>
      <div class="crow" style="border-top:0.5px solid var(--sep);padding-top:8px;margin-top:4px;"><span class="clbl">Wetten mit Einsatz</span><span class="cval">${gWagers.length}</span></div>
    </div>`:''}
    <div class="sh">WM-Wetten (aus daten.csv)</div>
    <div class="card">${wmBets.length
      ? wmBets.map(b=>betHTML(b,true)).join('')
      : '<div class="empty"><div class="empty-ico">💰</div>Noch keine WM-Wetten.<br><small style="color:var(--t3)">Beim Hinzufügen "WM 2026" als Liga eintragen oder den € Button bei einem Spiel nutzen.</small></div>'
    }</div>`;
}

// ============================================================
//  INIT
// ============================================================
document.getElementById('f-date').value=new Date().toISOString().slice(0,10);
loadBets();
setInterval(loadBets,30000);
</script>

<?php endif; ?>
</body>
</html>
