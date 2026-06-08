<?php
// ============================================================
//  WETT-TRACKER PRO — KONFIGURATION (VORLAGE)
//  Kopiere diese Datei nach config.php und trage deine Werte ein.
//  config.php ist in .gitignore und wird NICHT committet.
// ============================================================

// ---------- BENUTZER (SEED) ----------
// Dieser Block wird NUR beim ersten Start verwendet.
// Beim ersten Aufruf schreibt auth.php diese Liste in users.json,
// danach ist users.json die Quelle der Wahrheit (Passwort ändern,
// neue Accounts anlegen ändern users.json, NICHT diese Datei).
// Passwörter sind mit bcrypt (cost=12) gehasht.
// Neuen Hash erzeugen via CLI:
//   php -r "echo password_hash('NEUES_PW', PASSWORD_BCRYPT, ['cost'=>12]).PHP_EOL;"
// und den ausgegebenen $2y$12$… String unten in 'hash' eintragen.
// Niemals Klartext-Passwörter in dieser Datei kommentieren!
define('USERS', [
    'Felix' => [
        'hash'    => 'BCRYPT_HASH_HIER_EINTRAGEN',
        'display' => 'Felix',
        'color'   => '#7f6af8',
    ],
    'Paul' => [
        'hash'    => 'BCRYPT_HASH_HIER_EINTRAGEN',
        'display' => 'Paul',
        'color'   => '#0a84ff',
    ],
]);

// ---------- SESSION ----------
define('SESSION_NAME',     'wtp_sess');
define('SESSION_LIFETIME',  8 * 3600);   // 8 Stunden

// ---------- BRUTE-FORCE SCHUTZ ----------
define('MAX_ATTEMPTS',  5);
define('LOCKOUT_SECS',  900);            // 15 Minuten

// ---------- DATEIPFADE ----------
define('CSV_FILE',     __DIR__ . '/daten.csv');
define('LOCKOUT_FILE', __DIR__ . '/lockouts.json');
define('LOG_FILE',     __DIR__ . '/access.log');
define('USERS_FILE',   __DIR__ . '/users.json');
define('SHARES_FILE',  __DIR__ . '/shares.csv');
define('INVITES_FILE', __DIR__ . '/bet_invites.csv');
define('TEAMS_FILE',   __DIR__ . '/teams.json');
define('KOMBI_LEGS_FILE', __DIR__ . '/kombi_legs.csv');
define('WM_DATA_FILE',   __DIR__ . '/wm_data.json');
define('CASINO_FILE',    __DIR__ . '/casino.csv');

// ---------- PASSWORT-RICHTLINIE ----------
define('PW_MIN_LEN', 12);   // bcrypt schluckt max. 72 Bytes — Range 12..72
define('PW_MAX_LEN', 72);
define('UN_MIN_LEN', 3);
define('UN_MAX_LEN', 32);

// ---------- SHARES SPALTEN (Issue #1+#4) ----------
define('SHARES_HEADER', ['bet_id', 'user', 'stake']);
define('INVITES_HEADER', ['id', 'bet_id', 'from_user', 'to_user', 'stake', 'status', 'created_at']);
define('KOMBI_LEGS_HEADER', ['bet_id', 'leg_idx', 'team', 'desc', 'odds']);
define('CASINO_HEADER', ['id', 'date', 'game', 'provider', 'buyin', 'cashout', 'note', 'user', 'bonus']);

// ---------- CSV SPALTEN ----------
define('CSV_HEADER', [
    'id','date','sport','desc','league','market',
    'stake','odds','status','bookie','note','user',
    'tax_rate','cashout','combo_id'
]);


// ---------- THEODDSAPI (Issue #2: Game API) ----------
// Free Tier auf https://the-odds-api.com (500 Requests/Monat).
// Hier deinen API-Key eintragen. Leer lassen = Feature disabled.
define('THEODDSAPI_KEY', '');

define('FIXTURES_CACHE_FILE', __DIR__ . '/fixtures_cache.json');
define('FIXTURES_CACHE_TTL',  1800);   // 30 Minuten
define('FIXTURES_TIMEOUT_S',  8);      // Request-Timeout in Sekunden

// Welche Sportarten importiert werden. TheOddsAPI nutzt sport_keys.
define('FIXTURES_SPORTS', [
    'soccer_epl',                    // English Premier League
    'soccer_germany_bundesliga',     // Bundesliga
    'soccer_uefa_champs_league',     // Champions League
    'soccer_spain_la_liga',          // La Liga
    'soccer_italy_serie_a',          // Serie A
]);

// ---------- BWIN DEFAULT TAX -----
