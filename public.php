<?php
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';");

require_once __DIR__ . '/config.php';

// ── CSV lesen (vereinfacht, ohne Auth-Abhängigkeit) ──────────────
function publicCsvRead(): array {
    if (!file_exists(CSV_FILE)) return [];
    $fp = @fopen(CSV_FILE, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    $header = fgetcsv($fp, 0, ',', '"');
    if ($header && isset($header[0]))
        $header[0] = preg_replace('/^\xEF\xBB\xBF/u', '', $header[0]);
    $rows = [];
    $cols = count(CSV_HEADER);
    while (($row = fgetcsv($fp, 0, ',', '"')) !== false) {
        if ($row === null || (count($row) === 1 && ($row[0] === null || $row[0] === ''))) continue;
        if (count($row) < 8) continue;
        $padded = array_pad($row, $cols, '');
        $rows[] = array_combine(CSV_HEADER, array_slice($padded, 0, $cols));
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return array_reverse($rows);
}

function publicUsersRead(): array {
    if (!file_exists(USERS_FILE)) return [];
    $raw = @file_get_contents(USERS_FILE);
    if (!$raw) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function calcPnLPublic(array $b): float {
    $stake   = (float)$b['stake'];
    $odds    = (float)$b['odds'];
    $tax     = (float)$b['tax_rate'];
    $cashout = (float)$b['cashout'];
    if ($b['status'] === 'void')    return 0;
    if ($b['status'] === 'cashout') return round($cashout - $stake, 2);
    if ($b['status'] === 'won') {
        $profit = max(0, $stake * $odds - $stake);
        $net    = $stake + ($profit - $profit * $tax);
        return round($net - $stake, 2);
    }
    if ($b['status'] === 'lost') return -$stake;
    return 0;
}

// ── API-Endpoint ─────────────────────────────────────────────────
if (($_GET['a'] ?? '') === 'feed') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');

    $all   = publicCsvRead();
    $users = publicUsersRead();

    $feed = array_map(function($b) use ($users) {
        $color = $users[$b['user']]['color'] ?? '#6366f1';
        return [
            'id'      => $b['id'],
            'date'    => $b['date'],
            'sport'   => $b['sport'],
            'desc'    => $b['desc'],
            'league'  => $b['league'],
            'market'  => $b['market'],
            'odds'    => (float)$b['odds'],
            'stake'   => (float)$b['stake'],
            'status'  => $b['status'],
            'user'    => $b['user'],
            'note'    => $b['note'],
            'color'   => $color,
            'pnl'     => calcPnLPublic($b),
        ];
    }, $all);

    // Statistiken
    $settled = array_filter($all, fn($b) => in_array($b['status'], ['won','lost','cashout']));
    $won     = array_filter($settled, fn($b) => $b['status'] === 'won');
    $open    = array_filter($all, fn($b) => $b['status'] === 'open');
    $totalPnl = array_reduce($all, fn($s, $b) => $s + calcPnLPublic($b), 0);
    $winRate  = count($settled) > 0 ? round(count($won) / count($settled) * 100, 1) : 0;

    echo json_encode([
        'bets' => $feed,
        'stats' => [
            'total'    => count($all),
            'open'     => count($open),
            'won'      => count($won),
            'lost'     => count(array_filter($settled, fn($b) => $b['status'] === 'lost')),
            'winRate'  => $winRate,
            'totalPnl' => round($totalPnl, 2),
        ],
        'ts' => time(),
    ]);
    exit;
}
?>
<!DOCTYPE html>
<html lang="de" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>WettPro · Live Feed</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg:#f0f2f5; --surface:#fff; --surface2:#f5f6f8; --surface3:#eaecf0;
  --t1:#0d0d14; --t2:#5a5a72; --t3:#9898b0;
  --sep:rgba(0,0,0,0.07); --sep2:rgba(0,0,0,0.04);
  --blue:#2563eb; --blue-s:rgba(37,99,235,0.10);
  --green:#16a34a; --green-s:rgba(22,163,74,0.10);
  --red:#dc2626; --red-s:rgba(220,38,38,0.10);
  --amber:#d97706; --amber-s:rgba(217,119,6,0.10);
  --purple:#7c3aed; --purple-s:rgba(124,58,237,0.10);
  --sh0:0 1px 3px rgba(0,0,0,0.06);
  --sh1:0 2px 8px rgba(0,0,0,0.08),0 0 0 0.5px rgba(0,0,0,0.04);
  --sh2:0 8px 32px rgba(0,0,0,0.10),0 0 0 0.5px rgba(0,0,0,0.04);
  --r-sm:8px; --r-md:12px; --r-lg:16px; --r-xl:20px; --r-full:9999px;
  --font:'Inter',-apple-system,system-ui,sans-serif;
}
[data-theme="dark"] {
  --bg:#08080c; --surface:#111116; --surface2:#18181e; --surface3:#222229;
  --t1:#f5f5fa; --t2:#9898b4; --t3:#4a4a62;
  --sep:rgba(255,255,255,0.07); --sep2:rgba(255,255,255,0.03);
  --blue:#3b82f6; --blue-s:rgba(59,130,246,0.14);
  --green:#22c55e; --green-s:rgba(34,197,94,0.14);
  --red:#f87171; --red-s:rgba(248,113,113,0.14);
  --amber:#fbbf24; --amber-s:rgba(251,191,36,0.14);
  --purple:#a78bfa; --purple-s:rgba(167,139,250,0.14);
  --sh0:0 1px 3px rgba(0,0,0,0.40);
  --sh1:0 2px 8px rgba(0,0,0,0.50),0 0 0 0.5px rgba(255,255,255,0.05);
  --sh2:0 8px 32px rgba(0,0,0,0.60),0 0 0 0.5px rgba(255,255,255,0.04);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;}
body{font-family:var(--font);background:var(--bg);color:var(--t1);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased;min-height:100vh;transition:background 0.25s,color 0.25s;}

/* ── TOPBAR ── */
.topbar{position:sticky;top:0;z-index:100;background:color-mix(in srgb,var(--surface) 88%,transparent);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border-bottom:0.5px solid var(--sep);}
.topbar-inner{max-width:1100px;margin:0 auto;padding:0 20px;height:58px;display:flex;align-items:center;gap:12px;}
.brand{font-size:18px;font-weight:800;letter-spacing:-0.5px;color:var(--t1);text-decoration:none;flex-shrink:0;}
.brand span{color:var(--blue);}
.live-pill{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;background:var(--red-s);border:0.5px solid color-mix(in srgb,var(--red) 25%,transparent);border-radius:var(--r-full);font-size:11px;font-weight:700;color:var(--red);letter-spacing:0.3px;}
.ldot{width:6px;height:6px;border-radius:50%;background:var(--red);animation:pulse 1.2s ease-in-out infinite;flex-shrink:0;}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.4;transform:scale(0.8);}}
.tb-spacer{flex:1;}
.ib{width:34px;height:34px;border-radius:var(--r-sm);border:0.5px solid var(--sep);background:var(--surface);color:var(--t2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;transition:all 0.15s;flex-shrink:0;text-decoration:none;}
.ib:hover{background:var(--surface2);color:var(--t1);}
.btn-login{display:inline-flex;align-items:center;gap:6px;padding:8px 18px;background:var(--blue);color:#fff;border-radius:var(--r-md);font-family:var(--font);font-size:13px;font-weight:600;border:none;cursor:pointer;text-decoration:none;transition:all 0.15s;white-space:nowrap;}
.btn-login:hover{opacity:0.88;transform:translateY(-1px);}
.btn-login:active{transform:scale(0.97);}

/* ── HERO ── */
.hero{max-width:1100px;margin:0 auto;padding:40px 20px 28px;}
.hero-title{font-size:32px;font-weight:800;letter-spacing:-1px;color:var(--t1);margin-bottom:8px;}
.hero-title span{color:var(--blue);}
.hero-sub{font-size:15px;color:var(--t2);max-width:520px;}

/* ── STATS BAR ── */
.stats-bar{max-width:1100px;margin:0 auto;padding:0 20px 28px;display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;}
.stat-card{background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-lg);box-shadow:var(--sh0);padding:16px 18px;}
.stat-lbl{font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;}
.stat-val{font-size:22px;font-weight:800;letter-spacing:-0.5px;font-variant-numeric:tabular-nums;}
.stat-sub{font-size:11px;color:var(--t3);margin-top:3px;}
.cg{color:var(--green);} .cr{color:var(--red);} .cb{color:var(--blue);} .ca{color:var(--amber);} .cp{color:var(--purple);}

/* ── MAIN LAYOUT ── */
.main{max-width:1100px;margin:0 auto;padding:0 20px 60px;display:grid;grid-template-columns:1fr 320px;gap:20px;align-items:start;}
@media(max-width:860px){.main{grid-template-columns:1fr;}}

/* ── FILTERS ── */
.filters-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center;}
.filter-label{font-size:11px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:0.4px;margin-right:2px;}
.chip{font-size:12px;font-weight:500;padding:5px 12px;border-radius:var(--r-full);border:0.5px solid var(--sep);cursor:pointer;background:var(--surface);color:var(--t2);transition:all 0.15s;white-space:nowrap;user-select:none;}
.chip:hover{background:var(--surface2);color:var(--t1);}
.chip.on{background:var(--blue);color:#fff;border-color:var(--blue);}
.chip.on-green{background:var(--green);color:#fff;border-color:var(--green);}
.fsel{padding:6px 10px;font-size:12px;background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-sm);color:var(--t2);font-family:var(--font);cursor:pointer;outline:none;transition:border-color 0.15s;}
.fsel:focus{border-color:var(--blue);}

/* ── BET FEED ── */
.feed-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;}
.feed-title{font-size:15px;font-weight:700;color:var(--t1);}
.feed-count{font-size:12px;color:var(--t3);}
.feed{display:flex;flex-direction:column;gap:10px;}

/* ── BET CARD ── */
.bet-card{background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-lg);box-shadow:var(--sh0);padding:16px 18px;transition:box-shadow 0.15s,transform 0.15s;animation:slideIn 0.25s ease;}
@keyframes slideIn{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:translateY(0);}}
.bet-card:hover{box-shadow:var(--sh1);transform:translateY(-1px);}
.bet-card-top{display:flex;align-items:flex-start;gap:12px;margin-bottom:10px;}
.avatar{width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:800;color:#fff;flex-shrink:0;letter-spacing:-0.5px;}
.bet-meta{flex:1;min-width:0;}
.bet-user{font-size:13px;font-weight:700;color:var(--t1);}
.bet-time{font-size:11px;color:var(--t3);margin-top:1px;}
.bet-status{flex-shrink:0;}
.bdg{font-size:10px;font-weight:700;padding:3px 9px;border-radius:var(--r-full);letter-spacing:0.3px;white-space:nowrap;}
.bdg-open{background:var(--amber-s);color:var(--amber);}
.bdg-won{background:var(--green-s);color:var(--green);}
.bdg-lost{background:var(--red-s);color:var(--red);}
.bdg-co{background:var(--blue-s);color:var(--blue);}
.bdg-void{background:var(--surface3);color:var(--t3);}
.bet-desc{font-size:14px;font-weight:600;color:var(--t1);margin-bottom:4px;line-height:1.35;}
.bet-league{font-size:11px;color:var(--t2);display:flex;align-items:center;gap:5px;flex-wrap:wrap;}
.bet-league-tag{background:var(--surface2);border-radius:4px;padding:2px 6px;font-size:10px;font-weight:500;}
.bet-card-bottom{display:flex;align-items:center;gap:0;border-top:0.5px solid var(--sep2);padding-top:10px;margin-top:4px;}
.bet-stat{flex:1;text-align:center;}
.bet-stat:not(:last-child){border-right:0.5px solid var(--sep2);}
.bet-stat-lbl{font-size:10px;font-weight:500;color:var(--t3);text-transform:uppercase;letter-spacing:0.3px;margin-bottom:3px;}
.bet-stat-val{font-size:14px;font-weight:700;font-variant-numeric:tabular-nums;}
.bet-note{font-size:11px;color:var(--t3);font-style:italic;margin-top:6px;padding-top:6px;border-top:0.5px solid var(--sep2);}

/* ── SIDEBAR ── */
.sidebar{display:flex;flex-direction:column;gap:14px;position:sticky;top:74px;}
.sidebar-card{background:var(--surface);border:0.5px solid var(--sep);border-radius:var(--r-lg);box-shadow:var(--sh0);overflow:hidden;}
.sc-header{padding:14px 16px;border-bottom:0.5px solid var(--sep);display:flex;align-items:center;gap:8px;}
.sc-title{font-size:13px;font-weight:700;color:var(--t1);}
.sc-body{padding:12px 0;}

/* Leaderboard */
.lb-row{display:flex;align-items:center;gap:10px;padding:8px 16px;transition:background 0.1s;}
.lb-row:hover{background:var(--surface2);}
.lb-rank{font-size:12px;font-weight:700;color:var(--t3);min-width:18px;}
.lb-rank.top1{color:#f59e0b;} .lb-rank.top2{color:#9ca3af;} .lb-rank.top3{color:#cd7c2b;}
.lb-info{flex:1;min-width:0;}
.lb-name{font-size:13px;font-weight:600;}
.lb-sub{font-size:11px;color:var(--t3);}
.lb-pnl{font-size:13px;font-weight:700;font-variant-numeric:tabular-nums;}

/* Sport breakdown */
.sport-row{display:flex;align-items:center;gap:10px;padding:8px 16px;}
.sport-ico{font-size:18px;width:28px;text-align:center;}
.sport-info{flex:1;}
.sport-name{font-size:12px;font-weight:600;}
.sport-bar-wrap{height:4px;background:var(--surface3);border-radius:2px;margin-top:4px;overflow:hidden;}
.sport-bar-fill{height:100%;border-radius:2px;background:var(--blue);transition:width 0.4s ease;}

/* CTA Card */
.cta-card{background:linear-gradient(135deg,#1e3a8a,#2563eb);border-radius:var(--r-lg);padding:20px 18px;text-align:center;}
.cta-title{font-size:16px;font-weight:800;color:#fff;margin-bottom:6px;}
.cta-sub{font-size:12px;color:rgba(255,255,255,0.65);margin-bottom:16px;line-height:1.45;}
.btn-cta{display:inline-flex;align-items:center;justify-content:center;padding:10px 24px;background:#fff;color:#1e3a8a;border-radius:var(--r-md);font-family:var(--font);font-size:13px;font-weight:700;text-decoration:none;transition:all 0.15s;}
.btn-cta:hover{transform:scale(1.03);}

/* Empty / loading */
.empty{text-align:center;padding:48px 20px;color:var(--t2);}
.empty-ico{font-size:36px;margin-bottom:10px;}
.skeleton{background:linear-gradient(90deg,var(--surface2) 25%,var(--surface3) 50%,var(--surface2) 75%);background-size:200% 100%;animation:shimmer 1.4s infinite;border-radius:var(--r-md);}
@keyframes shimmer{0%{background-position:200% 0;}100%{background-position:-200% 0;}}

/* Refresh indicator */
.refresh-bar{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--t3);}
.refresh-prog{flex:1;height:2px;background:var(--surface3);border-radius:1px;overflow:hidden;}
.refresh-fill{height:100%;background:var(--blue);border-radius:1px;transition:width 1s linear;}

/* Toast */
#toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(12px);background:var(--t1);color:var(--bg);border-radius:var(--r-full);padding:10px 20px;font-size:13px;font-weight:500;box-shadow:var(--sh2);opacity:0;pointer-events:none;transition:all 0.22s cubic-bezier(0.34,1.56,0.64,1);z-index:999;}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0);}

@media(max-width:640px){
  .hero{padding:24px 16px 18px;}
  .hero-title{font-size:24px;}
  .stats-bar{padding:0 16px 18px;grid-template-columns:repeat(2,1fr);}
  .main{padding:0 16px 40px;gap:16px;}
  .filters-bar{gap:6px;}
  .topbar-inner{padding:0 14px;}
  .sidebar{position:static;}
}
</style>
</head>
<body>

<!-- ── TOPBAR ── -->
<header class="topbar">
  <div class="topbar-inner">
    <a href="public.php" class="brand">Wett<span>Pro</span></a>
    <div class="live-pill"><span class="ldot"></span>LIVE</div>
    <div class="tb-spacer"></div>
    <button class="ib" id="theme-btn" onclick="toggleTheme()" title="Dark/Light Mode">
      <span id="theme-ico">🌙</span>
    </button>
    <a href="index.php" class="btn-login">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
      Login / Dashboard
    </a>
  </div>
</header>

<!-- ── HERO ── -->
<div class="hero">
  <h1 class="hero-title">Live <span>Bet Feed</span></h1>
  <p class="hero-sub">Alle aktuellen Wetten in Echtzeit – öffentlich einsehbar. Für eigene Wetten einfach einloggen.</p>
</div>

<!-- ── STATS BAR ── -->
<div class="stats-bar" id="stats-bar">
  <div class="stat-card"><div class="stat-lbl">Wetten gesamt</div><div class="stat-val cb" id="s-total">–</div><div class="stat-sub">alle Zeit</div></div>
  <div class="stat-card"><div class="stat-lbl">Offen</div><div class="stat-val ca" id="s-open">–</div><div class="stat-sub">aktive Wetten</div></div>
  <div class="stat-card"><div class="stat-lbl">Trefferquote</div><div class="stat-val cg" id="s-wr">–</div><div class="stat-sub" id="s-wr-s">gewonnen/gesamt</div></div>
  <div class="stat-card"><div class="stat-lbl">Gesamt P&amp;L</div><div class="stat-val" id="s-pnl">–</div><div class="stat-sub">nach Steuern</div></div>
</div>

<!-- ── MAIN ── -->
<div class="main">

  <!-- FEED -->
  <div>
    <div class="filters-bar">
      <span class="filter-label">Filter:</span>
      <div id="status-chips">
        <button class="chip on" data-status="" onclick="setStatus(this,'')">Alle</button>
        <button class="chip" data-status="open" onclick="setStatus(this,'open')">Offen</button>
        <button class="chip" data-status="won" onclick="setStatus(this,'won')">Gewonnen</button>
        <button class="chip" data-status="lost" onclick="setStatus(this,'lost')">Verloren</button>
      </div>
      <select class="fsel" id="flt-sport" onchange="render()">
        <option value="">Alle Sportarten</option>
        <option>Fußball</option><option>Tennis</option><option>Basketball</option>
        <option>Eishockey</option><option>American Football</option><option>MMA / Boxen</option>
      </select>
      <select class="fsel" id="flt-user" onchange="render()">
        <option value="">Alle Nutzer</option>
      </select>
    </div>

    <div class="feed-header">
      <div class="feed-title">Wetten-Feed</div>
      <div style="display:flex;align-items:center;gap:10px;">
        <div class="refresh-bar">
          <span id="refresh-txt">–</span>
          <div class="refresh-prog"><div class="refresh-fill" id="refresh-fill" style="width:100%"></div></div>
        </div>
      </div>
    </div>

    <div class="feed" id="feed">
      <!-- Skeleton loader -->
      <div class="bet-card"><div class="skeleton" style="height:90px;"></div></div>
      <div class="bet-card"><div class="skeleton" style="height:90px;"></div></div>
      <div class="bet-card"><div class="skeleton" style="height:90px;"></div></div>
    </div>

    <div id="feed-empty" class="empty" style="display:none;">
      <div class="empty-ico">🔍</div>
      Keine Wetten gefunden.
    </div>
  </div>

  <!-- SIDEBAR -->
  <aside class="sidebar">

    <!-- CTA -->
    <div class="cta-card">
      <div class="cta-title">Mitmachen!</div>
      <div class="cta-sub">Logge dich ein und platziere deine eigenen Wetten. Verfolge deinen P&L, nutze den WM-Tracker und mehr.</div>
      <a href="index.php" class="btn-cta">Zum Dashboard →</a>
    </div>

    <!-- Leaderboard -->
    <div class="sidebar-card">
      <div class="sc-header">
        <span style="font-size:16px;">🏆</span>
        <span class="sc-title">Leaderboard</span>
      </div>
      <div class="sc-body" id="leaderboard">
        <div class="empty" style="padding:20px;">Lade…</div>
      </div>
    </div>

    <!-- Sport-Breakdown -->
    <div class="sidebar-card">
      <div class="sc-header">
        <span style="font-size:16px;">⚽</span>
        <span class="sc-title">Nach Sportart</span>
      </div>
      <div class="sc-body" id="sport-breakdown">
        <div class="empty" style="padding:20px;">Lade…</div>
      </div>
    </div>

  </aside>
</div>

<div id="toast"></div>

<script>
const REFRESH_INTERVAL = 30; // Sekunden
const SPORT_EMOJI = {Fußball:'⚽',Tennis:'🎾',Basketball:'🏀',Eishockey:'🏒','American Football':'🏈',Baseball:'⚾','MMA / Boxen':'🥊',Sonstiges:'🎯'};

let allBets = [];
let filteredBets = [];
let activeStatus = '';
let refreshTimer  = null;
let refreshCount  = REFRESH_INTERVAL;

// ── Theme ──
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  document.getElementById('theme-ico').textContent = t==='dark' ? '☀️' : '🌙';
  localStorage.setItem('wtp_pub_theme', t);
}
function toggleTheme() {
  applyTheme(document.documentElement.getAttribute('data-theme')==='dark' ? 'light' : 'dark');
}
(function(){
  const saved = localStorage.getItem('wtp_pub_theme');
  const pref  = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  applyTheme(saved || pref);
})();

// ── Toast ──
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), 2200);
}

// ── Helpers ──
function fmtPnL(v)  { return (v>=0?'+':'')+v.toFixed(2)+' €'; }
function fmtAbs(v)  { return (+v).toFixed(2)+' €'; }
function timeAgo(dateStr) {
  const d = new Date(dateStr + 'T00:00:00');
  const now = new Date();
  const diff = Math.floor((now - d) / 86400000);
  if (diff === 0) return 'Heute';
  if (diff === 1) return 'Gestern';
  if (diff < 7)  return `vor ${diff} Tagen`;
  return d.toLocaleDateString('de-DE', {day:'2-digit',month:'2-digit',year:'2-digit'});
}
function initials(name) {
  return name.split(' ').map(p=>p[0]||'').join('').toUpperCase().slice(0,2) || '?';
}
function possibleWin(stake, odds) {
  return (stake * odds).toFixed(2);
}

// ── Status filter ──
function setStatus(el, val) {
  activeStatus = val;
  document.querySelectorAll('#status-chips .chip').forEach(b => b.classList.remove('on'));
  el.classList.add('on');
  render();
}

// ── Render feed ──
function render() {
  const fSport  = document.getElementById('flt-sport').value;
  const fUser   = document.getElementById('flt-user').value;

  filteredBets = allBets.filter(b => {
    if (activeStatus && b.status !== activeStatus) return false;
    if (fSport && b.sport !== fSport) return false;
    if (fUser  && b.user  !== fUser)  return false;
    return true;
  });

  const feed      = document.getElementById('feed');
  const feedEmpty = document.getElementById('feed-empty');
  document.querySelector('.feed-count')?.remove();

  if (!filteredBets.length) {
    feed.innerHTML = '';
    feedEmpty.style.display = '';
    return;
  }
  feedEmpty.style.display = 'none';

  feed.innerHTML = filteredBets.map(b => {
    const pnl  = b.pnl;
    const pStr = (b.status==='won'||b.status==='lost'||b.status==='cashout') ? fmtPnL(pnl) : '–';
    const pCls = pnl>0?'cg':pnl<0?'cr':'';
    const win  = possibleWin(b.stake, b.odds);
    const bdgCls = {won:'bdg-won',lost:'bdg-lost',open:'bdg-open',cashout:'bdg-co',void:'bdg-void'}[b.status]||'bdg-void';
    const bdgLbl = {won:'Gewonnen',lost:'Verloren',open:'Offen',cashout:'Cashout',void:'Void'}[b.status]||b.status;
    const ico    = SPORT_EMOJI[b.sport] || '🎯';
    const av     = initials(b.user);
    const avBg   = b.color || '#6366f1';
    return `<div class="bet-card">
      <div class="bet-card-top">
        <div class="avatar" style="background:${avBg};">${av}</div>
        <div class="bet-meta">
          <div class="bet-user">${b.user}</div>
          <div class="bet-time">${timeAgo(b.date)}</div>
        </div>
        <div class="bet-status"><span class="bdg ${bdgCls}">${bdgLbl}</span></div>
      </div>
      <div class="bet-desc">${ico} ${b.desc}</div>
      <div class="bet-league">
        ${b.league ? `<span class="bet-league-tag">${b.league}</span>` : ''}
        ${b.market ? `<span class="bet-league-tag">${b.market}</span>` : ''}
        ${b.sport  ? `<span class="bet-league-tag">${b.sport}</span>`  : ''}
      </div>
      <div class="bet-card-bottom">
        <div class="bet-stat">
          <div class="bet-stat-lbl">Quote</div>
          <div class="bet-stat-val cb">${b.odds.toFixed(2)}×</div>
        </div>
        <div class="bet-stat">
          <div class="bet-stat-lbl">Einsatz</div>
          <div class="bet-stat-val">${fmtAbs(b.stake)}</div>
        </div>
        <div class="bet-stat">
          <div class="bet-stat-lbl">Mög. Gewinn</div>
          <div class="bet-stat-val cg">+${win} €</div>
        </div>
        <div class="bet-stat">
          <div class="bet-stat-lbl">P&amp;L</div>
          <div class="bet-stat-val ${pCls}">${pStr}</div>
        </div>
      </div>
      ${b.note ? `<div class="bet-note">💬 ${b.note}</div>` : ''}
    </div>`;
  }).join('');
}

// ── Leaderboard ──
function renderLeaderboard() {
  const byUser = {};
  allBets.forEach(b => {
    if (!byUser[b.user]) byUser[b.user] = {name:b.user,color:b.color,pnl:0,cnt:0,won:0,settled:0};
    byUser[b.user].pnl  += b.pnl;
    byUser[b.user].cnt++;
    if (b.status==='won'||b.status==='lost'||b.status==='cashout') {
      byUser[b.user].settled++;
      if (b.status==='won') byUser[b.user].won++;
    }
  });
  const ranked = Object.values(byUser).sort((a,b) => b.pnl - a.pnl);
  const rankCls = ['top1','top2','top3'];
  const medals  = ['🥇','🥈','🥉'];
  document.getElementById('leaderboard').innerHTML = ranked.length
    ? ranked.map((u, i) => {
        const wr = u.settled ? (u.won/u.settled*100).toFixed(0)+'%' : '–';
        return `<div class="lb-row">
          <div class="lb-rank ${rankCls[i]||''}">${medals[i]||String(i+1)+'.'}</div>
          <div class="lb-info">
            <div class="lb-name">${u.name}</div>
            <div class="lb-sub">${u.cnt} Wetten · ${wr} Trefferquote</div>
          </div>
          <div class="lb-pnl ${u.pnl>=0?'cg':'cr'}">${fmtPnL(u.pnl)}</div>
        </div>`;
      }).join('')
    : '<div class="empty" style="padding:20px;">Keine Daten</div>';
}

// ── Sport Breakdown ──
function renderSportBreakdown() {
  const bySport = {};
  allBets.forEach(b => {
    if (!bySport[b.sport]) bySport[b.sport] = 0;
    bySport[b.sport]++;
  });
  const total = allBets.length || 1;
  const sorted = Object.entries(bySport).sort((a,b) => b[1]-a[1]);
  document.getElementById('sport-breakdown').innerHTML = sorted.length
    ? sorted.map(([s, cnt]) => {
        const pct = (cnt/total*100).toFixed(0);
        return `<div class="sport-row">
          <div class="sport-ico">${SPORT_EMOJI[s]||'🎯'}</div>
          <div class="sport-info">
            <div class="sport-name">${s} <span style="color:var(--t3);font-weight:400;font-size:11px;">${cnt}×</span></div>
            <div class="sport-bar-wrap"><div class="sport-bar-fill" style="width:${pct}%"></div></div>
          </div>
        </div>`;
      }).join('')
    : '<div class="empty" style="padding:20px;">Keine Daten</div>';
}

// ── User Filter aufbauen ──
function buildUserFilter() {
  const users = [...new Set(allBets.map(b => b.user))].sort();
  const sel = document.getElementById('flt-user');
  const cur = sel.value;
  sel.innerHTML = '<option value="">Alle Nutzer</option>' +
    users.map(u => `<option${u===cur?' selected':''}>${u}</option>`).join('');
}

// ── Stats aktualisieren ──
function updateStats(stats) {
  document.getElementById('s-total').textContent = stats.total;
  document.getElementById('s-open').textContent  = stats.open;
  const wrEl = document.getElementById('s-wr');
  wrEl.textContent = stats.winRate + '%';
  wrEl.className   = 'stat-val ' + (stats.winRate >= 50 ? 'cg' : 'ca');
  document.getElementById('s-wr-s').textContent  = stats.won + '/' + (stats.won + stats.lost);
  const pEl = document.getElementById('s-pnl');
  pEl.textContent = fmtPnL(stats.totalPnl);
  pEl.className   = 'stat-val ' + (stats.totalPnl >= 0 ? 'cg' : 'cr');
}

// ── Fetch ──
async function fetchFeed() {
  try {
    const r = await fetch('?a=feed&_t=' + Date.now(), {cache:'no-store'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    allBets = d.bets || [];
    updateStats(d.stats || {});
    buildUserFilter();
    render();
    renderLeaderboard();
    renderSportBreakdown();
    document.getElementById('refresh-txt').textContent = 'Jetzt: ' + new Date().toLocaleTimeString('de-DE',{hour:'2-digit',minute:'2-digit'});
  } catch(e) {
    console.error('Feed-Fehler:', e);
    toast('Verbindungsfehler – versuche es gleich erneut');
  }
}

// ── Auto-Refresh Countdown ──
function startRefreshTimer() {
  clearInterval(refreshTimer);
  refreshCount = REFRESH_INTERVAL;
  updateFill();
  refreshTimer = setInterval(() => {
    refreshCount--;
    updateFill();
    if (refreshCount <= 0) {
      fetchFeed();
      refreshCount = REFRESH_INTERVAL;
    }
  }, 1000);
}

function updateFill() {
  const pct = (refreshCount / REFRESH_INTERVAL * 100).toFixed(0);
  const el  = document.getElementById('refresh-fill');
  if (el) el.style.width = pct + '%';
}

// ── Init ──
fetchFeed();
startRefreshTimer();
</script>

</body>
</html>
