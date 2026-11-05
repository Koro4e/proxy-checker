#!/usr/bin/env python3
"""
proxy_checker.py — сбор публичных прокси из автообновляемых GitHub-списков
и их локальная проверка: живость, latency, страна, ISP, anonymity, HTTPS-туннель.

Только проверка и характеристики. Никаких регистраций, ферм и обвязки.

Хранилище: out/store.json — отслеживаемый набор прокси. Каждый цикл списки
перечитываются, диффятся с хранилищем: новые добавляются, исчезнувшие удаляются,
дельта пишется в out/changes.jsonl и показывается на дашборде.

Зависимости:  pip install aiohttp aiohttp-socks

Примеры:
  python proxy_checker.py --loop 30 --serve 8000   # фоновый режим: цикл каждые 30 мин + веб-интерфейс
  python proxy_checker.py                          # один прогон, только файлы
  python proxy_checker.py --protocols socks5 --top 50
  python proxy_checker.py --limit-per-source 20    # быстрый тест на малом объёме
  python proxy_checker.py --sources-json my_sources.json

Результаты в out/: dashboard.html (интерфейс), proxies_live.csv, proxies_live.json,
store.json (хранилище), changes.jsonl (история изменений списков).
"""

import argparse
import asyncio
import csv
import functools
import http.server
import json
import re
import socketserver
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# В замороженном exe рабочая папка — рядом с exe, а не во временной распаковке
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent

import aiohttp
from aiohttp_socks import ProxyConnector

# ----------------------------------------------------------------------------
# Источники — автообновляемые GitHub-репозитории из гайда (raw-URL проверены).
# proto=None значит «протокол указан в строке списка» (http://..., socks5://...),
# а для голых ip:port строк используется http.
# ----------------------------------------------------------------------------
DEFAULT_SOURCES = [
    {"name": "monosans/proxy-list http",    "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",    "proto": "http"},
    {"name": "monosans/proxy-list socks4",  "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",  "proto": "socks4"},
    {"name": "monosans/proxy-list socks5",  "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",  "proto": "socks5"},
    {"name": "TheSpeedX/PROXY-List http",   "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",   "proto": "http"},
    {"name": "TheSpeedX/PROXY-List socks4", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "proto": "socks4"},
    {"name": "TheSpeedX/PROXY-List socks5", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "proto": "socks5"},
    {"name": "hideip.me http",              "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",      "proto": "http"},
    {"name": "hideip.me https",             "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt",     "proto": "http"},
    {"name": "hideip.me socks4",            "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",    "proto": "socks4"},
    {"name": "hideip.me socks5",            "url": "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",    "proto": "socks5"},
    {"name": "roosterkid HTTPS",            "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",  "proto": "http"},
    {"name": "roosterkid SOCKS4",           "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt", "proto": "socks4"},
    {"name": "roosterkid SOCKS5",           "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "proto": "socks5"},
    {"name": "dinoz0rg checked http",       "url": "https://raw.githubusercontent.com/dinoz0rg/proxy-list/main/checked_proxies/http.txt", "proto": "http"},
    {"name": "dinoz0rg checked socks4",      "url": "https://cdn.jsdelivr.net/gh/dinoz0rg/proxy-list@main/checked_proxies/socks4.txt", "proto": "socks4"},
    {"name": "dinoz0rg checked socks5",      "url": "https://cdn.jsdelivr.net/gh/dinoz0rg/proxy-list@main/checked_proxies/socks5.txt", "proto": "socks5"},
    {"name": "ProxyScrape all",             "url": "https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/all/data.txt", "proto": None},
    {"name": "ProxyScrape http",            "url": "https://cdn.jsdelivr.net/gh/ProxyScrape/free-proxy-list@main/proxies/protocols/http/data.txt", "proto": None},
    {"name": "ProxyScrape socks4",          "url": "https://cdn.jsdelivr.net/gh/ProxyScrape/free-proxy-list@main/proxies/protocols/socks4/data.txt", "proto": None},
    {"name": "ProxyScrape socks5",          "url": "https://cdn.jsdelivr.net/gh/ProxyScrape/free-proxy-list@main/proxies/protocols/socks5/data.txt", "proto": None},
    {"name": "rix4uni fresh proxylist",     "url": "https://raw.githubusercontent.com/rix4uni/fresh-proxy-list/main/proxylist.txt", "proto": None},
]

GEO_JUDGE = "http://ip-api.com/json/?fields=status,message,country,countryCode,city,isp,org,as,query,proxy,hosting&lang=ru"
ANON_JUDGE = "http://httpbin.org/get"
CONNECT_JUDGE = "https://api.ipify.org/?format=json"

SCHEME_RE = re.compile(r"^(https?|socks4a?|socks5h?)://", re.I)
IPPORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")
SCHEME_MAP = {"http": "http", "https": "http", "socks4": "socks4", "socks4a": "socks4", "socks5": "socks5", "socks5h": "socks5"}
ANON_HEADER_KEYS = ("via", "x-forwarded-for", "forwarded", "proxy-connection", "client-ip", "x-real-ip")


@dataclass
class Proxy:
    proto: str
    host: str
    port: int
    sources: set = field(default_factory=set)


@dataclass
class CheckResult:
    proto: str
    host: str
    port: int
    sources: str = ""
    alive: bool = False
    latency_ms: int | None = None
    exit_ip: str | None = None
    country: str | None = None
    cc: str | None = None
    city: str | None = None
    isp: str | None = None
    hosting: bool | None = None
    https_ok: bool | None = None
    anon: str = "n/a"
    error: str | None = None


# ----------------------------------------------------------------------------
# Хранилище: отслеживаемый набор прокси между прогонами
# ----------------------------------------------------------------------------

def store_key(proto: str, host: str, port: int) -> str:
    return f"{proto}|{host}|{port}"


def load_store(out_dir: Path) -> dict:
    path = out_dir / "store.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        print("  [!] store.json повреждён — начинаю с пустого хранилища")
        return {}


def save_store(out_dir: Path, store: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "store.json").write_text(
        json.dumps(store, ensure_ascii=False, indent=1), encoding="utf-8")


def append_changes(out_dir: Path, record: dict) -> None:
    with open(out_dir / "changes.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ----------------------------------------------------------------------------
# Загрузка и парсинг списков
# ----------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Сбор и проверка публичных прокси (HTTP/SOCKS4/SOCKS5).")
    p.add_argument("--protocols", default="http,socks4,socks5",
                   help="какие протоколы проверять, через запятую (по умолчанию все)")
    p.add_argument("--timeout", type=int, default=8, help="таймаут на прокси в секундах (по умолчанию 8)")
    p.add_argument("--concurrency", type=int, default=300, help="сколько прокси проверять одновременно (по умолчанию 300)")
    p.add_argument("--limit-per-source", type=int, default=0, help="ограничить число прокси с каждого источника (0 = без лимита)")
    p.add_argument("--stride", type=int, default=1, help="брать каждую N-ю строку списка — для честной выборки вместо головы (1 = все)")
    p.add_argument("--skip-dead", type=int, default=0, help="не перепроверять известные мёртвые каждый N-й цикл (0 = проверять всегда)")
    p.add_argument("--fast-judges", type=int, default=0, help="judges (https/anon) только для прокси быстрее N мс (0 = для всех)")
    p.add_argument("--top", type=int, default=25, help="сколько лучших показать в консоли (по умолчанию 25)")
    p.add_argument("--loop", type=int, default=0, help="повторять цикл каждые N минут (0 = один прогон)")
    p.add_argument("--serve", type=int, default=0, help="поднять веб-интерфейс на 127.0.0.1:PORT (0 = выключено)")
    p.add_argument("--out", default=str(BASE_DIR / "out"), help="папка для результатов")
    p.add_argument("--no-anon", action="store_true", help="не определять уровень анонимности (быстрее)")
    p.add_argument("--no-connect-test", action="store_true", help="не тестировать HTTPS-туннель (CONNECT)")
    p.add_argument("--sources-json", default=None, help='JSON-файл с доп. источниками: [{"name","url","proto"}]')
    return p.parse_args()


async def fetch_text(session: aiohttp.ClientSession, url: str) -> str | None:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status != 200:
                print(f"  [!] HTTP {r.status}: {url}")
                return None
            return await r.text()
    except Exception as e:
        print(f"  [!] {type(e).__name__}: {url}")
        return None


def valid_port(port: int) -> bool:
    return 1 <= port <= 65535


def valid_ip(host: str) -> bool:
    parts = host.split(".")
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


async def load_proxies(session: aiohttp.ClientSession, sources: list, args) -> dict:
    bag: dict = {}

    def feed(name: str, proto_default: str | None, text: str) -> int:
        added = 0
        for idx, raw in enumerate(text.splitlines()):
            if args.limit_per_source and added >= args.limit_per_source:
                break
            if args.stride > 1 and idx % args.stride != 0:
                continue
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            proto = proto_default
            m = SCHEME_RE.match(line)
            if m:
                proto = SCHEME_MAP.get(m.group(1).lower(), proto_default)
                line = line[m.end():].strip()
            # Голый ip:port без схемы — считаем HTTP-прокси.
            proto = proto or "http"
            line = line.split()[0] if line else line
            m2 = IPPORT_RE.search(line)
            if not m2:
                continue
            host, port = m2.group(1), int(m2.group(2))
            if not valid_ip(host) or not valid_port(port):
                continue
            if proto not in args.protocols:
                continue
            key = (proto, host, port)
            if key in bag:
                bag[key].sources.add(name)
            else:
                bag[key] = Proxy(proto=proto, host=host, port=port, sources={name})
            added += 1
        return added

    async def grab(src):
        return src, await fetch_text(session, src["url"])

    for src, text in await asyncio.gather(*[grab(s) for s in sources]):
        if text is None:
            continue
        n = feed(src["name"], src.get("proto"), text)
        print(f"  [+] {src['name']}: {n} entries")
    return bag


# ----------------------------------------------------------------------------
# Проверка прокси
# ----------------------------------------------------------------------------

async def get_own_ip(session: aiohttp.ClientSession) -> str | None:
    try:
        async with session.get("http://ip-api.com/json/?fields=query",
                               timeout=aiohttp.ClientTimeout(total=10)) as r:
            j = await r.json(content_type=None)
            return j.get("query")
    except Exception:
        return None


async def check_proxy(sem: asyncio.Semaphore, p: Proxy, args, my_ip: str | None, stats: dict, resolver=None) -> CheckResult:
    res = CheckResult(proto=p.proto, host=p.host, port=p.port, sources=";".join(sorted(p.sources)))
    async with sem:
        connector = ProxyConnector.from_url(f"{p.proto}://{p.host}:{p.port}")
        try:
            timeout = aiohttp.ClientTimeout(total=args.timeout, connect=args.timeout)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout, resolver=resolver) as s:
                # 1. Гео + latency через прокси
                t0 = time.perf_counter()
                async with s.get(GEO_JUDGE) as r:
                    data = await r.json(content_type=None)
                res.latency_ms = int((time.perf_counter() - t0) * 1000)
                if data.get("status") != "success":
                    raise RuntimeError(f"judge: {data.get('message', 'fail')}")
                res.alive = True
                res.exit_ip = data.get("query")
                res.country = data.get("country")
                res.cc = data.get("countryCode")
                res.city = data.get("city")
                res.isp = (data.get("isp") or data.get("org") or "")[:80]
                res.hosting = data.get("hosting")

                # 2. HTTPS-туннель (CONNECT) — на медленных пропускаем в fast-режиме
                if not args.no_connect_test and (args.fast_judges <= 0 or (res.latency_ms or 10**9) <= args.fast_judges):
                    try:
                        t1 = time.perf_counter()
                        async with s.get(CONNECT_JUDGE) as r:
                            await r.read()
                        res.https_ok = (time.perf_counter() - t1) < args.timeout
                    except Exception:
                        res.https_ok = False

                # 3. Уровень анонимности по эху заголовков — тоже только для быстрых
                if not args.no_anon and (args.fast_judges <= 0 or (res.latency_ms or 10**9) <= args.fast_judges):
                    try:
                        async with s.get(ANON_JUDGE) as r:
                            j = await r.json(content_type=None)
                        hdrs = {k.lower(): str(v) for k, v in j.get("headers", {}).items()}
                        found = [k for k in ANON_HEADER_KEYS if k in hdrs]
                        if not found:
                            res.anon = "elite"
                        elif my_ip and my_ip in hdrs.get("x-forwarded-for", ""):
                            res.anon = "transparent"
                        else:
                            res.anon = "anonymous"
                    except Exception:
                        res.anon = "n/a"
        except Exception as e:
            msg = str(e)
            res.error = (type(e).__name__ + (f": {msg[:70]}" if msg else ""))[:100]
        finally:
            stats["done"] += 1
            if res.alive:
                stats["alive"] += 1
            if stats["done"] % 1000 == 0:
                print(f"  ... checked {stats['done']}, alive {stats['alive']}")
    return res


# ----------------------------------------------------------------------------
# Дашборд
# ----------------------------------------------------------------------------

DASHBOARD_TEMPLATE = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="300">
<title>Proxy Dashboard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; background:#0d0f13; color:#d7dae0; font:13px/1.45 ui-monospace,Consolas,Menlo,monospace; }
  .wrap { max-width:1400px; margin:0 auto; padding:20px; }
  h1 { font-size:18px; margin:0 0 2px; }
  .sub { color:#7d8490; font-size:11px; margin-bottom:16px; }
  .cards { display:flex; flex-wrap:wrap; gap:10px; margin-bottom:14px; }
  .card { background:#151922; border:1px solid #242a36; border-radius:8px; padding:10px 16px; min-width:110px; }
  .card .v { font-size:22px; font-weight:700; }
  .card .l { font-size:10px; color:#7d8490; text-transform:uppercase; letter-spacing:.08em; }
  .v.ok { color:#5fd08a; } .v.add { color:#6ac8e8; } .v.rem { color:#e86a7a; }
  .bar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:12px; }
  select, input[type=text] { background:#151922; color:#d7dae0; border:1px solid #2a3140; border-radius:6px; padding:5px 8px; font:inherit; }
  input[type=text] { width:210px; }
  label.chk { display:flex; gap:5px; align-items:center; color:#9aa1ad; cursor:pointer; }
  button { background:#2b3b5e; color:#dbe6ff; border:1px solid #3d5388; border-radius:6px; padding:5px 12px; font:inherit; cursor:pointer; }
  button:hover { background:#35497a; }
  .cnt { margin-left:auto; color:#7d8490; font-size:11px; }
  table { width:100%; border-collapse:collapse; background:#10141b; border:1px solid #1f2530; border-radius:8px; overflow:hidden; }
  th { position:sticky; top:0; background:#171c26; color:#8f97a5; font-size:10px; text-transform:uppercase; letter-spacing:.07em; text-align:left; padding:8px 10px; cursor:pointer; user-select:none; white-space:nowrap; }
  th:hover { color:#d7dae0; }
  th.sorted { color:#e8c46a; }
  td { padding:6px 10px; border-top:1px solid #1a2029; white-space:nowrap; }
  tr:hover td { background:#151b25; }
  .ms-fast { color:#5fd08a; font-weight:700; } .ms-mid { color:#e8c46a; } .ms-slow { color:#e86a7a; }
  .elite { color:#5fd08a; } .anonymous { color:#e8c46a; } .transparent { color:#e86a7a; }
  .dc { color:#e86a7a; } .resid { color:#5fd08a; }
  .src { color:#6b7280; max-width:260px; overflow:hidden; text-overflow:ellipsis; }
  @media (max-width: 800px){ .card{min-width:90px} input[type=text]{width:140px} }
</style>
</head>
<body>
<div class="wrap">
  <h1>Proxy Dashboard</h1>
  <div class="sub">обновлено: __GENERATED__ &middot; страница сама перечитывается каждые 5 мин &middot; данные: out/proxies_live.json</div>

  <div class="cards">
    <div class="card"><div class="v ok">__ALIVE__</div><div class="l">живых</div></div>
    <div class="card"><div class="v">__CHECKED__</div><div class="l">проверено</div></div>
    <div class="card"><div class="v add">+__ADDED__</div><div class="l">новых в списках</div></div>
    <div class="card"><div class="v rem">-__REMOVED__</div><div class="l">исчезло из списков</div></div>
    <div class="card"><div class="v">__TRACKED__</div><div class="l">в хранилище</div></div>
  </div>

  <div class="bar">
    <select id="fProto"><option value="">протокол: все</option><option>http</option><option>socks4</option><option>socks5</option></select>
    <select id="fCC"><option value="">страна: все</option></select>
    <select id="fAnon"><option value="">anon: все</option><option>elite</option><option>anonymous</option><option>transparent</option><option>n/a</option></select>
    <label class="chk"><input type="checkbox" id="fHttps"> только HTTPS</label>
    <label class="chk"><input type="checkbox" id="fResid"> не датацентр</label>
    <input type="text" id="fSearch" placeholder="поиск: IP / город / ISP...">
    <button id="btnCopy">Copy ip:port</button>
    <span class="cnt" id="cnt"></span>
  </div>

  <table id="t">
    <thead><tr>
      <th data-k="proto">proto</th><th data-k="addr">address</th><th data-k="latency_ms">ms</th>
      <th data-k="cc">cc</th><th data-k="city">city</th><th data-k="isp">ISP</th>
      <th data-k="hosting">тип</th><th data-k="https_ok">https</th><th data-k="anon">anon</th><th class="src">sources</th>
    </tr></thead>
    <tbody id="tb"></tbody>
  </table>
</div>

<script>
const DATA = __DATA__;
let sortKey = "latency_ms", sortDir = 1;

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const addr = r => r.host + ":" + r.port;
const getVal = (r,k) => k==="addr" ? addr(r) : (r[k] ?? "");

function render(){
  const fp = document.getElementById("fProto").value;
  const fc = document.getElementById("fCC").value;
  const fa = document.getElementById("fAnon").value;
  const fh = document.getElementById("fHttps").checked;
  const fr = document.getElementById("fResid").checked;
  const q  = document.getElementById("fSearch").value.trim().toLowerCase();

  let rows = DATA.proxies.filter(r =>
    (!fp || r.proto === fp) &&
    (!fc || r.cc === fc) &&
    (!fa || r.anon === fa) &&
    (!fh || r.https_ok === true) &&
    (!fr || r.hosting === false) &&
    (!q || (addr(r)+" "+(r.city||"")+" "+(r.isp||"")+" "+(r.country||"")).toLowerCase().includes(q))
  );
  rows.sort((a,b) => {
    const va = getVal(a,sortKey), vb = getVal(b,sortKey);
    if (typeof va === "number" || typeof vb === "number") return ((va??1e9) - (vb??1e9)) * sortDir;
    return String(va).localeCompare(String(vb)) * sortDir;
  });

  const tb = document.getElementById("tb");
  tb.innerHTML = rows.map(r => {
    const ms = r.latency_ms;
    const msCls = ms < 300 ? "ms-fast" : ms < 1000 ? "ms-mid" : "ms-slow";
    const typeCls = r.hosting ? "dc" : "resid";
    const typeTxt = r.hosting ? "DC" : "resid";
    return "<tr>" +
      "<td>" + esc(r.proto) + "</td>" +
      "<td>" + esc(addr(r)) + "</td>" +
      "<td class='" + msCls + "'>" + (ms ?? "?") + "</td>" +
      "<td>" + esc(r.cc || "??") + "</td>" +
      "<td>" + esc(r.city || "") + "</td>" +
      "<td>" + esc(r.isp || "") + "</td>" +
      "<td class='" + typeCls + "'>" + typeTxt + "</td>" +
      "<td>" + (r.https_ok ? "да" : "нет") + "</td>" +
      "<td class='" + esc(r.anon) + "'>" + esc(r.anon) + "</td>" +
      "<td class='src' title='" + esc(r.sources) + "'>" + esc(r.sources) + "</td>" +
    "</tr>";
  }).join("");
  document.getElementById("cnt").textContent = "показано " + rows.length + " из " + DATA.proxies.length;
}

// страны в селектор — по убыванию количества
const ccCount = {};
DATA.proxies.forEach(r => { if (r.cc) ccCount[r.cc] = (ccCount[r.cc]||0)+1; });
Object.entries(ccCount).sort((a,b)=>b[1]-a[1]).forEach(([cc]) => {
  const o = document.createElement("option"); o.textContent = cc; document.getElementById("fCC").appendChild(o);
});

document.querySelectorAll("th[data-k]").forEach(th => th.addEventListener("click", () => {
  const k = th.dataset.k;
  if (sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = 1; }
  document.querySelectorAll("th").forEach(x => x.classList.remove("sorted"));
  th.classList.add("sorted");
  render();
}));
["fProto","fCC","fAnon"].forEach(id => document.getElementById(id).addEventListener("change", render));
["fHttps","fResid"].forEach(id => document.getElementById(id).addEventListener("change", render));
document.getElementById("fSearch").addEventListener("input", render);
document.getElementById("btnCopy").addEventListener("click", () => {
  const txt = DATA.proxies.map(r => r.proto + "://" + addr(r)).join("\n");
  navigator.clipboard.writeText(txt).then(
    () => { document.getElementById("btnCopy").textContent = "Скопировано!"; setTimeout(()=>document.getElementById("btnCopy").textContent="Copy ip:port", 1500); },
    () => { document.getElementById("btnCopy").textContent = "Ошибка"; });
});

render();
</script>
</body>
</html>
"""


def build_dashboard(out_dir: Path, live: list, total_checked: int, delta: dict,
                    tracked: int, generated_at: str) -> Path:
    data = {"generated_at": generated_at, "proxies": [
        {"proto": r.proto, "host": r.host, "port": r.port, "latency_ms": r.latency_ms,
         "cc": r.cc, "city": r.city, "country": r.country, "isp": r.isp,
         "hosting": r.hosting, "https_ok": r.https_ok, "anon": r.anon, "sources": r.sources}
        for r in live]}
    html = (DASHBOARD_TEMPLATE
            .replace("__DATA__", json.dumps(data, ensure_ascii=False))
            .replace("__GENERATED__", generated_at)
            .replace("__ALIVE__", str(len(live)))
            .replace("__CHECKED__", str(total_checked))
            .replace("__ADDED__", str(delta.get("added", 0)))
            .replace("__REMOVED__", str(delta.get("removed", 0)))
            .replace("__TRACKED__", str(tracked)))
    path = out_dir / "dashboard.html"
    path.write_text(html, encoding="utf-8")
    return path


# ----------------------------------------------------------------------------
# Выводы
# ----------------------------------------------------------------------------

def write_outputs(results: list, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    live = [r for r in results if r.alive]
    live.sort(key=lambda r: (r.latency_ms or 10**9))

    csv_path = out_dir / "proxies_live.csv"
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["proto", "host", "port", "latency_ms", "exit_ip", "country", "cc",
                    "city", "isp", "hosting", "https_ok", "anon", "sources"])
        for r in live:
            w.writerow([r.proto, r.host, r.port, r.latency_ms, r.exit_ip, r.country, r.cc,
                        r.city, r.isp, r.hosting, r.https_ok, r.anon, r.sources])

    json_path = out_dir / "proxies_live.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_checked": len(results),
        "alive": len(live),
        "proxies": [asdict(r) for r in live],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return csv_path, json_path


def print_table(live: list, top: int) -> None:
    print(f"\n  {'proto':<7} {'address':<24} {'ms':>5}  {'cc':<3} {'city':<14} {'ISP':<28} {'https':<5} {'anon'}")
    print("  " + "-" * 110)
    for r in live[:top]:
        addr_s = f"{r.host}:{r.port}"
        print(f"  {r.proto:<7} {addr_s:<24} {r.latency_ms:>5}  {r.cc or '??':<3} "
              f"{(r.city or '')[:14]:<14} {(r.isp or '')[:28]:<28} "
              f"{('' if r.https_ok is None else ('yes' if r.https_ok else 'no')):<5} {r.anon}")


def start_web_server(out_dir: Path, port: int):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(out_dir))
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


# ----------------------------------------------------------------------------
# Цикл
# ----------------------------------------------------------------------------

async def run_cycle(args, session: aiohttp.ClientSession, store: dict) -> list:
    print("[1/4] Fetching lists...")
    bag = await load_proxies(session, args.sources, args)
    print(f"      unique in lists now: {len(bag)}")

    # Дифф с хранилищем: новые добавляем, исчезнувшие удаляем
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    current_keys = {store_key(p.proto, p.host, p.port) for p in bag.values()}
    store_keys = {k for k in store if not k.startswith("_")}
    added = sorted(current_keys - store_keys)
    removed = sorted(store_keys - current_keys)
    first_run = not store_keys
    for k, p in bag.items():
        sk = store_key(p.proto, p.host, p.port)
        e = store.setdefault(sk, {"proto": p.proto, "host": p.host, "port": p.port,
                                  "sources": [], "last_seen": None, "last": None})
        e["sources"] = sorted(p.sources)
        e["last_seen"] = now_iso
    for k in removed:
        del store[k]
    delta = {"added": 0 if first_run else len(added), "removed": len(removed)}
    print(f"[2/4] Diff vs store: +{delta['added']} added, -{delta['removed']} removed"
          + ("  (первый прогон — всё новое)" if first_run else ""))
    if added and not first_run:
        print("      sample added:   " + ", ".join(added[:5]) + ("..." if len(added) > 5 else ""))
    if removed:
        print("      sample removed: " + ", ".join(removed[:5]) + ("..." if len(removed) > 5 else ""))

    # Счётчик циклов в хранилище (для --skip-dead)
    meta = store.setdefault("_meta", {"cycle": 0})
    meta["cycle"] = int(meta.get("cycle", 0)) + 1
    cycle_no = int(meta["cycle"])

    proxies = list(bag.values())
    # Инкрементальный режим: известные мёртвые перепроверяются каждый N-й цикл,
    # живые и новые — каждый. Живых мало, поэтому обычный цикл короткий.
    skipped_dead = 0
    if args.skip_dead > 0 and cycle_no % args.skip_dead != 0:
        filtered = []
        for p in proxies:
            e = store.get(store_key(p.proto, p.host, p.port))
            last = (e or {}).get("last")
            if last and last.get("alive") is False:
                skipped_dead += 1
                continue
            filtered.append(p)
        proxies = filtered

    print(f"[3/4] Checking (concurrency {args.concurrency}, timeout {args.timeout}s, cycle {cycle_no}" +
          (f", skip-dead: пропущено {skipped_dead} мёртвых)" if skipped_dead else ")"))
    my_ip = await get_own_ip(session)
    try:
        resolver = aiohttp.AsyncResolver()  # c-ares: DNS в event loop, а не в тред-пуле
    except Exception:
        resolver = None
    sem = asyncio.Semaphore(args.concurrency)
    stats = {"done": 0, "alive": 0}
    results = await asyncio.gather(*[check_proxy(sem, p, args, my_ip, stats, resolver) for p in proxies])

    for r in results:
        e = store[store_key(r.proto, r.host, r.port)]
        e["last"] = {"alive": r.alive, "latency_ms": r.latency_ms, "cc": r.cc,
                     "checked_at": now_iso}

    live = sorted([r for r in results if r.alive], key=lambda r: (r.latency_ms or 10**9))
    print(f"[4/4] Alive: {len(live)} of {len(results)} checked" +
          (f" (dead skipped: {skipped_dead})" if skipped_dead else ""))
    by_proto = {}
    for r in live:
        by_proto[r.proto] = by_proto.get(r.proto, 0) + 1
    for proto, n in sorted(by_proto.items()):
        print(f"      {proto}: {n}")

    csv_path, json_path = write_outputs(results, Path(args.out))
    dash_path = build_dashboard(Path(args.out), live, len(results), delta,
                                len(store), now_iso)
    append_changes(Path(args.out), {"ts": now_iso, "cycle": cycle_no,
                                    "added": delta["added"], "removed": delta["removed"],
                                    "alive": len(live), "checked": len(results),
                                    "skipped_dead": skipped_dead})
    save_store(Path(args.out), store)
    print(f"      results: {csv_path}")
    print(f"               {json_path}")
    print(f"               {dash_path}")
    print_table(live, args.top)
    return results


async def main():
    args = parse_args()
    args.protocols = set(x.strip().lower() for x in args.protocols.split(",") if x.strip())
    args.sources = list(DEFAULT_SOURCES)
    if args.sources_json:
        extra = json.loads(Path(args.sources_json).read_text(encoding="utf-8"))
        args.sources.extend(extra)
        print(f"Extra sources from {args.sources_json}: {len(extra)}")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    store = load_store(out_dir)
    tracked = len([k for k in store if not k.startswith("_")])
    if tracked:
        print(f"Хранилище: {tracked} прокси с прошлого прогона")

    # Windows Proactor шумит ConnectionResetError от мёртвых прокси — глушим только его.
    loop = asyncio.get_running_loop()
    default_handler = loop.get_exception_handler()

    def quiet_reset(loop_, ctx):
        if isinstance(ctx.get("exception"), ConnectionResetError):
            return
        if default_handler:
            default_handler(loop_, ctx)
        else:
            loop_.default_exception_handler(ctx)

    loop.set_exception_handler(quiet_reset)

    if args.serve:
        httpd = start_web_server(out_dir, args.serve)
        print(f"Web UI: http://127.0.0.1:{args.serve}/dashboard.html")

    async with aiohttp.ClientSession() as session:
        while True:
            started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n=== Cycle {started} ===")
            try:
                await run_cycle(args, session, store)
            except Exception as e:
                print(f"[!] Cycle error: {type(e).__name__}: {e}")
            if args.loop <= 0:
                if args.serve:
                    print(f"Serving {out_dir} — Ctrl+C для выхода.")
                    try:
                        await asyncio.Event().wait()
                    except asyncio.CancelledError:
                        break
                break
            print(f"Next cycle in {args.loop} min. (Ctrl+C to stop)")
            try:
                await asyncio.sleep(args.loop * 60)
            except asyncio.CancelledError:
                break


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
    if getattr(sys, "frozen", False) and len(sys.argv) == 1:
        try:
            input("\n[Enter] — выход")
        except Exception:
            pass
