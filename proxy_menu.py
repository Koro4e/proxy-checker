"""proxy_menu.py — кликабельное TUI-меню для proxy_checker (textual).

Запускается автоматически, если exe/скрипт открыт без аргументов.
Кнопки мыши: скан, фоновый цикл, стоп, дашборд, папка результатов, выход.
Скан выполняется фоновым процессом; меню показывает прогресс и живой лог.
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "out"

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Footer, Header, Input, ProgressBar, RichLog, Static

CREATE_NO_WINDOW = 0x08000000


class MenuApp(App):
    TITLE = "Proxy Checker"
    SUB_TITLE = "сбор и проверка публичных прокси"

    CSS = """
    Screen { background: #0d0f13; }
    #bar { height: 3; padding: 0 1; }
    #bar Button { margin-right: 1; min-width: 12; }
    #opts { height: 3; padding: 0 1; background: #12151c; }
    #opts Static { width: auto; padding: 1 1 0 1; color: #8f97a5; }
    #opts Input { width: 12; }
    #status { height: 1; padding: 0 1; background: #12151c; color: #e8c46a; }
    #table { height: 1fr; }
    #log { height: 10; border-top: solid #242a36; background: #10141b; }
    """

    BINDINGS = [("q", "quit", "Выход (Q)")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="bar"):
            yield Button("▶ Скан", id="b-start", variant="success")
            yield Button("🔁 Цикл", id="b-loop", variant="primary")
            yield Button("⏹ Стоп", id="b-stop", variant="error")
            yield Button("📊 Дашборд", id="b-dash")
            yield Button("📁 Папка out", id="b-folder")
            yield Button("✕ Выход", id="b-quit", variant="default")
        with Horizontal(id="opts"):
            yield Static("потоки:")
            yield Input(value="500", id="i-conc")
            yield Static("таймаут, с:")
            yield Input(value="5", id="i-time")
            yield Static("цикл, мин:")
            yield Input(value="30", id="i-loop")
        yield ProgressBar(id="prog", show_eta=False)
        yield Static("⏹ простаивает — жми «▶ Скан»", id="status")
        yield DataTable(id="table")
        yield RichLog(id="log", markup=False, highlight=False, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#table", DataTable)
        table.add_columns("proto", "адрес", "ms", "cc", "город", "ISP", "https", "anon")
        table.cursor_type = "row"
        self.proc = None
        self._mtime = 0.0
        self.http_port = None
        self._start_http()
        self.set_interval(3.0, self.refresh_table)
        self.refresh_table()

    def _start_http(self) -> None:
        """Мини-сервер для дашборда: по http страница живёт в реальном времени."""
        import functools
        import http.server
        import socketserver
        import threading
        try:
            OUT_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            return
        for port in range(8619, 8631):
            try:
                handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(OUT_DIR))
                socketserver.ThreadingTCPServer.allow_reuse_address = True
                httpd = socketserver.ThreadingTCPServer(("127.0.0.1", port), handler)
                threading.Thread(target=httpd.serve_forever, daemon=True).start()
                self.http_port = port
                return
            except OSError:
                continue

    def _copy(self, text: str) -> bool:
        try:
            import pyperclip
            pyperclip.copy(text)
            return True
        except Exception:
            pass
        try:
            fn = getattr(self, "copy_to_clipboard", None)
            if fn:
                fn(text)
                return True
        except Exception:
            pass
        if os.name == "nt":
            try:
                subprocess.run(["clip"], input=text.encode("utf-16-le"), check=False)
                return True
            except Exception:
                return False
        return False

    def on_data_table_row_selected(self, event) -> None:
        """Клик (или Enter) по строке таблицы — копирует proto://адрес в буфер."""
        try:
            vals = self.query_one("#table", DataTable).get_row(event.row)
            text = f"{vals[0]}://{vals[1]}"
            ok = self._copy(text)
            self.notify(f"Скопировано: {text}" if ok else "Не удалось скопировать",
                        severity="information" if ok else "error")
        except Exception:
            pass

    # ---------- helpers ----------

    def _checker_cmd(self, extra: list) -> list:
        if getattr(sys, "frozen", False):
            base = [sys.executable]
        else:
            base = [sys.executable, str(BASE_DIR / "proxy_checker.py")]
        return base + extra + ["--out", str(OUT_DIR)]

    def _opts(self) -> tuple:
        def iv(sel: str, default: int) -> int:
            try:
                return max(1, int(self.query_one(sel, Input).value.strip()))
            except Exception:
                return default
        return iv("#i-conc", 400), iv("#i-time", 6), iv("#i-loop", 30)

    # ---------- actions ----------

    @work(exclusive=True, group="scan")
    async def run_scan(self, loop_minutes: int) -> None:
        if self.proc is not None and self.proc.returncode is None:
            self.notify("Скан уже идёт — сначала Стоп", severity="warning")
            return
        conc, tout, _ = self._opts()
        extra = ["--concurrency", str(conc), "--timeout", str(tout),
                 "--top", "30", "--skip-dead", "3", "--fast-judges", "3000"]
        if loop_minutes > 0:
            extra += ["--loop", str(loop_minutes)]
        flags = CREATE_NO_WINDOW if os.name == "nt" else 0
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        self.proc = await asyncio.create_subprocess_exec(
            *self._checker_cmd(extra),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            creationflags=flags,
        )
        log = self.query_one("#log", RichLog)
        status = self.query_one("#status", Static)
        prog = self.query_one("#prog", ProgressBar)
        mode = f"фоновый цикл каждые {loop_minutes} мин" if loop_minutes > 0 else "одиночный скан"
        status.update(f"▶ идёт: {mode} (PID {self.proc.pid})")
        log.write(f"$ {' '.join(self._checker_cmd(extra))}")
        assert self.proc.stdout is not None
        async for raw in self.proc.stdout:
            t = raw.decode("utf-8", "replace").rstrip()
            if not t:
                continue
            log.write(t)
            if "unique in lists now:" in t:
                try:
                    prog.update(total=int(t.rsplit(":", 1)[1].strip()), progress=0)
                except Exception:
                    pass
            elif "checked " in t and "alive " in t:
                try:
                    done = int(t.split("checked ")[1].split(",")[0])
                    alive = int(t.split("alive ")[1].split(")")[0].strip())
                    prog.update(progress=done)
                    status.update(f"▶ скан: проверено {done}, живых {alive}")
                except Exception:
                    pass
        rc = await self.proc.wait()
        self.proc = None
        status.update(f"⏹ процесс завершён (код {rc}) — дашборд обновлён")
        log.write(f"[процесс завершён, код {rc}]")
        self.refresh_table(force=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "b-start":
            self.run_scan(0)
        elif bid == "b-loop":
            _, _, lm = self._opts()
            self.run_scan(max(1, lm))
        elif bid == "b-stop":
            if self.proc is not None and self.proc.returncode is None:
                self.proc.terminate()
                self.query_one("#status", Static).update("⏹ останавливаю...")
            else:
                self.notify("Нечего останавливать", severity="warning")
        elif bid == "b-dash":
            p = OUT_DIR / "dashboard.html"
            if not p.exists():
                self.notify("Дашборда ещё нет — запусти скан", severity="warning")
            elif self.http_port:
                os.startfile(f"http://127.0.0.1:{self.http_port}/dashboard.html")
            else:
                os.startfile(str(p))
        elif bid == "b-folder":
            OUT_DIR.mkdir(parents=True, exist_ok=True)
            os.startfile(str(OUT_DIR))
        elif bid == "b-quit":
            if self.proc is not None and self.proc.returncode is None:
                self.proc.terminate()
            self.exit()

    # ---------- live table ----------

    def refresh_table(self, force: bool = False) -> None:
        jp = OUT_DIR / "proxies_live.json"
        try:
            m = jp.stat().st_mtime
            if not force and m == self._mtime:
                return
            self._mtime = m
            data = json.loads(jp.read_text(encoding="utf-8")).get("proxies", [])[:200]
            table = self.query_one("#table", DataTable)
            table.clear()
            for r in data:
                table.add_row(
                    r.get("proto", ""),
                    f"{r.get('host')}:{r.get('port')}",
                    r.get("latency_ms"),
                    r.get("cc") or "??",
                    (r.get("city") or "")[:12],
                    (r.get("isp") or "")[:26],
                    "да" if r.get("https_ok") else "нет",
                    r.get("anon", ""),
                )
        except Exception:
            pass


def run_menu() -> None:
    MenuApp().run()
