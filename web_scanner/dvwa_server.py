"""
DVWA 模拟服务 — 可切换 low / medium / high 安全等级。
每个等级包含: SQLi (GET), XSS (Reflected + Stored), Command Injection, Path Traversal.

启动方式: python dvwa_server.py
安全等级通过 Cookie security=low|medium|high 切换。
"""

import os
import subprocess
import html as html_mod
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from socketserver import ThreadingMixIn


PORT = 8888


class ThreadingServer(ThreadingMixIn, HTTPServer):
    """多线程 HTTP Server，避免并发阻塞。"""
    daemon_threads = True


class DVWAHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    # ----------------------------------------------------------------
    # 路由
    # ----------------------------------------------------------------
    def _handle(self, method):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)
        level = self._get_level()

        if path == "" or path == "/":
            self._serve_home(level)
        elif path == "/set_level":
            self._set_level_page()
        elif path == "/vulnerabilities/sqli":
            self._sqli(qs, level)
        elif path == "/vulnerabilities/xss_r":
            self._xss_reflected(qs, level)
        elif path == "/vulnerabilities/xss_s":
            body = self._get_body() if method == "POST" else {}
            self._xss_stored(qs, body, level, method)
        elif path == "/vulnerabilities/exec":
            self._cmd_injection(qs, level)
        elif path == "/vulnerabilities/fi":
            self._file_inclusion(qs, level)
        else:
            self._404()

    # ----------------------------------------------------------------
    # 安全等级
    # ----------------------------------------------------------------
    def _get_level(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("security="):
                return part.split("=", 1)[1].strip()
        return "low"

    def _set_level_page(self):
        qs = parse_qs(urlparse(self.path).query)
        new_level = qs.get("level", ["low"])[0]
        if new_level not in ("low", "medium", "high"):
            new_level = "low"
        self.send_response(302)
        self.send_header("Set-Cookie", f"security={new_level}; Path=/")
        self.send_header("Location", "/")
        self.end_headers()

    def _serve_home(self, level):
        body = f"""<html><head><meta charset="utf-8"><title>DVWA Test</title></head><body>
<h1>DVWA Simulation — Security: <span style="color:{'green' if level=='low' else 'orange' if level=='medium' else 'red'}">{level.upper()}</span></h1>
<p>Switch level:</p>
<ul>
<li><a href="/set_level?level=low">Low</a></li>
<li><a href="/set_level?level=medium">Medium</a></li>
<li><a href="/set_level?level=high">High</a></li>
</ul>
<hr>
<h2>Test Pages</h2>
<ul>
<li><a href="/vulnerabilities/sqli?id=1">SQL Injection</a> — ?id=</li>
<li><a href="/vulnerabilities/xss_r?name=Guest">Reflected XSS</a> — ?name=</li>
<li><a href="/vulnerabilities/xss_s">Stored XSS</a> — POST form</li>
<li><a href="/vulnerabilities/exec?cmd=127.0.0.1">Command Injection</a> — ?cmd=</li>
<li><a href="/vulnerabilities/fi?page=include.php">File Inclusion</a> — ?page=</li>
</ul>
</body></html>"""
        self._respond(200, body)

    # ----------------------------------------------------------------
    # SQL Injection (GET, param: id)
    # ----------------------------------------------------------------
    def _sqli(self, qs, level):
        user_id_raw = qs.get("id", ["1"])[0]

        if level == "low":
            # 直接拼接 SQL — 漏洞明显
            query = f"SELECT first_name, last_name FROM users WHERE user_id = {user_id_raw}"
            # 模拟错误回显
            if "'" in user_id_raw or '"' in user_id_raw:
                self._respond(200, f"<pre>You have an error in your SQL syntax near '{user_id_raw}' at line 1</pre><br>Query: {query}")
                return
            self._respond(200, f"<pre>ID: {user_id_raw}\nFirst name: admin\nSurname: admin</pre><br><i>Query: {query}</i>")
        elif level == "medium":
            # mysql_real_escape_string 风格 — 部分防护
            escaped = user_id_raw.replace("'", "\\'").replace('"', '\\"')
            query = f"SELECT first_name, last_name FROM users WHERE user_id = {escaped}"
            # 数字型绕过仍然可行
            if " OR " in user_id_raw.upper() or " UNION " in user_id_raw.upper():
                self._respond(200, f"<pre>ID: {escaped}\nFirst name: admin\nSurname: admin\nFirst name: Gordon\nSurname: Brown</pre><br><i>Query: {query}</i>")
            elif "'" in user_id_raw:
                self._respond(200, f"<pre>No results</pre><br><i>Query: {query}</i>")
            else:
                self._respond(200, f"<pre>ID: {escaped}\nFirst name: admin\nSurname: admin</pre><br><i>Query: {query}</i>")
        else:  # high
            # 预处理语句模拟 — 数字型校验
            if not user_id_raw.lstrip("-").isdigit():
                self._respond(200, "<pre>Invalid ID format. Only integers allowed.</pre>")
            else:
                self._respond(200, f"<pre>ID: {user_id_raw}\nFirst name: admin\nSurname: admin</pre>")

    # ----------------------------------------------------------------
    # Reflected XSS (GET, param: name)
    # ----------------------------------------------------------------
    def _xss_reflected(self, qs, level):
        name = qs.get("name", ["Guest"])[0]

        if level == "low":
            body = f"<h1>Hello, {name}</h1>"
        elif level == "medium":
            # 过滤 <script> 但不过滤其他向量
            escaped = name.replace("<script>", "").replace("</script>", "")
            body = f"<h1>Hello, {html_mod.escape(escaped)}</h1>"
        else:  # high
            body = f"<h1>Hello, {html_mod.escape(name)}</h1>"

        self._respond(200, f"<html><body>{body}</body></html>")

    # ----------------------------------------------------------------
    # Stored XSS (POST form)
    # ----------------------------------------------------------------
    _stored_messages = []  # 类级别存储

    def _xss_stored(self, qs, body_params, level, method):
        if method == "POST" and body_params.get("txtName") and body_params.get("mtxMessage"):
            name = body_params.get("txtName", [""])[0]
            msg = body_params.get("mtxMessage", [""])[0]
            if level == "medium":
                name = name.replace("<script>", "").replace("</script>", "")
                msg = msg.replace("<script>", "").replace("</script>", "")
            elif level == "high":
                name = html_mod.escape(name)
                msg = html_mod.escape(msg)
            self._stored_messages.append((name, msg))

        # show stored
        messages_html = ""
        for n, m in self._stored_messages:
            messages_html += f"<div><strong>{n}</strong>: {m}</div>"
        form = """<form method="post">
<input name="txtName" placeholder="Name"><br>
<textarea name="mtxMessage" placeholder="Message"></textarea><br>
<button type="submit">Sign Guestbook</button>
</form>"""
        self._respond(200, f"<html><body><h1>Guestbook</h1>{messages_html}<hr>{form}</body></html>")

    def _run_cmd(self, cmd):
        """执行命令（仅本地测试环境），返回输出。"""
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
            out = r.stdout + r.stderr
            return out if out.strip() else "(no output)"
        except subprocess.TimeoutExpired:
            return "(timeout)"
        except Exception as e:
            return f"(error: {e})"

    def _cmd_injection(self, qs, level):
        target = qs.get("cmd", ["127.0.0.1"])[0]

        if level == "low":
            output = self._run_cmd(f"echo Target: {target} && echo INJECTED")
            self._respond(200, f"<pre>{output}</pre>")
        elif level == "medium":
            filtered = target.replace("&&", "").replace(";", "")
            output = self._run_cmd(f"echo Target: {filtered} && echo INJECTED")
            self._respond(200, f"<pre>{output}</pre>")
        else:  # high
            import re
            if re.match(r"^[\d.a-zA-Z\-]+$", target):
                output = self._run_cmd(f"echo Target: {target}")
                self._respond(200, f"<pre>{output}</pre>")
            else:
                self._respond(200, "<pre>Invalid target. Only IP/hostname characters allowed.</pre>")

    # ----------------------------------------------------------------
    # File Inclusion / Path Traversal (GET, param: page)
    # ----------------------------------------------------------------
    def _file_inclusion(self, qs, level):
        page = qs.get("page", ["include.php"])[0]

        if level == "low":
            # 直接拼接 — 路径遍历可行
            file_path = os.path.join(os.path.dirname(__file__), page)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self._respond(200, f"<pre>{html_mod.escape(content)}</pre>")
            except Exception:
                self._respond(200, f"<pre>Warning: include({page}): failed to open stream: No such file or directory</pre>")
        elif level == "medium":
            # 替换 ../ 但可双重编码绕过
            filtered = page.replace("../", "").replace("..\\", "")
            file_path = os.path.join(os.path.dirname(__file__), filtered)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self._respond(200, f"<pre>{html_mod.escape(content)}</pre>")
            except Exception:
                self._respond(200, f"<pre>Warning: include({filtered}): failed to open stream: No such file or directory</pre>")
        else:  # high
            # 白名单
            allowed = {"include.php", "file1.php", "file2.php", "file3.php"}
            if page in allowed:
                file_path = os.path.join(os.path.dirname(__file__), page)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    self._respond(200, f"<pre>{html_mod.escape(content)}</pre>")
                except Exception:
                    self._respond(200, f"<pre>ERROR: File not found.</pre>")
            else:
                self._respond(200, "<pre>ERROR: File not found.</pre>")

    # ----------------------------------------------------------------
    # 工具方法
    # ----------------------------------------------------------------
    def _get_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8")
            return parse_qs(raw)
        except Exception:
            return {}

    def _respond(self, code, body):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass

    def _404(self):
        self._respond(404, "<h1>404 Not Found</h1>")

    def log_message(self, format, *args):
        pass  # 静默日志


if __name__ == "__main__":
    print(f"DVWA 模拟靶场启动: http://localhost:{PORT}")
    print("切换等级: /set_level?level=low  |  /set_level?level=medium  |  /set_level?level=high")
    server = ThreadingServer(("0.0.0.0", PORT), DVWAHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
