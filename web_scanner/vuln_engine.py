import json
import re
import time
import html
import subprocess
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
import difflib
import shutil


class VulnerabilityScanner:
    def __init__(self, payloads_path=None, session=None, sqlmap_enabled=False, quick_mode=False,
                 llm_analyzer=None, llm_max_iterations=2):
        self.session = session or requests.Session()
        if payloads_path:
            with open(payloads_path, "r", encoding="utf-8") as f:
                self.payloads = json.load(f)
        else:
            self.payloads = {}
        self._request_cache = {}
        self._cache_enabled = True
        self.sqlmap_enabled = sqlmap_enabled
        self.quick_mode = quick_mode
        self.llm = llm_analyzer
        self.llm_max_iter = llm_max_iterations
        self.sqli_error_re = [re.compile(pat, re.I) for pat in [
            r'SQL syntax', r'mysql_fetch', r'ORA-', r'you have an error in your SQL'
        ]]
        self.traversal_re = re.compile(
            r'No such file or directory|failed to open stream|open_basedir restriction|Warning|'
            r'Root directory|etc/passwd|root:x:0:0|root:\/bin\/bash', re.I
        )
        self.cmd_evidence_re = re.compile(
            r'uid=|command not found|sh:|bash:|INJECTED|root@|icmp_seq|bytes from|ttl=|time=', re.I
        )
        self.cmd_false_positive_re = re.compile(
            r'failed to open stream|failed opening|include\(\):|warning: include\(\)|no such file or directory', re.I
        )

    def _is_reflected(self, resp_text, marker):
        if not resp_text or not marker:
            return False
        if marker in resp_text:
            return True
        escaped = html.escape(marker)
        if escaped in resp_text:
            return True
        return False

    def clear_cache(self):
        self._request_cache.clear()

    def _make_cache_key(self, url, method="GET", params=None, data=None):
        params_key = tuple(sorted((params or {}).items())) if params else None
        data_key = tuple(sorted((data or {}).items())) if data else None
        return (method.upper(), url, params_key, data_key)

    def _fetch_page(self, url, params=None, data=None, method="GET", timeout=10, session=None, use_cache=True):
        session = session or self.session
        key = self._make_cache_key(url, method, params, data)
        if use_cache and self._cache_enabled and key in self._request_cache:
            return self._request_cache[key]

        try:
            if method.upper() == "POST":
                response = session.post(url, params=params, data=data, timeout=timeout, verify=False)
            else:
                response = session.get(url, params=params, timeout=timeout, verify=False)
            if use_cache and self._cache_enabled and response is not None:
                self._request_cache[key] = response
            return response
        except Exception:
            return None

    def extract_hidden_inputs(self, url, params=None, data=None, method="GET"):
        hidden = {}
        r = self._fetch_page(url, params=params if method.upper() == "GET" else None,
                             data=data if method.upper() == "POST" else None,
                             method=method, timeout=10)
        if not r or not r.text:
            return hidden
        soup = BeautifulSoup(r.text, 'html.parser')
        form = soup.find('form')
        if not form:
            return hidden
        for inp in form.find_all('input'):
            if inp.get('type', '').lower() != 'hidden':
                continue
            name = inp.get('name')
            if not name:
                continue
            hidden[name] = inp.get('value', '')
        return hidden

    def test_sqli(self, url, param_name=None, method='GET', params=None, data=None):
        findings = []

        def send_with_param(base, params=None, data=None, timeout=10):
            return self._fetch_page(base, params=params, data=data, method=method, timeout=timeout)

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        target_base = parsed.scheme + '://' + parsed.netloc + parsed.path

        base_params = params.copy() if params is not None else ({k: v[0] for k, v in qs.items()} if qs else {})
        base_data = data.copy() if data is not None else {}

        if params is not None and method.upper() == 'GET':
            base_params.update(self.extract_hidden_inputs(url, params=base_params, method='GET'))
        elif data is not None and method.upper() == 'POST':
            base_data.update(self.extract_hidden_inputs(url, data=base_data, method='POST'))

        param_names = [param_name] if param_name else (list(base_params.keys()) if base_params else (list(base_data.keys()) if base_data else []))
        if not param_names:
            return findings

        boolean_payloads = ["' AND 1=1 -- ", "' AND 1=2 -- ", '" AND 1=1 -- ', '" AND 1=2 -- ']
        time_payloads = [] if self.quick_mode else ["' OR sleep(5)-- ", '" OR sleep(5)-- ', "'; WAITFOR DELAY '0:0:5'--"]
        numeric_boolean = ['1 OR 1=1', '1 AND 1=2']
        numeric_time = [] if self.quick_mode else ['1 OR SLEEP(5)', '1; SELECT SLEEP(5)']
        union_payloads = [] if self.quick_mode else ["' UNION SELECT NULL-- ", "' UNION SELECT NULL,NULL-- "]

        def response_reflects_text(response, payloads):
            if not response or not response.text:
                return False
            return any(self._is_reflected(response.text, payload) for payload in payloads)

        for pname in param_names:
            current_params = base_params.copy() if method.upper() == 'GET' else None
            current_data = base_data.copy() if method.upper() == 'POST' else None
            if pname:
                if method.upper() == 'GET' and pname not in current_params:
                    current_params[pname] = '1'
                if method.upper() == 'POST' and pname not in current_data:
                    current_data[pname] = '1'

            baseline = send_with_param(target_base, params=current_params, data=current_data)
            base_time = baseline.elapsed.total_seconds() if baseline and hasattr(baseline, 'elapsed') else 0

            score = 0
            evidence = []

            for p in self.payloads.get('sqli', []):
                params_copy = current_params.copy() if current_params is not None else None
                data_copy = current_data.copy() if current_data is not None else None
                if pname:
                    if method.upper() == 'GET':
                        params_copy[pname] = p
                    else:
                        data_copy[pname] = p
                r = send_with_param(target_base, params=params_copy, data=data_copy)
                if not r:
                    continue
                error_matched = False
                for pat_re in self.sqli_error_re:
                    if pat_re.search(r.text):
                        score += 3
                        evidence.append({'type': 'error-based', 'payload': p, 'match': pat_re.pattern})
                        error_matched = True
                        break
                if not error_matched and baseline:
                    len_diff = abs(len(r.text) - len(baseline.text))
                    if len_diff > max(50, len(baseline.text) * 0.2):
                        ratio = difflib.SequenceMatcher(a=baseline.text, b=r.text).ratio()
                        if ratio < 0.96 and not self._is_reflected(r.text, p):
                            score += 2
                            evidence.append({'type': 'structural-change', 'payload': p,
                                             'len_diff': len_diff, 'ratio': round(ratio, 4)})
                if score >= 4:
                    break

            if score < 4 and pname and baseline:
                for t in range(0, len(boolean_payloads), 2):
                    p_true = boolean_payloads[t]
                    p_false = boolean_payloads[t + 1]
                    params_true = current_params.copy() if current_params is not None else None
                    params_false = current_params.copy() if current_params is not None else None
                    data_true = current_data.copy() if current_data is not None else None
                    data_false = current_data.copy() if current_data is not None else None
                    if method.upper() == 'GET':
                        params_true[pname] = p_true
                        params_false[pname] = p_false
                    else:
                        data_true[pname] = p_true
                        data_false[pname] = p_false
                    r_true = send_with_param(target_base, params=params_true, data=data_true)
                    r_false = send_with_param(target_base, params=params_false, data=data_false)
                    if not r_true or not r_false:
                        continue
                    if response_reflects_text(r_true, [p_true, p_false]) or response_reflects_text(r_false, [p_true, p_false]):
                        continue
                    ratio = difflib.SequenceMatcher(a=r_true.text, b=r_false.text).ratio()
                    if ratio < 0.995:
                        score += 2
                        evidence.append({'type': 'boolean-based', 'param': pname, 'ratio': ratio})
                        break

            if score < 4 and pname and baseline:
                for p in time_payloads:
                    params_copy = current_params.copy() if current_params is not None else None
                    data_copy = current_data.copy() if current_data is not None else None
                    if method.upper() == 'GET':
                        params_copy[pname] = p
                    else:
                        data_copy[pname] = p
                    t0 = time.time()
                    r = send_with_param(target_base, params=params_copy, data=data_copy, timeout=15)
                    t1 = time.time()
                    if r and not response_reflects_text(r, [p]):
                        delta = t1 - t0
                        if delta - base_time > 2.0:
                            score += 4
                            evidence.append({'type': 'time-based', 'param': pname, 'delay': delta})
                            break

            base_val = None
            if pname and method.upper() == 'GET':
                base_val = current_params.get(pname)
            elif pname and method.upper() == 'POST':
                base_val = current_data.get(pname)
            is_numeric = False
            try:
                if base_val is not None and str(base_val).lstrip('-').isdigit():
                    is_numeric = True
            except Exception:
                is_numeric = False

            if score < 4 and is_numeric:
                for nb in numeric_boolean:
                    params_copy = current_params.copy() if current_params is not None else None
                    data_copy = current_data.copy() if current_data is not None else None
                    if method.upper() == 'GET':
                        params_copy[pname] = nb
                    else:
                        data_copy[pname] = nb
                    r_nb = send_with_param(target_base, params=params_copy, data=data_copy)
                    if not r_nb or not baseline:
                        continue
                    ratio = difflib.SequenceMatcher(a=baseline.text, b=r_nb.text).ratio()
                    if ratio < 0.99:
                        score += 2
                        evidence.append({'type': 'numeric-boolean', 'param': pname, 'payload': nb, 'ratio': ratio})
                        break

            if score < 4 and is_numeric:
                for nt in numeric_time:
                    params_copy = current_params.copy() if current_params is not None else None
                    data_copy = current_data.copy() if current_data is not None else None
                    if method.upper() == 'GET':
                        params_copy[pname] = nt
                    else:
                        data_copy[pname] = nt
                    t0 = time.time()
                    r_nt = send_with_param(target_base, params=params_copy, data=data_copy, timeout=15)
                    t1 = time.time()
                    if r_nt and not response_reflects_text(r_nt, [nt]):
                        delta = t1 - t0
                        if delta - base_time > 2.5:
                            score += 4
                            evidence.append({'type': 'numeric-time', 'param': pname, 'payload': nt, 'delay': delta})
                            break

            if score < 4 and pname:
                for up in union_payloads:
                    params_copy = current_params.copy() if current_params is not None else None
                    data_copy = current_data.copy() if current_data is not None else None
                    if method.upper() == 'GET':
                        params_copy[pname] = up
                    else:
                        data_copy[pname] = up
                    r = send_with_param(target_base, params=params_copy, data=data_copy)
                    if r and baseline:
                        if re.search(r"<table|<th|column", r.text, re.I) and not re.search(r"<table|<th|column", baseline.text, re.I):
                            score += 3
                            evidence.append({'type': 'union-based', 'payload': up})
                            break

            if score >= 4:
                trigger_payload = evidence[0].get("payload", "") if evidence else ""
                findings.append({'type': 'sqli', 'url': url, 'param': pname, 'score': score,
                                 'payload': trigger_payload, 'evidence': evidence})

        if not findings and self.sqlmap_enabled:
            sqlmap_path = shutil.which('sqlmap')
            if sqlmap_path:
                for pname in param_names:
                    try:
                        cmd = [sqlmap_path, '-u', url, '-p', pname, '--batch', '--level', '1', '--risk', '1']
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                        out = proc.stdout + proc.stderr
                        if 'is vulnerable' in out.lower() or ('parameter' in out.lower() and 'is vulnerable' in out.lower()):
                            findings.append({'type': 'sqli-sqlmap', 'url': url, 'param': pname, 'evidence': out[:200]})
                            break
                    except Exception:
                        continue

        return findings

    def test_xss(self, url, param_name=None, method='GET', params=None, data=None):
        findings = []
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        target_base = parsed.scheme + '://' + parsed.netloc + parsed.path
        base_params = params.copy() if params is not None else ({k: v[0] for k, v in qs.items()} if qs else {})
        base_data = data.copy() if data is not None else {}

        def detect_dom_xss(html_text):
            if not html_text:
                return None
            soup = BeautifulSoup(html_text, 'html.parser')
            for script in soup.find_all('script'):
                text = script.string or ''
                if 'document.location.href' in text or 'location.href' in text or 'window.location' in text:
                    match = re.search(r'indexOf\(["\']([^=]+)=', text)
                    if match and ('document.write' in text or 'innerHTML' in text or 'write(' in text):
                        return match.group(1)
            return None

        def send_with_param(base, params=None, data=None):
            return self._fetch_page(base, params=params, data=data, method='POST' if method.upper() == 'POST' else 'GET', timeout=8)

        fetched_page = None
        if not base_params and not base_data:
            page_resp = self._fetch_page(target_base, timeout=8)
            fetched_page = page_resp.text if page_resp else ''
            dom_param = detect_dom_xss(fetched_page)
            if dom_param:
                findings.append({'type': 'xss', 'payload': 'dom', 'url': url, 'param': dom_param})
                return findings

        for p in self.payloads.get('xss', []):
            marker = p
            test_targets = []
            if param_name:
                if method.upper() == 'GET':
                    current = base_params.copy()
                    current[param_name] = p
                    test_targets.append((target_base, current, None, param_name))
                else:
                    current = base_data.copy()
                    current[param_name] = p
                    test_targets.append((target_base, None, current, param_name))
            elif base_params:
                for key in base_params:
                    current = base_params.copy()
                    current[key] = p
                    test_targets.append((target_base, current, None, key))
            elif base_data:
                for key in base_data:
                    current = base_data.copy()
                    current[key] = p
                    test_targets.append((target_base, None, current, key))
            else:
                continue

            for base, params_map, data_map, param_key in test_targets:
                try:
                    r = send_with_param(base, params=params_map, data=data_map)
                    if r and self._is_reflected(r.text, marker):
                        findings.append({'type': 'xss', 'payload': p, 'url': r.url, 'param': param_key})
                        break
                    if method.upper() == 'POST' and r:
                        follow = self._fetch_page(target_base, timeout=8)
                        if follow and self._is_reflected(follow.text, marker):
                            findings.append({'type': 'xss', 'payload': p, 'url': target_base, 'param': param_key, 'stored': True})
                            break
                except Exception:
                    continue
            if findings:
                break

        if not findings and base_params and not base_data:
            page_text = fetched_page if fetched_page is not None else ''
            if not page_text:
                page_resp = self._fetch_page(target_base, timeout=8)
                page_text = page_resp.text if page_resp else ''
            dom_param = detect_dom_xss(page_text)
            if dom_param and dom_param in base_params:
                findings.append({'type': 'xss', 'payload': 'dom', 'url': url, 'param': dom_param})

        return findings

    def test_path_traversal(self, url):
        findings = []
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        target_base = parsed.scheme + '://' + parsed.netloc + parsed.path
        base_params = {k: v[0] for k, v in qs.items()} if qs else {}
        baseline = self._fetch_page(target_base, params=base_params if base_params else None, timeout=8)
        baseline_text = baseline.text if baseline else ''

        for p in self.payloads.get('traversal', []):
            if base_params:
                for key in base_params:
                    current_params = base_params.copy()
                    current_params[key] = p
                    try:
                        r = self._fetch_page(target_base, params=current_params, timeout=8)
                        if not r:
                            continue
                        if self.traversal_re.search(r.text):
                            findings.append({'type': 'path_traversal', 'payload': p, 'url': r.url, 'param': key, 'status_code': r.status_code})
                        elif baseline and r.status_code == 200 and abs(len(r.text) - len(baseline_text)) > 200:
                            findings.append({'type': 'path_traversal', 'payload': p, 'url': r.url, 'param': key, 'status_code': r.status_code, 'length_diff': len(r.text) - len(baseline_text)})
                    except Exception:
                        continue
            else:
                target = urljoin(url, p)
                try:
                    r = self._fetch_page(target, timeout=8)
                    if not r:
                        continue
                    if self.traversal_re.search(r.text):
                        findings.append({'type': 'path_traversal', 'payload': p, 'url': target, 'status_code': r.status_code})
                    elif baseline and r.status_code == 200 and abs(len(r.text) - len(baseline_text)) > 200:
                        findings.append({'type': 'path_traversal', 'payload': p, 'url': target, 'status_code': r.status_code, 'length_diff': len(r.text) - len(baseline_text)})
                except Exception:
                    continue
        return findings

    def test_command_injection(self, url, param_name=None, method='GET', params=None, data=None):
        findings = []
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        target_base = parsed.scheme + '://' + parsed.netloc + parsed.path
        base_params = params.copy() if params is not None else ({k: v[0] for k, v in qs.items()} if qs else {})
        base_data = data.copy() if data is not None else {}

        def is_cmd_evidence(text, payload=None):
            if not text:
                return False
            if self.cmd_false_positive_re.search(text):
                return False
            if payload and 'echo INJECTED' in payload and 'INJECTED' in text:
                return True
            return self.cmd_evidence_re.search(text) is not None

        for p in self.payloads.get('cmd', []):
            if param_name or base_params:
                if not param_name and base_params:
                    for key in base_params:
                        current = base_params.copy()
                        current[key] = p
                        try:
                            r = self._fetch_page(target_base, params=current, data=None, method='GET', timeout=8)
                            if r and is_cmd_evidence(r.text, p):
                                findings.append({'type': 'cmd_injection', 'payload': p, 'url': r.url, 'param': key})
                                break
                        except Exception:
                            continue
                else:
                    current_params = base_params.copy() if method.upper() == 'GET' else None
                    current_data = base_data.copy() if method.upper() == 'POST' else None
                    if param_name:
                        if method.upper() == 'GET':
                            current_params[param_name] = p
                        else:
                            current_data[param_name] = p
                    try:
                        r = self._fetch_page(target_base, params=current_params, data=current_data, method=method.upper(), timeout=8)
                        if r and is_cmd_evidence(r.text, p):
                            findings.append({'type': 'cmd_injection', 'payload': p, 'url': r.url, 'param': param_name})
                    except Exception:
                        continue
            else:
                target = urljoin(url, p)
                try:
                    r = self._fetch_page(target, timeout=8)
                    if r and is_cmd_evidence(r.text, p):
                        findings.append({'type': 'cmd_injection', 'payload': p, 'url': target})
                except Exception:
                    continue
        return findings

    # -----------------------------------------------------------------
    # LLM 集成方法
    # -----------------------------------------------------------------

    def _llm_send_payload(self, url, param_name, payload, method, base_params, base_data):
        """发送单个 payload 并返回 (response, elapsed)。"""
        parsed = urlparse(url)
        target_base = parsed.scheme + '://' + parsed.netloc + parsed.path
        params_copy = base_params.copy() if base_params is not None else None
        data_copy = base_data.copy() if base_data is not None else None
        if param_name:
            if method.upper() == 'GET' and params_copy is not None:
                params_copy[param_name] = payload
            elif data_copy is not None:
                data_copy[param_name] = payload
        t0 = time.time()
        r = self._fetch_page(target_base, params=params_copy, data=data_copy,
                             method=method, timeout=10)
        elapsed = time.time() - t0
        return r, elapsed

    def _llm_analyze_finding(self, finding):
        """对一条规则 finding 做 LLM 二次确认，返回 (confirmed: bool, reason: str)。

        会重放 payload 以获取漏洞触发的真实响应，而非裸 URL 的正常页面。
        """
        if not self.llm or not self.llm.available:
            return True, ""
        try:
            f_url = finding.get("url", "")
            f_param = finding.get("param", "")
            f_payload = finding.get("payload", "")
            # 如果顶层没有 payload，尝试从 evidence 中提取
            if not f_payload:
                for ev in finding.get("evidence", []):
                    if isinstance(ev, dict) and ev.get("payload"):
                        f_payload = ev.get("payload")
                        break

            if f_param and f_payload:
                parsed = urlparse(f_url)
                target_base = parsed.scheme + "://" + parsed.netloc + parsed.path
                qs = parse_qs(parsed.query)
                params = {k: v[0] for k, v in qs.items()} if qs else {}
                params[f_param] = f_payload
                r = self._fetch_page(target_base, params=params, timeout=8)
            else:
                r = self._fetch_page(f_url, timeout=8)

            if not r:
                return True, ""
            result = self.llm.analyze_response(
                url=f_url,
                payload=f_payload,
                param=f_param,
                vuln_type=finding.get("type", ""),
                status_code=r.status_code,
                response_body=r.text or "",
            )
            finding["llm_analysis"] = result
            finding["llm_reason"] = result.get("reason", "")
            return result.get("triggered", True), result.get("reason", "")
        except Exception:
            return True, ""

    def _llm_scan_param(self, url, param_name, method, base_params, base_data, vuln_type):
        """LLM 驱动的单参数扫描：基础payload → LLM分析 → 优化payload循环。

        返回该参数上 LLM 确认的 findings 列表。
        """
        findings = []
        if not self.llm or not self.llm.available:
            return findings

        initial_payloads = self.payloads.get(vuln_type, [])[:4]
        if not initial_payloads:
            return findings

        failed_attempts = []
        tried_payloads = set()

        current_payloads = list(initial_payloads)

        for iteration in range(self.llm_max_iter + 1):
            for p in current_payloads:
                if p in tried_payloads:
                    continue
                tried_payloads.add(p)
                r, elapsed = self._llm_send_payload(url, param_name, p, method,
                                                    base_params, base_data)
                if not r:
                    continue
                result = self.llm.analyze_response(
                    url=url, payload=p, param=param_name,
                    vuln_type=vuln_type, status_code=r.status_code,
                    response_body=r.text or "",
                )
                if result.get("triggered"):
                    findings.append({
                        "type": vuln_type,
                        "url": url,
                        "param": param_name,
                        "payload": p,
                        "llm_confidence": result.get("confidence", 1.0),
                        "llm_reason": result.get("reason", ""),
                        "evidence": result.get("evidence", []),
                        "llm_generated": iteration > 0,
                    })
                    return findings  # 找到一个就停
                else:
                    failed_attempts.append({
                        "payload": p,
                        "reason": result.get("reason", "No specific reason"),
                    })

            if iteration >= self.llm_max_iter:
                break

            new_payloads = self.llm.generate_payloads(
                vuln_type=vuln_type,
                url=url,
                param=param_name,
                failed_attempts=failed_attempts[-6:],  # 最近 6 次失败
            )
            current_payloads = [p for p in new_payloads if p not in tried_payloads]
            if not current_payloads:
                break

        return findings

    def scan_endpoints(self, endpoints, test_types=None):
        if test_types is None:
            test_types = {'sqli', 'xss', 'path_traversal', 'cmd'}
        else:
            test_types = set(test_types)
        results = []

        # 用于 LLM 探索：记录每个 endpoint 的表单参数信息
        _llm_explore_targets = []  # (url, method, params, data, visible_keys)

        for ep in endpoints:
            try:
                r = self._fetch_page(ep, timeout=6)
                content_type = r.headers.get('content-type', '') if r else ''
                if 'html' not in content_type.lower():
                    continue
                html = r.text if r else None
            except Exception:
                html = None

            if html:
                try:
                    soup = BeautifulSoup(html, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        action = form.get('action') or ep
                        method = (form.get('method') or 'get').lower()
                        visible_fields = {}
                        hidden_fields = {}
                        submit_fields = {}
                        for inp in form.find_all(['input', 'textarea', 'select']):
                            name = inp.get('name')
                            if not name:
                                continue
                            field_type = inp.get('type', '').lower()
                            if inp.name == 'textarea':
                                field_type = 'textarea'
                            if inp.name == 'select':
                                field_type = 'select'
                            value = inp.get('value')
                            if value is None:
                                if field_type in ('number', 'range'):
                                    value = '1'
                                elif field_type == 'select':
                                    option = inp.find('option', selected=True) or inp.find('option')
                                    value = option.get('value') if option and option.get('value') is not None else ''
                                elif field_type == 'email':
                                    value = 'test@example.com'
                                elif field_type == 'tel':
                                    value = '1234567890'
                                elif field_type == 'url':
                                    value = 'http://example.com'
                                elif field_type == 'password':
                                    value = 'Password123'
                                elif re.search(r'\b(id|num|count|age|page|limit|year|month|amount|qty|size)\b', name, re.I):
                                    value = '1'
                                else:
                                    value = 'test'
                            if field_type == 'hidden':
                                hidden_fields[name] = value
                            elif field_type in ('submit', 'button', 'reset'):
                                submit_fields[name] = value
                            else:
                                visible_fields[name] = value

                        if not visible_fields:
                            continue

                        full_action = urljoin(ep, action)
                        if method == 'post':
                            payload_template = {**hidden_fields, **submit_fields, **visible_fields}
                            for pname in visible_fields.keys():
                                data = payload_template.copy()
                                if 'sqli' in test_types:
                                    results.extend(self.test_sqli(full_action, param_name=pname, method='POST', data=data))
                                if 'cmd' in test_types:
                                    results.extend(self.test_command_injection(full_action, param_name=pname, method='POST', data=data))
                                if 'xss' in test_types:
                                    results.extend(self.test_xss(full_action, param_name=pname, method='POST', data=data))
                            _llm_explore_targets.append((full_action, 'POST', None, payload_template, list(visible_fields.keys())))
                        else:
                            params_template = {**hidden_fields, **submit_fields, **visible_fields}
                            for pname in visible_fields.keys():
                                params = params_template.copy()
                                if 'sqli' in test_types:
                                    results.extend(self.test_sqli(full_action, param_name=pname, params=params))
                                if 'xss' in test_types:
                                    results.extend(self.test_xss(full_action, param_name=pname, params=params))
                            _llm_explore_targets.append((full_action, 'GET', params_template, None, list(visible_fields.keys())))
                except Exception:
                    pass

            # also test the endpoint directly
            if 'sqli' in test_types:
                results.extend(self.test_sqli(ep))
            if 'xss' in test_types:
                results.extend(self.test_xss(ep))
            if 'path_traversal' in test_types:
                results.extend(self.test_path_traversal(ep))
            if 'cmd' in test_types:
                results.extend(self.test_command_injection(ep))

        # ---- LLM 增强阶段 ----
        if self.llm and self.llm.available:
            # Phase A: LLM 二次确认已有 findings（去误报）
            confirmed = []
            for f in results:
                triggered, reason = self._llm_analyze_finding(f)
                if triggered or triggered is None:  # None = LLM 不确定，保留
                    confirmed.append(f)
            results = confirmed

            # Phase B: LLM 探索 — 对未见漏洞的参数用 LLM 动态生成 payload
            seen_params = set()
            for f in results:
                key = (f.get('url', ''), f.get('param', ''), f.get('type', ''))
                seen_params.add(key)

            for url, method, params, data, pkeys in _llm_explore_targets:
                for vuln_type in ['sqli', 'xss', 'cmd']:
                    if vuln_type not in test_types:
                        continue
                    for pname in pkeys:
                        if (url, pname, vuln_type) in seen_params:
                            continue
                        llm_findings = self._llm_scan_param(
                            url, pname, method, params, data, vuln_type)
                        results.extend(llm_findings)
                        for lf in llm_findings:
                            seen_params.add((lf.get('url', ''), lf.get('param', ''), lf.get('type', '')))

        return results
