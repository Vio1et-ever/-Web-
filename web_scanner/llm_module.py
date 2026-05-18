"""
LLM 驱动的漏洞分析模块 — 替换原有 sklearn ML 误报过滤。

能力:
  - analyze_response:  分析 HTTP 响应，判断漏洞是否触发
  - generate_payloads: 基于失败原因动态生成优化 payload
  - generate_patch:    为已确认漏洞生成修复补丁
"""
import json
import re
import os


class LLMAnalyzer:
    def __init__(self, api_key=None, base_url=None, model="gpt-4o"):
        api_key = api_key or os.environ.get("OPENAI_API_KEY")
        base_url = base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.model = model
        self.available = False
        self._client = None
        self._init_error = None
        if not api_key:
            self._init_error = "未配置 API Key（通过 --llm-api-key 参数或 OPENAI_API_KEY 环境变量）"
            return
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key=api_key, base_url=base_url)
            self.available = True
        except ImportError:
            self._init_error = "缺少 openai 包，请执行: pip install openai"
        except Exception as e:
            self._init_error = f"LLM 客户端初始化失败: {e}"

    # -----------------------------------------------------------------
    # 公共接口
    # -----------------------------------------------------------------

    def analyze_response(self, url, payload, param, vuln_type, status_code, response_body):
        """分析单次 payload 回显，返回 {triggered, confidence, reason, evidence}。

        当 LLM 不可用或调用失败时返回 triggered=None 表示不确定。
        """
        if not self.available:
            return {"triggered": None, "confidence": 0.0, "reason": "LLM unavailable", "evidence": []}

        snippet = _truncate_response(response_body, 3000)
        prompt = _build_analysis_prompt(url, payload, param, vuln_type, status_code, snippet)
        raw = self._call_llm(prompt)
        return _parse_json_response(raw, default={
            "triggered": None, "confidence": 0.0, "reason": "LLM response parse failed", "evidence": []
        })

    def generate_payloads(self, vuln_type, url, param, failed_attempts, code_context=""):
        """根据失败记录生成 3-5 个优化 payload。"""
        if not self.available:
            return []

        prompt = _build_payload_gen_prompt(vuln_type, url, param, failed_attempts, code_context)
        raw = self._call_llm(prompt)
        return _parse_payload_list(raw)

    def generate_patch(self, finding):
        """为一条漏洞 finding 生成修复方案文本。"""
        if not self.available:
            return ""

        prompt = _build_patch_prompt(finding)
        return self._call_llm(prompt) or ""

    # -----------------------------------------------------------------
    # 内部
    # -----------------------------------------------------------------

    def _call_llm(self, prompt):
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a web security expert. Output only valid JSON when asked."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=1024,
            )
            return resp.choices[0].message.content
        except Exception:
            return None


# -------------------------------------------------------------------
# Prompt 构造
# -------------------------------------------------------------------

def _build_analysis_prompt(url, payload, param, vuln_type, status_code, response_snippet):
    return f"""Analyze whether a {vuln_type} vulnerability was triggered by the following payload.

Target URL: {url}
Injected Parameter: {param}
Payload: {payload}
HTTP Status Code: {status_code}

Response body (truncated):
```
{response_snippet}
```

Output strict JSON (no markdown, no extra text):
{{
  "triggered": true or false,
  "confidence": 0.0 to 1.0,
  "vuln_type": "{vuln_type}",
  "reason": "Brief explanation — if not triggered, what protection prevented it? If triggered, what evidence confirms it?",
  "evidence": ["specific strings or patterns from the response that support your conclusion"]
}}"""


def _build_payload_gen_prompt(vuln_type, url, param, failed_attempts, code_context):
    attempts_text = "\n".join(
        f"- payload: {a.get('payload','?')}  |  reason: {a.get('reason','?')}"
        for a in failed_attempts
    )
    return f"""You are a penetration testing expert. The basic payloads below failed to trigger a {vuln_type} vulnerability.

Target: {url}
Parameter: {param}

Failed attempts:
{attempts_text}

Relevant code/context (if available):
{code_context or 'N/A'}

Generate 3-5 optimized payloads that may bypass the observed protections. Consider:
- Different encoding (URL-encode, double-encode, Unicode escapes, hex entities)
- Alternative SQL/CMD/XSS syntax or vectors
- Context-specific bypasses based on the failure reasons

Output strict JSON array of strings (no markdown, no extra text):
["payload1", "payload2", "payload3"]"""


def _build_patch_prompt(finding):
    return f"""You are a security engineer. Write a concrete code patch to fix this vulnerability.

Vulnerability Type: {finding.get('type', 'unknown')}
URL: {finding.get('url', 'unknown')}
Parameter: {finding.get('param', 'N/A')}
Payload: {finding.get('payload', 'N/A')}
Evidence: {json.dumps(finding.get('evidence', []))}
LLM Analysis: {finding.get('llm_reason', 'N/A')}

Provide a specific, actionable code fix (input validation, parameterized queries, output encoding, WAF rule, etc.). Include example code if helpful. Output as plain text (no markdown formatting needed)."""


# -------------------------------------------------------------------
# 工具函数
# -------------------------------------------------------------------

def _truncate_response(text, max_chars=3000):
    if not text:
        return "(empty)"
    if len(text) <= max_chars:
        return text
    # 保留头部 70% + 尾部 30%，中间截断处插入标记
    head = int(max_chars * 0.7)
    tail = int(max_chars * 0.3)
    return text[:head] + "\n\n... [truncated] ...\n\n" + text[-tail:]


def _parse_json_response(raw, default=None):
    """从 LLM 回复中提取 JSON 对象。"""
    if default is None:
        default = {}
    if not raw:
        return default
    text = raw.strip()
    # 去除可能的 markdown 代码块包裹
    m = re.search(r'\{[\s\S]*\}', text)
    if not m:
        return default
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return default


def _parse_payload_list(raw):
    """从 LLM 回复中提取 payload 列表。"""
    if not raw:
        return []
    text = raw.strip()
    m = re.search(r'\[[\s\S]*\]', text)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
        return arr if isinstance(arr, list) else []
    except json.JSONDecodeError:
        return []
