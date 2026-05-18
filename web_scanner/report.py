import os
from jinja2 import Template

HTML_TEMPLATE = """
<html>
<head><meta charset="utf-8"><title>Vuln Report</title></head>
<body>
<h1>扫描报告</h1>
<p>目标：{{ target }}</p>
<h2>漏洞列表（共 {{ findings|length }} 条）</h2>
{% if findings %}
<ol>
{% for f in findings %}
    <li>
        <strong>类型：</strong> {{ f.type }}<br>
        <strong>URL：</strong> <a href="{{ f.url }}">{{ f.url }}</a><br>
        {% if f.payload %}<strong>Payload：</strong> {{ f.payload }}<br>{% endif %}
        {% if f.get('param') %}<strong>参数：</strong> {{ f.param }}<br>{% endif %}
        {% if f.get('score') %}<strong>评分：</strong> {{ f.score }}<br>{% endif %}
        {% if f.get('evidence') %}<strong>证据：</strong>
            <ul>
            {% for e in f.evidence %}
                <li>{{ e }}</li>
            {% endfor %}
            </ul>
        {% endif %}
        {% if f.get('verified') is not none %}
            <strong>动态验证：</strong> {{ '已验证' if f.verified else '未验证' }}<br>
        {% endif %}
        {% if f.get('llm_reason') %}<strong>LLM 分析：</strong> {{ f.llm_reason }}<br>{% endif %}
        {% if f.get('screenshot') %}
            <strong>截图：</strong> <a href="{{ f.screenshot }}">{{ f.screenshot }}</a><br>
        {% endif %}
        {% if f.get('patch') %}
            <strong>修复补丁：</strong>
            <pre style="background:#f4f4f4;padding:8px;border-left:3px solid #4caf50;overflow-x:auto;">{{ f.patch }}</pre>
        {% endif %}
    </li>
{% endfor %}
</ol>
{% else %}
<p>未发现漏洞（基于规则扫描）</p>
{% endif %}
</body>
</html>
"""


def generate_html_report(target, findings, out_file):
    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(target=target, findings=findings)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html)
    return out_file


def generate_pdf_report(html_file, pdf_file):
    try:
        import pdfkit
    except Exception:
        raise RuntimeError("pdfkit 未安装，请运行：pip install pdfkit，并确保 wkhtmltopdf 已安装")

    # 尝试自动发现 wkhtmltopdf
    config = None
    try:
        path = pdfkit.configuration().wkhtmltopdf
        if path:
            config = pdfkit.configuration(wkhtmltopdf=path)
    except Exception:
        # 允许用户通过环境变量或系统 PATH 提供 wkhtmltopdf
        config = None

    pdfkit.from_file(html_file, pdf_file, configuration=config)
    return pdf_file


def check_wkhtmltopdf():
    try:
        import pdfkit
        try:
            cfg = pdfkit.configuration()
            return getattr(cfg, 'wkhtmltopdf', None)
        except Exception:
            return None
    except Exception:
        return None
