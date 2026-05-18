"""
DVWA 靶场实验 — 对 Low / Medium / High 三个安全等级运行扫描器，
收集漏洞检测数据并生成对比图表与分析报告。
"""
import sys
import os
import time
import json
import threading
import requests
import warnings

warnings.filterwarnings("ignore")

# 确保项目根目录在 path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_scanner import vuln_engine, target_info, llm_module


TARGET_BASE = "http://localhost:8888"
ENDPOINTS = [
    f"{TARGET_BASE}/vulnerabilities/sqli?id=1",
    f"{TARGET_BASE}/vulnerabilities/xss_r?name=Guest",
    f"{TARGET_BASE}/vulnerabilities/xss_s",
    f"{TARGET_BASE}/vulnerabilities/exec?cmd=127.0.0.1",
    f"{TARGET_BASE}/vulnerabilities/fi?page=include.php",
]


def start_dvwa_server():
    """在后台线程启动 DVWA 模拟服务。"""
    from web_scanner.dvwa_server import ThreadingServer, DVWAHandler, PORT
    server = ThreadingServer(("0.0.0.0", PORT), DVWAHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    return server


def set_security_level(session, level):
    """设置安全等级 Cookie。"""
    session.get(f"{TARGET_BASE}/set_level?level={level}", timeout=5)


def scan_level(level, session, llm_analyzer=None):
    """对指定安全等级执行扫描，返回 findings 列表。"""
    set_security_level(session, level)
    print(f"  [{level.upper()}] 安全等级已设置，开始扫描...")

    ppath = os.path.join(os.path.dirname(__file__), "payloads.json")
    scanner = vuln_engine.VulnerabilityScanner(
        payloads_path=ppath,
        session=session,
        llm_analyzer=llm_analyzer,
        llm_max_iterations=1,
        quick_mode=True,
    )
    findings = scanner.scan_endpoints(ENDPOINTS)

    print(f"  [{level.upper()}] 扫描完成，发现 {len(findings)} 条漏洞")
    for f in findings:
        print(f"    - [{f.get('type','?')}] {f.get('url','?')}  param={f.get('param','?')}  payload={f.get('payload','?')[:50]}")
    return findings


def classify_findings(findings):
    """按漏洞类型统计。"""
    counts = {"sqli": 0, "xss": 0, "path_traversal": 0, "cmd_injection": 0, "other": 0}
    for f in findings:
        t = f.get("type", "")
        if t == "sqli":
            counts["sqli"] += 1
        elif t == "xss":
            counts["xss"] += 1
        elif t == "path_traversal":
            counts["path_traversal"] += 1
        elif t == "cmd_injection":
            counts["cmd_injection"] += 1
        else:
            counts["other"] += 1
    return counts


def generate_charts(results, out_dir):
    """生成对比图表。"""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    os.makedirs(out_dir, exist_ok=True)

    levels = ["Low", "Medium", "High"]
    vuln_types = ["sqli", "xss", "path_traversal", "cmd_injection"]
    labels_cn = ["SQL Injection", "XSS", "Path Traversal", "Cmd Injection"]
    colors = ["#2196F3", "#FF9800", "#4CAF50", "#F44336"]

    # 提取数据
    total_counts = [len(results[lv]) for lv in levels]
    type_matrix = {}
    for vt in vuln_types:
        type_matrix[vt] = [classify_findings(results[lv])[vt] for lv in levels]

    # ---------- 图1: 堆叠柱状图 — 各等级发现的漏洞类型分布 ----------
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    x = np.arange(len(levels))
    width = 0.55
    bottom = np.zeros(len(levels))
    for vt, color in zip(vuln_types, colors):
        vals = type_matrix[vt]
        bars = ax1.bar(x, vals, width, bottom=bottom, label=labels_cn[vuln_types.index(vt)],
                       color=color, edgecolor="white", linewidth=0.8)
        for bar, val in zip(bars, vals):
            if val > 0:
                ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_y() + bar.get_height() / 2,
                         str(val), ha="center", va="center", fontsize=9, fontweight="bold", color="white")
        bottom += np.array(vals)

    ax1.set_ylabel("Vulnerability Count", fontsize=12)
    ax1.set_title("DVWA — Vulnerability Detection by Security Level", fontsize=13, fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(levels, fontsize=11)
    ax1.legend(loc="upper right", fontsize=9)
    ax1.set_ylim(0, max(total_counts) + 2)
    ax1.grid(axis="y", alpha=0.3)

    # ---------- 图2: 分组柱状图 — 每种漏洞类型在不同等级下的检出 ----------
    x2 = np.arange(len(vuln_types))
    width2 = 0.25
    level_colors = ["#4CAF50", "#FF9800", "#F44336"]
    for i, (lv, lc) in enumerate(zip(levels, level_colors)):
        vals = [type_matrix[vt][i] for vt in vuln_types]
        bars = ax2.bar(x2 + i * width2, vals, width2, label=lv, color=lc, edgecolor="white")
        for bar, val in zip(bars, vals):
            if val > 0:
                ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_y() + bar.get_height() + 0.05,
                         str(val), ha="center", fontsize=9, fontweight="bold")

    ax2.set_ylabel("Detection Count", fontsize=12)
    ax2.set_title("Vulnerability Type Detection by Level", fontsize=13, fontweight="bold")
    ax2.set_xticks(x2 + width2)
    ax2.set_xticklabels(labels_cn, fontsize=10)
    ax2.legend(fontsize=9)
    ax2.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    chart1 = os.path.join(out_dir, "dvwa_results.png")
    plt.savefig(chart1, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  图表已保存: {chart1}")

    # ---------- 图3: 检出率 vs 预期 ----------
    # 预期漏洞数: low=4类各1, medium=部分被过滤, high=几乎全部免疫
    fig, ax = plt.subplots(figsize=(8, 4.5))
    expected = [4, 3, 1]  # low:4, medium:~3, high:~1
    detected = total_counts
    x3 = np.arange(len(levels))
    w = 0.3
    bars1 = ax.bar(x3 - w / 2, expected, w, label="Expected (known vulns)", color="#BBDEFB", edgecolor="#1976D2")
    bars2 = ax.bar(x3 + w / 2, detected, w, label="Detected", color="#1976D2", edgecolor="#0D47A1")
    for b in bars1:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.05, str(int(b.get_height())),
                ha="center", fontsize=11, fontweight="bold", color="#1976D2")
    for b in bars2:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.05, str(int(b.get_height())),
                ha="center", fontsize=11, fontweight="bold", color="#0D47A1")

    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("Expected vs Detected Vulnerabilities", fontsize=13, fontweight="bold")
    ax.set_xticks(x3)
    ax.set_xticklabels(levels, fontsize=11)
    ax.legend(fontsize=9)
    ax.set_ylim(0, max(max(expected), max(detected)) + 1.5)
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    chart2 = os.path.join(out_dir, "dvwa_expected_vs_detected.png")
    plt.savefig(chart2, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  图表已保存: {chart2}")

    return chart1, chart2


def print_report(results):
    """打印实验分析报告。"""
    print("\n" + "=" * 65)
    print("  DVWA Security Level Scanning — Experimental Report")
    print("=" * 65)

    levels = ["low", "medium", "high"]
    all_counts = {}
    for lv in levels:
        c = classify_findings(results[lv])
        all_counts[lv] = c
        print(f"\n  [{lv.upper()}]  Total findings: {len(results[lv])}")
        print(f"    SQL Injection:    {c['sqli']}")
        print(f"    XSS:              {c['xss']}")
        print(f"    Path Traversal:   {c['path_traversal']}")
        print(f"    Command Injection:{c['cmd_injection']}")

    print("\n" + "-" * 65)
    print("  Analysis:")
    print("-" * 65)

    # Low level
    low_c = all_counts["low"]
    low_total = sum(low_c.values())
    print(f"\n  1. LOW    (no filtering)")
    print(f"     - Total detected: {low_total}")
    print(f"     - All 4 vulnerability types should be detectable")
    print(f"     - SQLi: raw string concatenation, error messages exposed")
    print(f"     - XSS: unsanitized output, <script> reflected directly")
    print(f"     - CMD Injection: shell command concatenation without filtering")
    print(f"     - Path Traversal: direct file path concatenation")

    med_c = all_counts["medium"]
    med_total = sum(med_c.values())
    print(f"\n  2. MEDIUM (basic filtering)")
    print(f"     - Total detected: {med_total}")
    print(f"     - SQLi: escape quotes but numeric injection still works")
    print(f"     - XSS: strip <script> tags but other vectors (img, svg) still work")
    print(f"     - CMD Injection: blacklist && and ; but | and `` bypass")
    print(f"     - Path Traversal: strip ../ but encoded variants bypass")

    high_c = all_counts["high"]
    high_total = sum(high_c.values())
    print(f"\n  3. HIGH   (proper security)")
    print(f"     - Total detected: {high_total}")
    print(f"     - SQLi: type validation — only integers accepted")
    print(f"     - XSS: htmlspecialchars() — all output escaped")
    print(f"     - CMD Injection: IP regex whitelist — only digits and dots")
    print(f"     - Path Traversal: whitelist of allowed files")

    print("\n" + "-" * 65)
    print("  Detection Rate Summary:")
    print("-" * 65)
    print(f"    LOW:    {low_total}/4  ({low_total*25:.0f}%)")
    print(f"    MEDIUM: {med_total}/4  ({med_total*25:.0f}%)")
    print(f"    HIGH:   {high_total}/4  ({high_total*25:.0f}%)")

    print("\n" + "=" * 65)


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "test_results")
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 55)
    print("  DVWA 靶场扫描实验")
    print("=" * 55)

    # 1. 启动 DVWA 模拟服务
    print("\n[1/4] 启动 DVWA 模拟靶场...")
    server = start_dvwa_server()
    print(f"  服务已启动: {TARGET_BASE}")

    # 测试连接
    try:
        r = requests.get(f"{TARGET_BASE}/", timeout=3)
        print(f"  连接正常 (HTTP {r.status_code})")
    except Exception as e:
        print(f"  连接失败: {e}")
        return

    # 2. 初始化 LLM 分析器（可选）
    llm = None
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("LLM_API_KEY")
    if api_key:
        print("\n[LLM] 检测到 API Key，启用 LLM 增强分析")
        llm = llm_module.LLMAnalyzer(api_key=api_key)
    else:
        print("\n[LLM] 未设置 API Key，仅使用规则引擎")

    # 3. 执行三级扫描
    print("\n[2/4] 开始扫描...")
    results = {}
    session = requests.Session()
    session.verify = False

    for level in ["low", "medium", "high"]:
        print(f"\n--- Security Level: {level.upper()} ---")
        findings = scan_level(level, session, llm)
        results[level] = findings

    # 4. 生成图表与报告
    print("\n[3/4] 生成图表...")
    generate_charts(results, out_dir)

    print("\n[4/4] 实验分析报告")
    print_report(results)

    # 保存 JSON
    json_path = os.path.join(out_dir, "dvwa_scan_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({lv: results[lv] for lv in results}, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n详细 JSON 已保存: {json_path}")

    print("\nDone.")


if __name__ == "__main__":
    main()
