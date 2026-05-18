"""
DVWA 靶场漏洞检测评估 — 计算 Accuracy / Precision / Recall / F1 Score。

Ground Truth 定义（基于对 dvwa_server.py 源码的逐级分析）：

Low (无过滤):
  sqli=1: 字符串直接拼接 SQL
  xss=1:  输出未转义 (Reflected + Stored 均未防护)
  traversal=1: 路径直接拼接
  cmd=1:  shell 命令拼接，无过滤
  → 4 Positive, 0 Negative

Medium (基础过滤):
  sqli=1: 转义引号，但数字型注入(1 OR 1=1)仍可绕过
  xss=1:  仅过滤<script>标签，Stored XSS中img/onerror等向量仍可触发
  traversal=0: 剥离 ../ 和 ..\\ ，默认payload集中无有效绕过payload
  cmd=1:  过滤 && 和 ; ，但 | 管道的payload仍可绕过
  → 3 Positive, 1 Negative

High (正确防护):
  sqli=0: 仅允许整数输入
  xss=0:  html.escape() 全部转义
  traversal=0: 文件白名单
  cmd=0:  IP/hostname正则白名单
  → 0 Positive, 4 Negative
"""
import sys
import os
import time
import json
import threading
import warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from web_scanner import vuln_engine

TARGET_BASE = "http://localhost:8888"
ENDPOINTS = [
    f"{TARGET_BASE}/vulnerabilities/sqli?id=1",
    f"{TARGET_BASE}/vulnerabilities/xss_r?name=Guest",
    f"{TARGET_BASE}/vulnerabilities/xss_s",
    f"{TARGET_BASE}/vulnerabilities/exec?cmd=127.0.0.1",
    f"{TARGET_BASE}/vulnerabilities/fi?page=include.php",
]

# Ground Truth: {level: {type: 1|0}}
GROUND_TRUTH = {
    "low":    {"sqli": 1, "xss": 1, "path_traversal": 1, "cmd_injection": 1},
    "medium": {"sqli": 1, "xss": 1, "path_traversal": 0, "cmd_injection": 1},
    "high":   {"sqli": 0, "xss": 0, "path_traversal": 0, "cmd_injection": 0},
}

VULN_TYPES = ["sqli", "xss", "path_traversal", "cmd_injection"]


def start_dvwa_server():
    from web_scanner.dvwa_server import ThreadingServer, DVWAHandler, PORT
    server = ThreadingServer(("0.0.0.0", PORT), DVWAHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    return server


def set_security_level(session, level):
    session.get(f"{TARGET_BASE}/set_level?level={level}", timeout=5)


def scan_level(level, session):
    """运行扫描，返回该等级下检测到的漏洞类型集合。"""
    set_security_level(session, level)

    ppath = os.path.join(os.path.dirname(__file__), "payloads.json")
    scanner = vuln_engine.VulnerabilityScanner(
        payloads_path=ppath,
        session=session,
        llm_analyzer=None,
        llm_max_iterations=1,
        quick_mode=True,
    )
    findings = scanner.scan_endpoints(ENDPOINTS)

    detected_types = set()
    for f in findings:
        t = f.get("type", "")
        if t in VULN_TYPES:
            detected_types.add(t)

    return detected_types, findings


def calculate_metrics(all_gt, all_pred):
    """从 ground-truth 和 prediction 列表计算二分类指标。"""
    tp = sum(1 for g, p in zip(all_gt, all_pred) if g == 1 and p == 1)
    fp = sum(1 for g, p in zip(all_gt, all_pred) if g == 0 and p == 1)
    fn = sum(1 for g, p in zip(all_gt, all_pred) if g == 1 and p == 0)
    tn = sum(1 for g, p in zip(all_gt, all_pred) if g == 0 and p == 0)

    accuracy  = (tp + tn) / max(tp + tn + fp + fn, 1)
    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 1e-9)

    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "Accuracy":  round(accuracy, 4),
        "Precision": round(precision, 4),
        "Recall":    round(recall, 4),
        "F1":        round(f1, 4),
    }


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "test_results")
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 65)
    print("  DVWA Vulnerability Detection — Metrics Evaluation")
    print("=" * 65)

    # 1. Start DVWA
    print("\n[1] Starting DVWA simulation server...")
    server = start_dvwa_server()
    try:
        r = requests.get(f"{TARGET_BASE}/", timeout=3)
        print(f"    Server online (HTTP {r.status_code})")
    except Exception as e:
        print(f"    Connection failed: {e}")
        return

    # 2. Scan all three levels
    print("\n[2] Scanning three security levels...")
    session = requests.Session()
    session.verify = False

    level_results = {}
    for level in ["low", "medium", "high"]:
        detected_types, findings = scan_level(level, session)
        level_results[level] = {"detected": detected_types, "findings": findings}

        gt = GROUND_TRUTH[level]
        print(f"\n  [{level.upper()}]")
        for vt in VULN_TYPES:
            gt_label = "VULN" if gt[vt] else "SAFE"
            pred_label = "DETECTED" if vt in detected_types else "MISSED"
            match = "OK" if (vt in detected_types) == bool(gt[vt]) else "XX"
            print(f"    {vt:20s}  GT={gt_label:5s}  Pred={pred_label:8s}  {match}")

    # 3. Build per-type per-level matrices
    print("\n[3] Confusion Matrix per level")
    print("-" * 55)

    all_gt = []
    all_pred = []

    for level in ["low", "medium", "high"]:
        gt = GROUND_TRUTH[level]
        detected = level_results[level]["detected"]

        level_gt = [gt[vt] for vt in VULN_TYPES]
        level_pred = [1 if vt in detected else 0 for vt in VULN_TYPES]
        all_gt.extend(level_gt)
        all_pred.extend(level_pred)

        m = calculate_metrics(level_gt, level_pred)
        print(f"  {level:8s}  TP={m['TP']}  FP={m['FP']}  FN={m['FN']}  TN={m['TN']}  "
              f"Acc={m['Accuracy']:.3f}  Prec={m['Precision']:.3f}  Rec={m['Recall']:.3f}  F1={m['F1']:.3f}")

    # 4. Overall metrics
    print("\n[4] Overall Metrics (all levels combined)")
    print("-" * 55)
    overall = calculate_metrics(all_gt, all_pred)
    print(f"  TP={overall['TP']}  FP={overall['FP']}  FN={overall['FN']}  TN={overall['TN']}")
    print(f"  Accuracy:  {overall['Accuracy']:.4f}")
    print(f"  Precision: {overall['Precision']:.4f}")
    print(f"  Recall:    {overall['Recall']:.4f}")
    print(f"  F1 Score:  {overall['F1']:.4f}")

    # 5. Summary table
    print("\n" + "=" * 65)
    print("  METRICS SUMMARY")
    print("=" * 65)
    print(f"  {'Level':<10} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1 Score':<12}")
    print(f"  {'-'*10} {'-'*12} {'-'*12} {'-'*12} {'-'*12}")

    level_metrics = {}
    for level in ["low", "medium", "high"]:
        gt = GROUND_TRUTH[level]
        detected = level_results[level]["detected"]
        lgt = [gt[vt] for vt in VULN_TYPES]
        lpd = [1 if vt in detected else 0 for vt in VULN_TYPES]
        m = calculate_metrics(lgt, lpd)
        level_metrics[level] = m
        print(f"  {level:<10} {m['Accuracy']:<12.4f} {m['Precision']:<12.4f} {m['Recall']:<12.4f} {m['F1']:<12.4f}")

    print(f"  {'-'*10} {'-'*12} {'-'*12} {'-'*12} {'-'*12}")
    print(f"  {'Overall':<10} {overall['Accuracy']:<12.4f} {overall['Precision']:<12.4f} {overall['Recall']:<12.4f} {overall['F1']:<12.4f}")
    print("=" * 65)

    # Save results
    output = {
        "ground_truth": GROUND_TRUTH,
        "per_level": {
            lv: {
                "detected_types": list(level_results[lv]["detected"]),
                "metrics": level_metrics[lv],
                "findings": level_results[lv]["findings"],
            }
            for lv in ["low", "medium", "high"]
        },
        "overall": overall,
    }
    json_path = os.path.join(out_dir, "evaluation_metrics.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, default=str)
    print(f"\nDetailed results saved to: {json_path}")


if __name__ == "__main__":
    main()
