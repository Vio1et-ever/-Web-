import argparse
import warnings
import os

from . import target_info, vuln_engine, llm_module, report

warnings.filterwarnings('ignore')


def main():
    parser = argparse.ArgumentParser(description="轻量 Web 漏洞扫描器 (LLM 增强)")
    parser.add_argument("target", help="目标 URL，例如 http://example.com")
    parser.add_argument("--wordlist", help="目录枚举字典文件", default=None)
    parser.add_argument("--cookies", help="Cookie 字符串，例如 PHPSESSID=xxx; security=low", default=None)
    parser.add_argument("--user-agent", help="自定义 User-Agent",
                        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36")
    parser.add_argument("--headers", help="额外请求头(JSON 格式)", default=None)
    parser.add_argument("--depth", help="爬取深度，0 仅扫描目标 URL", type=int, default=0)
    parser.add_argument("--use-llm", help="启用 LLM 增强分析（Payload 优化 / 误报过滤 / 补丁生成）", action="store_true")
    parser.add_argument("--llm-api-key", help="LLM API Key（默认从 OPENAI_API_KEY 环境变量读取）", default=None)
    parser.add_argument("--llm-base-url", help="LLM API Base URL（默认从 OPENAI_BASE_URL 环境变量读取）", default=None)
    parser.add_argument("--llm-model", help="LLM 模型名称", default="deepseek")
    parser.add_argument("--llm-max-iter", help="LLM Payload 优化最大迭代次数", type=int, default=2)
    parser.add_argument("--out", help="报告输出目录", default="./reports")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    sess = __import__('requests').Session()
    sess.headers.update({"User-Agent": args.user_agent})
    if args.cookies:
        cookie_pairs = [c.strip() for c in args.cookies.split(';') if '=' in c]
        cookies = {k.strip(): v.strip() for k, v in (pair.split('=', 1) for pair in cookie_pairs)}
        sess.cookies.update(cookies)
    if args.headers:
        try:
            extra_headers = __import__('json').loads(args.headers)
            if isinstance(extra_headers, dict):
                sess.headers.update(extra_headers)
        except Exception:
            pass

    # ---- 1. 信息收集 ----
    endpoints = target_info.crawl_urls(args.target, max_depth=args.depth, session=sess)
    if args.wordlist:
        with open(args.wordlist, encoding='utf-8') as f:
            words = [l.strip() for l in f if l.strip()]
        found = target_info.enumerate_directories(args.target, words, session=sess)
        endpoints += [u for u, _ in found]

    # ---- 2. 漏洞检测（规则引擎 + 可选 LLM 增强） ----
    ppath = os.path.join(os.path.dirname(__file__), "payloads.json")

    llm_analyzer = None
    if args.use_llm:
        llm_analyzer = llm_module.LLMAnalyzer(
            api_key=args.llm_api_key,
            base_url=args.llm_base_url,
            model=args.llm_model,
        )
        if llm_analyzer.available:
            print(f"[LLM] 已连接模型: {args.llm_model}")
        else:
            print(f"[LLM] 警告: {llm_analyzer._init_error}，LLM 增强已禁用")

    scanner = vuln_engine.VulnerabilityScanner(
        payloads_path=ppath,
        session=sess,
        llm_analyzer=llm_analyzer,
        llm_max_iterations=args.llm_max_iter,
    )
    findings = scanner.scan_endpoints(endpoints)

    # ---- 3. 报告生成（含 LLM 补丁） ----
    if llm_analyzer and llm_analyzer.available:
        print("[LLM] 正在生成漏洞补丁...")
        for f in findings:
            patch = llm_analyzer.generate_patch(f)
            if patch:
                f["patch"] = patch

    html = report.generate_html_report(args.target, findings, os.path.join(args.out, "report.html"))
    print("HTML 报告已生成：", html)

    if findings:
        type_counts = {}
        for f in findings:
            t = f.get('type', 'unknown')
            type_counts[t] = type_counts.get(t, 0) + 1
        print("漏洞统计：")
        for t, c in type_counts.items():
            print(f"  - {t}: {c}")


if __name__ == "__main__":
    main()
