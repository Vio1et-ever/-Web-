import argparse
import os
import warnings

from . import target_info, vuln_engine, llm_module, report

warnings.filterwarnings('ignore')


def run_scan_with_selenium(target, out_dir, driver_path=None, max_depth=1):
    os.makedirs(out_dir, exist_ok=True)

    # 1. 尝试使用 Selenium 深度爬取
    try:
        endpoints = target_info.crawl_with_selenium(target, max_depth=max_depth, driver_path=driver_path, headless=True)
        print(f"Selenium 抓取到 {len(endpoints)} 个 URL")
    except Exception as e:
        print("Selenium 抓取失败：", e)
        print("回退到静态爬虫")
        import requests
        sess = requests.Session()
        endpoints = target_info.crawl_urls(target, max_depth=max_depth, session=sess)

    if target not in endpoints:
        endpoints.append(target)

    # 2. 漏洞检测
    ppath = os.path.join(os.path.dirname(__file__), "payloads.json")
    scanner = vuln_engine.VulnerabilityScanner(payloads_path=ppath)
    findings = scanner.scan_endpoints(endpoints)

    # 3. LLM 分析确认（可选）
    llm = None
    if os.environ.get("OPENAI_API_KEY"):
        llm = llm_module.LLMAnalyzer()
        if llm.available:
            scanner.llm = llm
            # 重新扫描以启用 LLM 增强
            findings = scanner.scan_endpoints(endpoints)

    final = []
    if llm and llm.available:
        for f in findings:
            triggered, _ = scanner._llm_analyze_finding(f)
            if triggered or triggered is None:
                final.append(f)
    else:
        final = list(findings)

    # 3.5 XSS 验证（使用 Selenium 打开并等待 alert）
    xss_count = 0
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.common.exceptions import TimeoutException

        opts = Options()
        opts.add_argument("--headless=new")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--no-sandbox")
        if driver_path:
            serv = Service(executable_path=driver_path)
            drv = webdriver.Chrome(service=serv, options=opts)
        else:
            drv = webdriver.Chrome(options=opts)

        for idx, f in enumerate(list(final)):
            if f.get("type") == "xss":
                try:
                    drv.set_page_load_timeout(10)
                    drv.get(f["url"])
                    try:
                        WebDriverWait(drv, 5).until(EC.alert_is_present())
                        alert = drv.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        shot = os.path.join(out_dir, f"xss_alert_{idx}.png")
                        drv.save_screenshot(shot)
                        f["verified"] = True
                        f["alert_text"] = alert_text
                        f["screenshot"] = shot
                    except TimeoutException:
                        # 未出现 alert，仍保存页面快照供人工复核
                        shot = os.path.join(out_dir, f"xss_nodelay_{idx}.png")
                        drv.save_screenshot(shot)
                        f.setdefault("verified", False)
                        f["screenshot"] = shot
                except Exception:
                    continue
        drv.quit()
    except Exception:
        # Selenium 不可用或启动失败；跳过 XSS 动态验证
        pass

    # 4. 报告（含 LLM 补丁）
    if llm and llm.available:
        print("[LLM] 正在生成漏洞补丁...")
        for f in final:
            patch = llm.generate_patch(f)
            if patch:
                f["patch"] = patch

    html_path = os.path.join(out_dir, "report_selenium.html")
    report.generate_html_report(target, final, html_path)
    print("HTML 报告已生成：", html_path)

    # Print summary counts by type
    from collections import Counter
    types = [f.get('type','unknown') for f in final]
    cnt = Counter(types)
    print('漏洞类型统计：')
    for k,v in cnt.items():
        print(f' - {k}: {v}')

    # 5. 尝试生成 PDF
    pdf_path = os.path.join(out_dir, "report_selenium.pdf")
    try:
        report.generate_pdf_report(html_path, pdf_path)
        print("PDF 报告已生成：", pdf_path)
    except Exception as e:
        print("PDF 生成失败：", e)
        print("请确认已安装 wkhtmltopdf 并在 PATH 中，或手动生成 PDF。")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target')
    parser.add_argument('--out', default='./reports')
    parser.add_argument('--driver-path', default=None)
    parser.add_argument('--depth', type=int, default=1)
    args = parser.parse_args()

    run_scan_with_selenium(args.target, args.out, driver_path=args.driver_path, max_depth=args.depth)


if __name__ == '__main__':
    main()
