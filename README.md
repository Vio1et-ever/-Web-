# 基于大语言模型辅助分析的 Web 漏洞扫描器

**基于大语言模型辅助分析的 Web 漏洞扫描器** 是一个轻量级的自动化漏洞扫描工具，基于规则引擎与 LLM 双路径架构，支持 SQL 注入、XSS、路径遍历、命令注入等常见 Web 漏洞的自动化探测与验证。

---

## 目录

1. [#功能特性](#功能特性)
2. [#项目目录结构](#项目目录结构)
3. [#系统架构](#系统架构)
4. [#快速开始](#快速开始)
5. [#模块详解](#模块详解)
6. [#核心技术](#核心技术)
7. [#运行与测试](#运行与测试)
8. [#项目声明](#项目声明)

---

## 功能特性

- **多类型漏洞检测**：SQLi（错误型、布尔型、时间型、Union联合查询）、XSS（反射型、存储型、DOM 型）、路径遍历、命令注入
- **规则引擎 + LLM 双路径**：规则引擎快速初筛，LLM 负责误报过滤（Phase A）与 Payload 迭代优化（Phase B）
- **灵活的目标采集**：支持链接爬取、目录枚举、端口扫描、Selenium 渲染 JS 动态页面
- **多格式报告**：HTML 和可选 PDF 报告输出，包含指标图表
- **DVWA 标准化评估**：内置基准测试脚本，支持 Accuracy / Precision / Recall / F1 指标评估

---

## 项目目录结构

```
e:\vscode\
├── README.md                              # 项目说明文档
├── requirements.txt                       # Python 依赖清单
├── web_scanner/                            # 核心源码包
│   ├── __init__.py                        #   包初始化
│   ├── main.py                            #   CLI 入口与扫描主流程
│   ├── target_info.py                     #   目标采集（爬虫/端口扫描/目录枚举）
│   ├── vuln_engine.py                     #   漏洞检测引擎（规则匹配 + 动态验证）
│   ├── llm_module.py                      #   LLM 增强分析模块（Phase A + Phase B + 补丁生成）
│   ├── report.py                          #   HTML / PDF 报告生成
│   ├── payloads.json                      #   检测 Payload 库（SQLi / XSS / PathTraversal / CMDi）
│   ├── dvwa_server.py                     #   DVWA 模拟靶场服务器
│   ├── run_dvwa_test.py                   #   DVWA 三级扫描实验脚本
│   ├── run_selenium_scan.py               #   Selenium 动态页面扫描
│   ├── evaluate_dvwa.py                   #   DVWA 指标评估（Accuracy / Precision / Recall / F1）
│   ├── ENGINEERING_DOC.md                 #   系统工程文档
│   └── DVWA_BENCHMARK_COMPARISON.md       #   多工具 DVWA 基准对比分析
└──reports/                                # 扫描报告输出目录

```

---

## 系统架构

### 数据流概览

<pre style="background-color: #ffffff; color: #000000; padding: 12px; border: 1px solid #d0d0d0; border-radius: 4px; font-family: Consolas, 'Courier New', monospace; font-size: 13px; line-height: 1.5;">
用户输入 (URL + 参数)
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│  main.py — 扫描协调器                                      │
│                                                          │
│  ① 解析 CLI 参数，初始化 Session、Cookie、请求头             │
│  ② 调用 target_info.py 采集目标 URL 列表                    │
│  ③ 实例化 VulnerabilityScanner，加载 payloads.json          │
│  ④ 可选：初始化 LLMAnalyzer（OpenAI 兼容 API）              │
│  ⑤ 逐 URL 调用 scanner.scan_endpoints()                   │
│  ⑥ 汇总 findings，调用 report.py 生成报告                   │
└──────────────────────────────────────────────────────────┘
       │
       ├──▶ target_info.py
       │    • crawl_urls()       深度优先爬取，提取 &lt;a&gt;/&lt;link&gt;/&lt;script&gt;/&lt;img&gt;
       │    • enumerate_directories()  字典爆破隐藏路径
       │    • scan_ports()       多线程端口扫描 (80/443/8080)
       │    • crawl_with_selenium()    Selenium WebDriver 渲染 JS 页面
       │
       ├──▶ vuln_engine.py
       │    • scan_endpoints()    遍历 URL 列表，调度各检测器
       │    • test_sqli()         错误回显 + 结构变化 + 布尔盲注 + 时间盲注 + Union
       │    • test_xss()          反射检测 + DOM 注入 + 事件处理器注入
       │    • test_path_traversal()  路径遍历 + 编码绕过检测
       │    • test_cmd_injection()   命令拼接 + 管道符 + 反引号注入
       │    • _verify_finding()   动态二次验证（重放 Payload 并比对响应）
       │    • 评分制：score ≥ 4 判定为漏洞
       │
       ├──▶ llm_module.py（可选，--use-llm 启用）
       │    Phase A — 误报过滤
       │    • analyze_response()  分析 HTTP 响应语义，判断 Payload 是否真实执行
       │    • 输入：URL + Payload + 参数 + 漏洞类型 + 响应正文
       │    • 输出：{triggered, confidence, reason, evidence}
       │    • LLM 识别：HTML 实体编码 / WAF 拦截页 / 错误消息巧合匹配
       │
       │    Phase B — Payload 优化
       │    • generate_payloads()  根据失败记录迭代生成绕过 Payload
       │    • 输入：漏洞类型 + 失败 Payload 列表 + 代码上下文
       │    • 输出：3~5 个优化 Payload
       │    • 迭代策略：最多 llm_max_iter 轮，每轮根据反馈调整
       │
       │    Phase C — 补丁生成
       │    • generate_patch()     为已确认漏洞生成修复建议
       │
       └──▶ report.py
            • generate_html_report()   Jinja2 模板渲染 HTML 报告
            • 包含：漏洞列表 / Payload / 证据 / LLM 分析 / 修复补丁
            • 可选：pdfkit 转换为 PDF
</pre>

---

## 快速开始

### 依赖安装

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
pip install -r requirements.txt
```

### 1. 运行常规扫描

```bash
python -m web_scanner.main http://127.0.0.1/DVWA/ --depth 2 --out reports
```

参数说明：

| 参数 | 说明 |
|------|------|
| `target` | 扫描目标 URL（必填） |
| `--wordlist` | 目录枚举字典文件，可选 |
| `--cookies` | 请求 Cookie，例如 `PHPSESSID=xxx; security=low` |
| `--user-agent` | 自定义 User-Agent |
| `--headers` | 额外请求头，JSON 格式字符串 |
| `--depth` | 爬取深度，`0` 表示仅扫描目标 URL |
| `--use-llm` | 启用 LLM 增强分析（Phase A 误报过滤 + Phase B Payload 优化） |
| `--llm-api-key` | LLM API Key（默认从 `OPENAI_API_KEY` 环境变量读取） |
| `--llm-base-url` | LLM API Base URL（默认从 `OPENAI_BASE_URL` 环境变量读取） |
| `--llm-model` | LLM 模型名称，默认 `deepseek` |
| `--llm-max-iter` | LLM Payload 优化最大迭代次数，默认 2 |
| `--out` | 报告输出目录，默认 `./reports` |

### 2. 启用 LLM 增强扫描

```bash
python -m web_scanner.main http://127.0.0.1/DVWA/ --depth 2 --use-llm --llm-api-key "sk-xxx" --llm-base-url "https://api.deepseek.com" --llm-model "deepseek-v4-pro"
```

### 3. 运行 DVWA 评估脚本

```bash
# 纯规则引擎评估
python web_scanner/evaluate_dvwa.py

# 规则引擎 + LLM 评估
python web_scanner/evaluate_dvwa.py --use-llm --llm-api-key "sk-xxx" --llm-base-url "https://api.deepseek.com" --llm-model "deepseek-v4-pro"
```
---

## 模块详解

### 1. `main.py` — CLI 入口与扫描协调器

作为整个系统的调度中心，`main.py` 负责串联从参数解析到报告输出的完整扫描流程。它通过 `argparse` 接收用户配置，初始化 `requests.Session` 并注入 Cookie 与自定义请求头，随后依次调用三个核心子系统：目标采集、漏洞检测、报告生成。当 `--use-llm` 标志开启时，协调器还会在漏洞检测阶段初始化 `LLMAnalyzer` 实例并注入 `VulnerabilityScanner`，在报告生成阶段为每条 finding 调用 `generate_patch()` 附加修复建议。协调器本身不执行检测逻辑，而是作为依赖注入的容器——它将 Session、Payloads、LLMAnalyzer 三个共享资源分发给各模块，确保整个扫描过程中 HTTP 连接复用、LLM 客户端单例、Payload 库一次加载。

### 2. `target_info.py` — 目标信息采集

该模块负责在漏洞检测之前构建目标 URL 集合，提供四种互补的采集方式以适应不同类型的 Web 应用。

- **`crawl_urls(start_url, max_depth, session)`**：基于广度优先的 HTML 链接爬取。从起始页开始，解析 `<a>`、`<link>`、`<script>`、`<img>` 标签中的 `href` 和 `src` 属性，过滤掉静态资源扩展名（js/css/png/jpg/gif/svg/ico/woff/pdf/zip 等），仅保留 HTML 页面链接。同域限制确保爬虫不会越界到外部站点。`max_depth` 控制爬取深度，0 表示仅返回起始 URL。

- **`enumerate_directories(base_url, wordlist, session)`**：字典驱动的目录枚举。对字典中的每个路径拼接至 base_url，通过 HTTP 状态码（200/301/302/403/401）判断路径是否存在。使用 `ThreadPoolExecutor` 实现并发请求以加速枚举过程。

- **`scan_ports(host, ports, timeout, workers)`**：多线程 TCP 端口扫描。默认检测 80、443、8080 端口，通过 `socket.connect()` 判断端口开放状态，最多支持 50 个并发 worker。

- **`crawl_with_selenium(start_url, max_depth, driver_path, headless)`**：针对 JavaScript 动态渲染页面的 Selenium 爬取。启动无头浏览器实例，等待页面 JS 执行完毕后提取渲染后的 DOM 中的链接，解决传统 HTTP 爬虫无法获取 SPA（单页应用）内容的痛点。

### 3. `vuln_engine.py` — 漏洞检测引擎

这是系统的核心模块，实现了四种漏洞类型的规则化检测。

**SQL 注入检测（`test_sqli`）** 采用分层递进策略。首先遍历 Payload 库中的 SQLi Payload，通过正则匹配响应中的数据库错误消息（MySQL/PostgreSQL/Oracle/SQL Server 特征）。若未命中，则计算响应长度变化率和文本相似度（`difflib.SequenceMatcher`），当长度差异超过 20% 且相似度低于 96% 时判定为"结构性变化"证据。以上两种快速检测仍不足时，进入布尔盲注阶段——发送 `' AND 1=1 -- ` 与 `' AND 1=2 -- ` 成对 Payload，比较两次响应的相似度，差异超过 0.5% 即计入证据。`quick_mode` 会跳过时间盲注和 Union 联合查询以换取速度。数字型 Payload（`1 OR 1=1`、`1 AND 1=2`）不依赖引号，可绕过 `addslashes()` 类转义防护。

**XSS 检测（`test_xss`）** 从三个维度覆盖。反射型检测：判断 Payload 是否在响应 HTML 中原样出现（包括 `html.escape()` 转义版本）。DOM 型检测：提取响应中 `<script>` 标签的文本内容和元素的事件处理器属性，检查是否包含 Payload 片段。存储型检测：对 POST 端点注入 Payload 后重新 GET 页面，验证 Payload 是否持久化于响应中。

**路径遍历检测（`test_path_traversal`）** 支持跨平台 Payload。Unix 路径（`../../../../etc/passwd`）、URL 编码变体、Windows 路径（`..\..\..\..\windows\win.ini`）均纳入 Payload 集。证据匹配使用专用的 `traversal_re` 正则，覆盖 "No such file or directory"、"failed to open stream"、"root:x:0:0" 等操作系统级回显特征。

**命令注入检测（`test_cmd_injection`）** 涵盖分号、管道符、反引号三种注入语法。证据正则匹配 `uid=`、`command not found`、`bytes from`（ping 回显）、`ttl=` 等命令执行特征，同时使用 `cmd_false_positive_re` 过滤 PHP `include()` 警告等常见误报源。

所有检测结果经 `_verify_finding()` 二次验证——使用原始 Payload 重放请求并交叉比对响应，排除网络抖动导致的偶发性误报。

### 4. `llm_module.py` — LLM 增强分析

该模块在规则引擎的检测结果之上提供语义级的智能判断，通过 OpenAI 兼容 API 调用大语言模型。

**Phase A — 误报过滤（`analyze_response`）**。接收规则引擎标记为"漏洞"的请求-响应对，将 URL、Payload、参数名、漏洞类型、HTTP 状态码及响应正文（截断至 3000 字符）构造为结构化 Prompt，要求 LLM 从三个维度判断漏洞是否真实触发：Payload 在响应中的存在形态（原样 vs 转义 vs 未出现）、服务器安全机制的介入迹象（WAF 拦截页、输入校验错误消息）、可利用性上下文（Payload 在浏览器/DOM 中的执行条件）。返回 JSON 格式的 `{triggered, confidence, reason, evidence}`。`triggered=false` 的 finding 将被降级或过滤。

**Phase B — Payload 优化（`generate_payloads`）**。当规则引擎对某参数未发现漏洞时，LLM 根据失败记录（哪些 Payload 被尝试、响应如何）和注入上下文，生成 3~5 个针对性绕过 Payload。例如面对 `addslashes()` 防护时，LLM 倾向于生成无引号数字型注入；面对 `<script>` 标签过滤时，LLM 会生成 `<img onerror>` 或 `<svg/onload>` 等替代向量。每次迭代的生成结果由规则引擎重新验证，`llm_max_iter` 控制最大迭代轮次。

**Phase C — 补丁生成（`generate_patch`）**。为已确认漏洞生成修复建议，涵盖输入校验（类型检查、正则白名单）、输出转义（`htmlspecialchars`、参数化查询）、架构修复（预编译语句、文件访问白名单）三个层级。

### 5. `report.py` — 报告生成

基于 Jinja2 模板引擎渲染 HTML 报告。报告内容包含：扫描目标概览、漏洞列表（含类型/URL/Payload/参数/评分/证据/LLM分析结论）、修复补丁（若 LLM 已生成）。可选通过 `pdfkit` 将 HTML 转换为 PDF，需要系统安装 `wkhtmltopdf`。

### 6. `payloads.json` — Payload 库

JSON 格式的漏洞检测 Payload 集合，按漏洞类型分为四组：

| 类型 | 示例 Payload | 数量 |
|------|-------------|------|
| `sqli` | `' OR '1'='1' -- `, `1 OR 1=1`, `' UNION SELECT NULL-- ` | 5+ |
| `xss` | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>` | 4+ |
| `traversal` | `../../../../etc/passwd`, `..%2F..%2F..%2Fetc%2Fpasswd`, `..\..\..\..\windows\win.ini` | 3+ |
| `cmd` | `;id;`, `|whoami|`, `` `whoami` ``, `;echo INJECTED;` | 4+ |

可根据目标应用的防护特征扩展 Payload 库以提升检测覆盖。

### 7. `dvwa_server.py` — DVWA 模拟靶场

基于 Python `http.server` 的轻量级 DVWA 模拟器，实现了 Low/Medium/High 三级安全防护的 5 个漏洞端点（SQLi / XSS Reflected / XSS Stored / Command Injection / File Inclusion）。安全等级通过 Cookie 切换，无需安装 PHP/MySQL 环境即可在本地运行供扫描器测试。

---


## 运行与测试

### 本地测试靶场

启动内置 DVWA 模拟服务器：

```python
from web_scanner.dvwa_server import ThreadingServer, DVWAHandler, PORT
server = ThreadingServer(("0.0.0.0", PORT), DVWAHandler)
server.serve_forever()
```

### 运行建议

- 先在受控环境（如 DVWA、本地测试站点）中验证扫描效果。
- 如需处理 JavaScript 渲染页面，可安装 Selenium 并调用 `crawl_with_selenium()`。
- 当扫描目标页面数量较多时，打开 `quick_mode` 或降低 `--depth` 可显著降低运行时间。
- `requirements.txt` 包含当前依赖：`requests`、`beautifulsoup4`、`jinja2`、`pdfkit`、`matplotlib`、`openai`。
- PDF 报告需要 `wkhtmltopdf` 安装在系统可访问路径。

---

## 项目声明

- **项目名称**：基于大语言模型辅助分析的 Web 漏洞检测系统
- **项目作者**：Chen Xinyun
- **作者单位**：暨南大学网络空间安全学院
- **开发语言**：Python 3.11
- **核心技术**：规则引擎 + LLM 双路径混合架构、基于规则扫描漏洞判定、LLM 驱动的语义级误报过滤与自适应 Payload 生成


