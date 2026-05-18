import socket
import concurrent.futures
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup


def scan_ports(host, ports=(80, 443, 8080), timeout=1.0, workers=50):
    results = {}

    def _check(p):
        try:
            with socket.socket() as s:
                s.settimeout(timeout)
                s.connect((host, p))
            return p, True
        except Exception:
            return p, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for p, open_ in ex.map(_check, ports):
            results[p] = open_
    return results


def probe_service(host, port, timeout=2.0):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = s.recv(1024)
        s.close()
        return data.decode(errors="ignore")
    except Exception as e:
        return str(e)


def _normalize(url):
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc
    path = parsed.path or "/"
    return f"{scheme}://{netloc}{path}"


def _is_html_link(url):
    parsed = urlparse(url)
    ext = parsed.path.lower().split('.')[-1] if '.' in parsed.path else ''
    return ext not in ('js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'pdf', 'zip', 'rar', 'exe', 'tar', 'gz', 'mp4', 'mp3', 'webm', 'ogg')


def extract_links(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for tag in soup.find_all(["a", "link", "script", "img"]):
        attr = "href" if tag.name in ("a", "link") else "src"
        if tag.has_attr(attr):
            href = tag.get(attr)
            if not href:
                continue
            full = urljoin(base_url, href)
            if _is_html_link(full):
                urls.add(full)
    return urls


def crawl_urls(start_url, max_depth=2, session=None, allowed_schemes=("http", "https")):
    if session is None:
        session = requests.Session()
    start_netloc = urlparse(start_url).netloc
    seen = set()
    results = set()
    queue = [(start_url, 0)]
    while queue:
        url, depth = queue.pop(0)
        norm = _normalize(url)
        if norm in seen or depth > max_depth:
            continue
        seen.add(norm)
        try:
            r = session.get(url, timeout=6, verify=False)
            results.add(url)
            links = extract_links(url, r.text)
            for l in links:
                p = urlparse(l)
                if p.scheme in allowed_schemes and p.netloc == start_netloc:
                    queue.append((l, depth + 1))
        except Exception:
            continue
    return list(results)


def enumerate_directories(base_url, wordlist, session=None):
    if session is None:
        session = requests.Session()
    found = []
    for w in wordlist:
        url = urljoin(base_url, w)
        try:
            r = session.get(url, timeout=5, verify=False)
            if r.status_code < 400:
                found.append((url, r.status_code))
        except Exception:
            continue
    return found


def crawl_with_selenium(start_url, max_depth=1, driver_path=None, headless=True):
    """
    使用 Selenium 渲染 JS 动态页面并抓取链接。安装 selenium & ChromeDriver 后可调用。
    返回抓取到的 URL 列表。
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
    except Exception:
        raise RuntimeError("selenium 未安装，请先 pip install selenium 并配置浏览器驱动")

    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
        opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")

    if driver_path:
        service = Service(executable_path=driver_path)
        driver = webdriver.Chrome(service=service, options=opts)
    else:
        driver = webdriver.Chrome(options=opts)

    seen = set()
    results = set()
    queue = [(start_url, 0)]
    while queue:
        url, depth = queue.pop(0)
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        try:
            driver.get(url)
            html = driver.page_source
            results.add(url)
            links = extract_links(url, html)
            for l in links:
                queue.append((l, depth + 1))
        except Exception:
            continue

    driver.quit()
    return list(results)
