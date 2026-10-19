#!/usr/bin/env python3
"""Sijishe CLI - Python port (GitHub Actions hardened).

✅ Session + 浏览器级 Header（UA 随机化）
✅ Cookie 注入（SIJISHE_COOKIE 优先，注入 Cookie Jar）
✅ Cookie 失效自动降级到账号密码登录（POST 提交，贴近真实浏览器）
✅ 显式代理注入，保证流量一定走 WARP（不会从机房 IP 裸奔）
✅ 403 降级（不抛异常、不炸 workflow），但登录/降级失败会明确报错
✅ 失败时以非 0 退出码结束，配合 workflow 的“重连 WARP 换 IP 重试”
"""

import hashlib
import os
import random
import string
import sys
import time

import requests
from bs4 import BeautifulSoup

MAIN_URL = "https://xsijishe.com"

# UA 池：固定 UA 是典型的机器人指纹，容易被 WAF 标记，每次运行随机选一个
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def get_accounts():
    # Cookie 与账号密码都允许存在：运行时优先试 Cookie，失效再降级到密码
    cookie = os.getenv("SIJISHE_COOKIE")
    username = os.environ.get("SIJISHE_USERNAME")
    password = os.environ.get("SIJISHE_PASSWORD")
    # 注意：不要把密码明文打进日志（Actions 日志可能被协作者/他人看到）
    print(f"username: {username or '(未配置)'}")
    print(f"password: {'已配置' if password else '(未配置)'}")
    print(f"cookie:   {'已配置' if cookie else '(未配置)'}")
    if not cookie and (not username or not password):
        raise RuntimeError("Missing SIJISHE_USERNAME / PASSWORD / COOKIE")

    return [
        {
            "username": username or "cookie_user",
            "password": password,
            "cookie": cookie,
        }
    ]


def get_random_string(length: int) -> str:
    return "".join(random.choices(string.ascii_letters, k=length))


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def safe_get(session: requests.Session, url: str, desc: str):
    """带 403 降级的 GET"""
    try:
        r = session.get(url, timeout=15)
        if r.status_code == 403:
            print(f"⚠️ {desc} 被拒绝 (403)，IP / WAF 限制，跳过")
            return None
        r.raise_for_status()
        return r
    except Exception as e:
        print(f"❌ {desc} 请求失败: {e}")
        return None


def safe_post(session: requests.Session, url: str, desc: str, data: dict, headers: dict = None):
    """带 403 降级的 POST（登录用）"""
    try:
        r = session.post(url, data=data, headers=headers or {}, timeout=15)
        if r.status_code == 403:
            print(f"⚠️ {desc} 被拒绝 (403)，IP / WAF 限制")
            return None
        r.raise_for_status()
        return r
    except Exception as e:
        print(f"❌ {desc} 请求失败: {e}")
        return None


def get_input_value(soup: BeautifulSoup, name: str) -> str:
    el = soup.find("input", {"name": name})
    return el["value"] if el and el.has_attr("value") else "Unknown"


def export_fresh_cookie(session: requests.Session):
    """账号密码登录成功后，把会话 Cookie 导出到文件，供 workflow 回写 GitHub Secret。

    当前 session 用的请求走 WARP 代理（ALL_PROXY），但导出文件只是本地落盘，
    与网络无关。导出的是 name=value; ... 形式的 Cookie 头字符串，可直接喂回
    SIJISHE_COOKIE 使用。
    """
    export_path = os.environ.get("COOKIE_EXPORT_FILE")
    if not export_path:
        return  # 未配置导出路径则跳过（本地调试默认不写文件）
    cookies = session.cookies.get_dict()
    if not cookies:
        print("⚠️ 会话中无可用 Cookie，跳过导出")
        return
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    try:
        with open(export_path, "w", encoding="utf-8") as f:
            f.write(cookie_str)
        print(f"✅ 已将新鲜 Cookie 导出到 {export_path}（供回写 Secret）")
    except Exception as e:
        print(f"⚠️ 导出 Cookie 失败: {e}")


# --------------------------------------------------------------------------- #
# Network primitives
# --------------------------------------------------------------------------- #


def build_proxies() -> dict:
    """从环境变量显式构建 requests 代理配置。

    workflow 里设置 ALL_PROXY=socks5://127.0.0.1:40000。
    requests 对不同版本/平台的环境变量 SOCKS 代理支持有差异，
    这里显式转成 session.proxies，保证流量一定走 WARP——
    否则请求会从 GitHub 机房 IP 裸奔，必被站点 WAF 403。
    """
    all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")
    proxies = {}
    for scheme in ("https", "http"):
        val = (
            os.environ.get(f"{scheme.upper()}_PROXY")
            or os.environ.get(f"{scheme.lower()}_proxy")
            or all_proxy
        )
        if val:
            proxies[scheme] = val
    return proxies


def get_client(account: dict) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Referer": MAIN_URL + "/",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    )

    # 显式走代理（见 build_proxies 注释）
    proxies = build_proxies()
    if proxies:
        s.proxies.update(proxies)
        print(f"✅ 已启用代理: {proxies.get('https') or proxies.get('http')}")
    else:
        print("⚠️ 未检测到代理环境变量，请求将直连（机房 IP，极易被 403）")

    cookie = account.get("cookie")
    if cookie:
        # 注入 Cookie Jar，而不是裸 Cookie 头：
        # 裸 Cookie 头会被后续响应里的 Set-Cookie 整体覆盖，
        # 导致注入的登录态意外丢失（requests 的已知行为）
        for pair in cookie.split(";"):
            if "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            s.cookies.set(name.strip(), value.strip(), domain=".xsijishe.com", path="/")
        print("✅ 已注入 SIJISHE_COOKIE 到 Cookie Jar（稍后校验有效性）")
    return s


def is_logged_in(session: requests.Session) -> bool:
    """访问签到页，根据页面内容判断 Cookie 是否仍然有效。

    返回 True 表示已登录（Cookie 有效），False 表示失效/未登录。
    拿不准时保守返回 False，宁可多走一次账号密码登录。
    """
    r = safe_get(session, f"{MAIN_URL}/k_misign-sign.html", "校验登录态")
    if r is None:
        return False
    text = r.text
    # 已登录的正向标记
    if 'id="JD_sign"' in text or "今日已签" in text or "您今天已经签到" in text:
        return True
    # 未登录的负向标记
    if "请登录" in text or "action=login" in text or "用户登录" in text:
        return False
    # 既没找到签到按钮也没找到登录入口：保守认为失效，触发降级
    return False


def get_login_params(session: requests.Session):
    """解析登录页 formhash（账号密码登录时使用）"""
    referer = f"{MAIN_URL}/home.php?mod=space"
    r = safe_get(session, referer, "获取登录参数")
    if r is None:
        return {"formhash": "", "referer": referer}

    soup = BeautifulSoup(r.text, "lxml")
    el = soup.find("input", {"name": "formhash"})
    formhash = el["value"] if el and el.has_attr("value") else ""
    return {"formhash": formhash, "referer": referer}


def login(session: requests.Session, account: dict, params: dict = None):
    """账号密码登录（仅在 Cookie 失效 / 未配置 Cookie 时调用）"""
    if not account.get("username") or not account.get("password"):
        raise RuntimeError(
            "Cookie 已失效，但未配置 SIJISHE_USERNAME / SIJISHE_PASSWORD，无法降级登录"
        )

    # 清掉可能失效的 Cookie，让账号密码登录写入新的会话 Cookie
    session.cookies.clear()
    session.headers.pop("Cookie", None)

    print("⚠️ 尝试账号密码登录")
    if params is None:
        params = get_login_params(session)

    # Discuz 登录是 POST 表单提交。原来用 GET 带账号密码：
    # 既不符合真实浏览器行为（WAF 基本必拦 403），密码还会进 URL/日志
    time.sleep(random.uniform(1, 3))  # 轻微随机延迟，请求节奏更像真人
    login_url = (
        f"{MAIN_URL}/member.php?mod=logging&action=login&loginsubmit=yes"
        f"&handlekey=login&loginhash=L{get_random_string(4)}&inajax=1"
    )
    payload = {
        "formhash": params["formhash"],
        "referer": params["referer"],
        "loginfield": "username",
        "username": account["username"],
        "password": md5_hex(account["password"]),
        "questionid": "0",
        "answer": "",
        "cookietime": "2592000",
    }
    r = safe_post(
        session,
        login_url,
        "登录",
        payload,
        headers={
            "Origin": MAIN_URL,
            "Referer": f"{MAIN_URL}/member.php?mod=logging&action=login",
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    if r is None:
        raise RuntimeError("登录请求失败（可能被 403 / WAF 拦截）")
    if "欢迎您回来" in r.text:
        print("🎉 登录成功")
        export_fresh_cookie(session)  # 登录成功 → 导出新鲜 Cookie 供回写 Secret
    else:
        raise RuntimeError("账号密码登录失败（用户名/密码错误或被拦截）")


# --------------------------------------------------------------------------- #
# Check-in
# --------------------------------------------------------------------------- #


def get_check_in_params(session: requests.Session):
    referer = f"{MAIN_URL}/k_misign-sign.html"
    r = safe_get(session, referer, "签到页")
    if r is None:
        return {"href": "", "referer": referer}

    soup = BeautifulSoup(r.text, "html.parser")
    el = soup.find("a", id="JD_sign")
    if not el or not el.has_attr("href"):
        print("⚠️ 可能已签到")
        return {"href": "", "referer": referer}
    return {"href": el["href"], "referer": referer}


def do_check_in(session: requests.Session, params: dict) -> bool:
    """执行签到。返回 True=成功/今日已签，False=失败（上层据此决定是否换 IP 重试）"""
    if not params["href"]:
        print("✅ 跳过签到（未找到签到入口，可能已签到）")
        return True

    print("⏳ 执行签到...")
    r = safe_get(session, f"{MAIN_URL}/{params['href']}", "签到请求")
    if r is None:
        return False

    if "今日已签" in r.text or "您今天已经签到" in r.text:
        print("✅ 今日已签到")
        return True
    if "签到成功" in r.text:
        print("🎉 签到成功")
        return True
    print(f"⚠️ 签到异常: {r.text[:100]}")
    return False


def print_user_info(session: requests.Session):
    r = safe_get(session, f"{MAIN_URL}/k_misign-sign.html", "用户信息")
    if r is None:
        return

    soup = BeautifulSoup(r.text, "html.parser")
    print(f"签到排名：{get_input_value(soup, 'qiandaobtnnum')}")
    print(f"连续签到：{get_input_value(soup, 'lxdays')} 天")
    print(f"签到总数：{get_input_value(soup, 'lxtdays')} 天")


# --------------------------------------------------------------------------- #
# Account
# --------------------------------------------------------------------------- #


def process_account_checkin(account: dict) -> bool:
    session = get_client(account)

    # 先访问首页：建立会话、拿到站点下发的初始 Cookie，请求链更接近真实浏览器
    safe_get(session, MAIN_URL + "/", "访问首页")

    if account.get("cookie"):
        if is_logged_in(session):
            print("✅ Cookie 有效，直接签到")
        else:
            print("⚠️ Cookie 失效，降级到账号密码登录")
            login(session, account)
    else:
        print("ℹ️ 未配置 Cookie，使用账号密码登录")
        login(session, account)

    params = get_check_in_params(session)
    if not do_check_in(session, params):
        return False
    print_user_info(session)
    return True


# --------------------------------------------------------------------------- #


def main():
    accounts = get_accounts()
    all_ok = True
    for acc in accounts:
        try:
            if process_account_checkin(acc):
                print(f"✅ 完成: {acc['username']}")
            else:
                all_ok = False
                print(f"❌ 未完成: {acc['username']}（将以退出码 1 结束，触发 workflow 换 IP 重试）")
        except Exception as e:
            all_ok = False
            print(f"❌ 处理失败: {e}")
    # 有失败就非 0 退出，让 GitHub Actions 重试（重连 WARP 换出口 IP）
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
