#!/usr/bin/env python3
"""Sijishe CLI - Python port (GitHub Actions hardened).

✅ Session + 浏览器级 Header
✅ Cookie 注入（SIJISHE_COOKIE 优先）
✅ Cookie 失效自动降级到账号密码登录（SIJISHE_USERNAME / SIJISHE_PASSWORD）
✅ 403 降级（不抛异常、不炸 workflow），但登录/降级失败会明确报错
"""

import hashlib
import os
import random
import string

import requests
from bs4 import BeautifulSoup

MAIN_URL = "https://xsijishe.com"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def get_accounts():
    # Cookie 与账号密码都允许存在：运行时优先试 Cookie，失效再降级到密码
    cookie = os.getenv("SIJISHE_COOKIE")
    username = os.environ.get("SIJISHE_USERNAME")
    password = os.environ.get("SIJISHE_PASSWORD")

    if not cookie and (not username or not password):
        raise RuntimeError("Missing SIJISHE_USERNAME / PASSWORD / COOKIE")

    return [{
        "username": username or "cookie_user",
        "password": password,
        "cookie": cookie,
    }]


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


def get_input_value(soup: BeautifulSoup, name: str) -> str:
    el = soup.find("input", {"name": name})
    return el["value"] if el and el.has_attr("value") else "Unknown"


# --------------------------------------------------------------------------- #
# Network primitives
# --------------------------------------------------------------------------- #


def get_client(account: dict) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Referer": MAIN_URL + "/",
            "Connection": "keep-alive",
        }
    )

    cookie = account.get("cookie")
    if cookie:
        s.headers.update({"Cookie": cookie})
        print("✅ 已注入 SIJISHE_COOKIE（稍后校验有效性）")
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

    # 清掉可能失效的手动 Cookie，让账号密码登录写入新的会话 Cookie
    session.headers.pop("Cookie", None)

    print("⚠️ 尝试账号密码登录")
    if params is None:
        params = get_login_params(session)

    login_url = (
        f"{MAIN_URL}/member.php?mod=logging&action=login&loginsubmit=yes"
        f"&handlekey=login&loginhash=L{get_random_string(4)}&inajax=1"
    )
    payload = {
        "formhash": params["formhash"],
        "referer": params["referer"],
        "username": account["username"],
        "password": md5_hex(account["password"]),
        "questionid": "0",
        "answer": "",
    }
    r = safe_get(session, login_url, "登录")
    if r is None:
        raise RuntimeError("登录请求失败（可能被 403 / WAF 拦截）")
    if "欢迎您回来" in r.text:
        print("🎉 登录成功")
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


def do_check_in(session: requests.Session, params: dict):
    if not params["href"]:
        print("✅ 跳过签到")
        return

    print("⏳ 执行签到...")
    r = safe_get(session, f"{MAIN_URL}/{params['href']}", "签到请求")
    if r is None:
        return

    if "今日已签" in r.text or "您今天已经签到过了" in r.text:
        print("✅ 今日已签到")
    elif "签到成功" in r.text:
        print("🎉 签到成功")
    else:
        print(f"⚠️ 签到异常: {r.text[:100]}")


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


def process_account_checkin(account: dict):
    session = get_client(account)

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
    do_check_in(session, params)
    print_user_info(session)


# --------------------------------------------------------------------------- #


def main():
    accounts = get_accounts()
    for acc in accounts:
        try:
            process_account_checkin(acc)
            print(f"✅ 完成: {acc['username']}")
        except Exception as e:
            print(f"❌ 处理失败: {e}")


if __name__ == "__main__":
    main()
