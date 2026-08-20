#!/usr/bin/env python3
"""Sijishe CLI - Python port (GitHub Actions hardened).

✅ Session + 浏览器级 Header
✅ Cookie 注入（SIJISHE_COOKIE 优先）
✅ 403 降级（不抛异常、不炸 workflow）
"""

import hashlib
import os
import random
import string
import sys
import time
from pathlib import Path

import requests
from bs4 import BeautifulSoup

MAIN_URL = "https://xsijishe.com"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def get_accounts():
    # Cookie 优先（Action 唯一稳的方式）
    if os.getenv("SIJISHE_COOKIE"):
        return [{"username": "cookie_user"}]

    username = os.environ.get("SIJISHE_USERNAME")
    password = os.environ.get("SIJISHE_PASSWORD")
    if not username or not password:
        raise RuntimeError("Missing SIJISHE_USERNAME / PASSWORD / COOKIE")
    return [{"username": username, "password": password}]


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

def get_client() -> requests.Session:
    s = requests.Session()
    s.headers.update(session.headers.update(
        {
            "accept": "*/*",
            "accept-language": "zh-CN,zh;q=0.9",
            "content-type": "application/json",
            "origin": "https://xsijishe.com",
            "priority": "u=1, i",
            "referer": "https://xsijishe.com/",
            "sec-ch-ua": "\"Not=A?Brand\";v=\"99\", \"Google Chrome\";v=\"151\", \"Chromium\";v=\"151\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
        }
    ))

    cookie = os.getenv("SIJISHE_COOKIE")
    if cookie:
        s.headers.update({"Cookie": cookie})
        print("✅ 已注入 SIJISHE_COOKIE")
    return s


def get_login_params(session: requests.Session):
    """有 Cookie 直接跳过，避免 403"""
    if "Cookie" in session.headers:
        print("✅ 使用 Cookie，跳过登录页解析")
        return {"formhash": "", "referer": f"{MAIN_URL}/home.php?mod=space"}

    referer = f"{MAIN_URL}/home.php?mod=space"
    r = safe_get(session, referer, "获取登录参数")
    if r is None:
        return {"formhash": "", "referer": referer}

    soup = BeautifulSoup(r.text, "lxml")
    el = soup.find("input", {"name": "formhash"})
    formhash = el["value"] if el and el.has_attr("value") else ""
    return {"formhash": formhash, "referer": referer}


def login(session: requests.Session, account: dict, params: dict):
    if "Cookie" in session.headers:
        print("✅ Cookie 已登录，跳过账号密码登录")
        return

    print("⚠️ 尝试账号密码登录（GitHub IP 极易 403）")
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
        return
    if "欢迎您回来" in r.text:
        print("🎉 登录成功")
    else:
        raise RuntimeError("登录失败")


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
    session = get_client()
    params = get_login_params(session)
    login(session, account, params)
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
