#!/usr/bin/env python3
"""Sijishe CLI - Python port of the Rust sijishe client.

Interacts with xsijishe.com: check-in and buy threads across multiple accounts.

Original Rust behaviour is preserved:
  - accounts are read from <config_dir>/sijishe/accounts.json
  - each account gets its own cookie jar (a fresh requests.Session)
  - login uses md5(password); check-in / buy parse the same DOM markers
"""

import hashlib
import os
import platform
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
def get_config_dir() -> Path:
    """Mirror dirs::config_dir().join("sijishe")."""
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif system == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "sijishe"


def get_random_string(length: int) -> str:
    """Alphabetic-only random string, like rand::distr::Alphabetic."""
    return "".join(random.choices(string.ascii_letters, k=length))


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def retry_with_backoff(func, retries: int = 3, base_delay: float = 0.01):
    """Exponential backoff + jitter, matching tokio_retry semantics."""
    last_exc = None
    for attempt in range(retries):
        try:
            return func()
        except Exception as e:  # noqa: BLE001 - mirror Rust retry semantics
            last_exc = e
            if attempt < retries - 1:
                delay = base_delay * (2**attempt)
                delay += random.uniform(0, delay)  # jitter
                time.sleep(delay)
    raise last_exc


def get_input_value(soup: BeautifulSoup, name: str) -> str:
    el = soup.find("input", {"name": name})
    if el and el.has_attr("value"):
        return el["value"]
    return "Unknown"


# --------------------------------------------------------------------------- #
# Network primitives
# --------------------------------------------------------------------------- #
def get_client() -> requests.Session:
    """A reqwest Client with cookie_store(true); referer set per-request."""
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114.0 Safari/537.36",
        }
    )
    return session


def get_login_params(session: requests.Session):
    referer = f"{MAIN_URL}/home.php?mod=space"
    resp = session.get(referer, headers={"Referer": f"{MAIN_URL}/"})
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    el = soup.find("input", {"name": "formhash"})
    formhash = el["value"] if el and el.has_attr("value") else ""
    return {"formhash": formhash, "referer": referer}


def login(session: requests.Session, account: dict, params: dict):
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
    resp = session.post(login_url, headers={"Referer": params["referer"]}, data=payload)
    resp.raise_for_status()
    text = resp.text
    if "欢迎您回来" in text:
        print("🎉 [Success] Login successful!")
        return
    raise RuntimeError(f"Login failed. Response snippet: {text[:100]}")


def get_check_in_params(session: requests.Session):
    referer = f"{MAIN_URL}/k_misign-sign.html"

    def attempt():
        resp = session.get(referer, headers={"Referer": f"{MAIN_URL}/"})
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        el = soup.find("a", id="JD_sign")
        if not el or not el.has_attr("href"):
            raise RuntimeError("Failed to get check in href (maybe already checked in)")
        return el["href"]

    href = retry_with_backoff(attempt, retries=3, base_delay=0.01)
    return {"href": href, "referer": referer}


def do_check_in(session: requests.Session, params: dict):
    print("⏳ Executing check-in operation...")
    check_in_url = f"{MAIN_URL}/{params['href']}"
    resp = session.get(check_in_url, headers={"Referer": params["referer"]})
    resp.raise_for_status()
    text = resp.text
    if "今日已签" in text or "您今天已经签到过了" in text:
        print("✅ Already checked in today.")
    elif "签到成功" in text or "CDATA" in text:
        print("🎉 Check-in successful!")
    else:
        print(f"⚠️ Check-in failed or returned unexpected response: {text[:100]}")


def print_user_info(session: requests.Session):
    print("🔎 Fetching user info...")
    url = f"{MAIN_URL}/k_misign-sign.html"
    resp = session.get(url, headers={"Referer": f"{MAIN_URL}/"})
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    qiandao_num = get_input_value(soup, "qiandaobtnnum")
    lxdays = get_input_value(soup, "lxdays")
    lxtdays = get_input_value(soup, "lxtdays")
    lxlevel = get_input_value(soup, "lxlevel")
    lxreward = get_input_value(soup, "lxreward")

    p_el = soup.select_one("li.nexmemberinfostwos > p")
    total_reward = p_el.decode_contents() if p_el else "Unknown"

    print(f"签到排名：{qiandao_num}")
    print(f"签到等级：Lv.{lxlevel}")
    print(f"连续签到：{lxdays} 天")
    print(f"签到总数：{lxtdays} 天")
    print(f"签到奖励：{lxreward}")
    print(f"总积分：{total_reward}")


# --------------------------------------------------------------------------- #
# Account-level orchestration
# --------------------------------------------------------------------------- #
def process_account_checkin(account: dict):
    session = get_client()
    params = get_login_params(session)
    print(f"📝 Fetched login params: formhash={params['formhash']}")
    login(session, account, params)
    params = get_check_in_params(session)
    print(f"📝 Fetched check-in params: href={params['href']}")
    do_check_in(session, params)
    print_user_info(session)


# --------------------------------------------------------------------------- #
# Shell completion (mirrors clap_complete generate)
# --------------------------------------------------------------------------- #


def main(argv=None) -> int:
    account = {"username": "516464301@qq.com", "password": "Zx15911067023"}
    try:
        process_account_checkin(account)
        print(f"✅ Finished processing for {account['username']}")
    except Exception as e:  # noqa: BLE001
        print(f"❌ Error processing {account['username']}: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    main()
