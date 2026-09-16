import os
import sqlite3
import base64
import logging
from dotenv import load_dotenv
from flask import Flask, request, session, redirect, url_for, render_template_string, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()  # .env 파일을 읽어서 환경변수로 등록

app = Flask(__name__)
# Caddy가 리버스 프록시로 앞단에 있어서, Flask가 보는 연결 IP는 항상 Caddy 컨테이너의
# 내부 IP입니다. 진짜 방문자 IP는 Caddy가 넣어주는 X-Forwarded-For 헤더에 들어있는데,
# ProxyFix가 이 헤더를 읽어서 request.remote_addr을 실제 방문자 IP로 바꿔줍니다.
# x_for=1은 "프록시를 딱 한 단계(Caddy)만 신뢰한다"는 뜻입니다.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY가 설정되지 않았습니다. .env 파일을 확인하세요.")

# ---------------------- 로깅 설정 ----------------------
# 누가(IP), 어떤 요청을, 로그인 시도는 어떤 아이디로 했는지 기록합니다.
# 비밀번호는 절대 로그에 남기지 않습니다 - 성공/실패 여부와 아이디, IP만 기록합니다.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
security_logger = logging.getLogger("security")


@app.before_request
def log_request_info():
    security_logger.info(
        "REQUEST ip=%s method=%s path=%s ua=%s",
        request.remote_addr,
        request.method,
        request.path,
        request.headers.get("User-Agent", "-"),
    )

# 플래그 조각들 - .env에서 읽어옵니다. 전체 플래그 SBOB{teunteuni_is_very_cute}를
# 7글자씩 4등분: SBOB{te / unteuni / _is_ver / y_cute} (순서대로 이어 붙이면 완성)
FLAG_PART_1 = os.environ.get("FLAG_PART_1", "SBOB{te")
# 마이페이지에서는 base64로 인코딩해서 HTML에 심어두고, JS가 devtools 조작을 감지했을 때만 디코딩합니다.
FLAG_PART_1_B64 = base64.b64encode(FLAG_PART_1.encode()).decode()

DATABASE = "memo.db"


# ---------------------- DB 관련 ----------------------

def get_db():
    """요청마다 재사용할 DB 커넥션을 g 객체에 저장"""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """앱 최초 실행 시 테이블 생성 및 admin 계정/샘플 메모 시딩"""
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS memos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        db.commit()

        # admin 계정이 없으면 초기 데이터로 생성
        admin = db.execute(
            "SELECT id FROM users WHERE username = ?", ("admin",)
        ).fetchone()
        if admin is None:
            # 평문 비밀번호는 소스코드 어디에도 없습니다 - 무차별 대입으로 알아내는 게 목적입니다.
            # (같이 드린 wordlist + bruteforce 스크립트로 /login을 직접 두드려보세요)
            admin_password_hash = (
                "scrypt:32768:8:1$xLvAegGAkrF6Xc8y$4a46097a09da7c19c4c9fb384b27c79a"
                "a368ff3b6c466bd85f6f9cfa7fde9bcc8bc6248e852b67b4c4e228346e1a8f111ddfd429de02bfddd1e60fa84b509481"
            )
            cur = db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                ("admin", admin_password_hash),
            )
            admin_id = cur.lastrowid

            # 관리자 전용 메모 - 소유권 검증이 걸려있는 정상 경로로는 admin만 봅니다.
            # (2번 플래그 조각은 이 메모 안에 평문으로 심어두고, 별도의 '공유' 기능에서
            # 검증을 빼먹는 방식으로 IDOR을 만듭니다 - 아래 memo_share 라우트 참고)
            flag_part_2 = os.environ.get("FLAG_PART_2", "unteuni")
            admin_memo_content = (
                "이 메모는 관리자만 볼 수 있어야 합니다.\n"
                f"[2/4] {flag_part_2}"
            )

            db.execute(
                "INSERT INTO memos (user_id, title, content) VALUES (?, ?, ?)",
                (admin_id, "관리자 전용 메모", admin_memo_content),
            )
            db.commit()


# ---------------------- 접근 제어 데코레이터 ----------------------

from functools import wraps


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            flash("관리자만 접근할 수 있습니다.")
            return redirect(url_for("home"))
        return view_func(*args, **kwargs)
    return wrapped


# ---------------------- HTML 템플릿 (파일 하나로 유지하기 위해 문자열로 관리) ----------------------

SHOP_CSS = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Jua&family=Gowun+Dodum&display=swap" rel="stylesheet">
<style>
    :root {
        --cream: #FFF9F2;
        --card: #FFFFFF;
        --brown: #5C4433;
        --brown-soft: #8A6E5C;
        --pink: #F6B8C4;
        --pink-dark: #E58CA0;
        --mint: #BFE3D0;
        --gold: #F0C34D;
        --line: #F0DCC8;
    }
    * {
        box-sizing: border-box;
    }
    html, body {
        margin: 0;
        padding: 0;
        background-color: var(--cream);
        color: var(--brown);
        font-family: 'Gowun Dodum', sans-serif;
    }
    .shop-topbar {
        background-color: var(--brown);
        color: var(--cream);
        text-align: center;
        font-size: 12px;
        letter-spacing: 0.3px;
        padding: 6px 12px;
    }
    .site-header {
        display: flex;
        align-items: center;
        max-width: 640px;
        margin: 0 auto;
        padding: 16px 24px 0;
    }
    .site-header .brand {
        display: flex;
        align-items: center;
        gap: 10px;
        text-decoration: none;
    }
    .site-header .brand img {
        width: 44px;
        height: 44px;
        border-radius: 50%;
        object-fit: cover;
        border: 2px solid var(--pink);
    }
    .site-header .brand .brand-text {
        display: flex;
        flex-direction: column;
    }
    .site-header .brand-text .brand-name {
        font-family: 'Jua', sans-serif;
        font-size: 20px;
        color: var(--brown);
        line-height: 1.2;
    }
    .site-header .brand-text .brand-tagline {
        font-size: 11px;
        color: var(--brown-soft);
        letter-spacing: 0.5px;
    }
    .content-box {
        position: relative;
        max-width: 640px;
        margin: 16px auto 60px;
        padding: 28px 32px;
        background-color: var(--card);
        border-radius: 24px;
        box-shadow: 0 8px 24px rgba(92, 68, 51, 0.08);
        line-height: 1.7;
    }
    .content-box::after {
        content: "";
        display: table;
        clear: both;
    }
    h1 {
        font-family: 'Jua', sans-serif;
        font-size: 26px;
        font-weight: normal;
        color: var(--brown);
        border-bottom: 2px dashed var(--line);
        padding-bottom: 14px;
        margin-top: 0;
    }
    a {
        color: var(--pink-dark);
        text-decoration: none;
        font-weight: bold;
    }
    a:hover {
        text-decoration: underline;
    }
    input[type="text"], input[type="password"], textarea {
        background-color: var(--cream);
        color: var(--brown);
        border: 2px solid var(--line);
        border-radius: 12px;
        padding: 10px 12px;
        font-family: inherit;
        font-size: 15px;
        margin: 4px 0 14px 0;
        width: 100%;
        outline: none;
    }
    input[type="text"]:focus, input[type="password"]:focus, textarea:focus {
        border-color: var(--pink);
    }
    input[type="submit"] {
        background-color: var(--gold);
        color: var(--brown);
        border: none;
        border-radius: 999px;
        padding: 10px 24px;
        font-family: 'Jua', sans-serif;
        font-size: 15px;
        cursor: pointer;
    }
    input[type="submit"]:hover {
        background-color: var(--pink);
    }
    ul.flash {
        list-style: none;
        padding: 10px 14px;
        margin: 0 0 16px;
        background-color: var(--mint);
        color: var(--brown);
        border-radius: 12px;
        font-size: 14px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
    }
    th {
        text-align: left;
        color: var(--brown-soft);
        font-weight: normal;
        padding-bottom: 8px;
        border-bottom: 2px dashed var(--line);
    }
    td {
        padding: 10px 0;
        border-bottom: 1px solid var(--line);
    }
    .nav-links a {
        display: inline-block;
        margin: 0 6px 6px 0;
        padding: 6px 14px;
        background-color: var(--cream);
        border: 2px solid var(--line);
        border-radius: 999px;
        font-size: 14px;
        font-weight: normal;
    }
    .nav-links a:hover {
        background-color: var(--pink);
        border-color: var(--pink);
        text-decoration: none;
    }
    .product-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
        gap: 14px;
        margin-top: 4px;
    }
    .product-card {
        position: relative;
        display: block;
        border: 1px solid var(--line);
        border-radius: 16px;
        overflow: hidden;
        background-color: var(--cream);
        color: var(--brown);
        text-decoration: none;
        font-weight: normal;
    }
    .product-card:hover {
        border-color: var(--pink);
        text-decoration: none;
    }
    .product-card img {
        width: 100%;
        aspect-ratio: 1 / 1;
        object-fit: cover;
        display: block;
    }
    .product-card .card-body {
        display: block;
        padding: 8px 10px 10px;
    }
    .product-card .card-title {
        display: block;
        font-size: 14px;
        font-weight: bold;
        color: var(--brown);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        margin-bottom: 2px;
    }
    .product-card .card-meta {
        font-size: 11px;
        color: var(--brown-soft);
    }
    .badge-new {
        position: absolute;
        top: 8px;
        left: 8px;
        background-color: var(--gold);
        color: var(--brown);
        font-family: 'Jua', sans-serif;
        font-size: 11px;
        padding: 2px 9px;
        border-radius: 999px;
    }
    .product-detail-img {
        display: block;
        width: 100%;
        max-width: 280px;
        border-radius: 16px;
        margin: 0 auto 18px;
    }
    .admin-flag-cell .hidden-flag {
        display: inline-block;
        margin-left: 10px;
        padding: 2px 10px;
        background-color: var(--mint);
        color: var(--brown);
        border-radius: 999px;
        font-size: 12px;
        font-weight: bold;
    }
    .admin-flag-cell .hidden-flag:empty {
        display: none;
        margin: 0;
        padding: 0;
    }
    .mini-gallery {
        display: flex;
        gap: 10px;
        margin: 4px 0 18px;
    }
    .mini-gallery img {
        flex: 1;
        min-width: 0;
        aspect-ratio: 1 / 1;
        object-fit: cover;
        border-radius: 14px;
        border: 2px solid var(--line);
    }
    .hero {
        text-align: center;
        margin-bottom: 8px;
    }
    .hero img {
        width: 200px;
        border-radius: 20px;
    }
    .hero h1 {
        border-bottom: none;
    }
    .page-header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 16px;
        margin-bottom: 8px;
    }
    .page-header h1 {
        border-bottom: none;
        padding-bottom: 0;
        margin-bottom: 6px;
    }
    .page-header img {
        width: 110px;
        border-radius: 16px;
        flex-shrink: 0;
    }
    .speech-wrap {
        display: flex;
        flex-direction: column;
        align-items: center;
        flex-shrink: 0;
    }
    .speech-bubble {
        position: relative;
        background-color: var(--mint);
        color: var(--brown);
        padding: 8px 12px;
        border-radius: 14px;
        font-size: 12px;
        font-weight: bold;
        margin-bottom: 10px;
        max-width: 130px;
        text-align: center;
        line-height: 1.4;
    }
    .speech-bubble::after {
        content: "";
        position: absolute;
        bottom: -7px;
        left: 50%;
        transform: translateX(-50%);
        border-width: 7px 7px 0 7px;
        border-style: solid;
        border-color: var(--mint) transparent transparent transparent;
    }
    .empty-state {
        text-align: center;
        padding: 20px 0;
        color: var(--brown-soft);
    }
    .empty-state img {
        width: 120px;
        border-radius: 16px;
        margin-bottom: 12px;
    }
    .site-footer {
        max-width: 640px;
        margin: 0 auto 40px;
        text-align: center;
        color: var(--brown-soft);
        font-size: 13px;
    }
    ::selection {
        background: var(--pink);
        color: var(--brown);
    }
</style>
"""

BASE_TEMPLATE = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>{{ title }} · 튼튼이 굿즈샵</title>
    """ + SHOP_CSS + """
</head>
<body>
    <div class="shop-topbar">🐾 우리집 튼튼이가 사장인 굿즈샵 · teuntteuni.shop</div>
    <header class="site-header">
        <a href="{{ url_for('home') }}" class="brand">
            <img src="{{ url_for('static', filename='img/logo.png') }}" alt="튼튼이">
            <span class="brand-text">
                <span class="brand-name">튼튼이 굿즈샵</span>
                <span class="brand-tagline">TTEUNTTEUNI PET SHOP</span>
            </span>
        </a>
    </header>
    <div class="content-box">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <ul class="flash">
                {% for msg in messages %}
                    <li>{{ msg }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}
        {{ content|safe }}
    </div>
    <footer class="site-footer">🐾 teuntteuni.shop · 튼튼이가 만든 작은 굿즈샵</footer>
</body>
</html>
"""

HOME_LOGGED_IN = """
<h1>어서오세요, {{ username }}님 🐾</h1>
<div class="mini-gallery">
    <img src="{{ url_for('static', filename='img/thumb1.png') }}" alt="튼튼이">
    <img src="{{ url_for('static', filename='img/thumb7.png') }}" alt="튼튼이">
    <img src="{{ url_for('static', filename='img/thumb5.png') }}" alt="튼튼이">
</div>
<p class="nav-links">
    <a href="{{ url_for('memo_list') }}">📦 내 굿즈함</a>
    <a href="{{ url_for('board') }}">🛍️ 전체 상품</a>
    <a href="{{ url_for('mypage') }}">🙋 마이페이지</a>
    {% if is_admin %}<a href="{{ url_for('admin_users') }}">⚙️ 관리자 페이지</a>{% endif %}
    <a href="{{ url_for('logout') }}">로그아웃</a>
</p>
"""

HOME_LOGGED_OUT = """
<div class="hero">
    <img src="{{ url_for('static', filename='img/hero.png') }}" alt="튼튼이">
    <h1>어서오세요, 튼튼이 굿즈샵입니다 🐾</h1>
    <p style="color:var(--brown-soft);">튼튼이가 플래그를 4조각으로 갈기갈기 찢어놨어요!</p>
</div>
<p class="nav-links" style="text-align:center;">
    <a href="{{ url_for('login') }}">로그인</a>
    <a href="{{ url_for('register') }}">회원가입</a>
</p>
"""

REGISTER_FORM = """
<div class="page-header">
    <h1>회원가입</h1>
    <div class="speech-wrap">
        <div class="speech-bubble">✏️ 문제는 쉬울거에요 멍</div>
        <img src="{{ url_for('static', filename='img/register.png') }}" alt="튼튼이">
    </div>
</div>
<form method="post">
    아이디 <input type="text" name="username" required><br>
    비밀번호 <input type="password" name="password" required><br>
    <input type="submit" value="가입하기">
</form>
<p><a href="{{ url_for('login') }}">이미 계정이 있으신가요? 로그인</a></p>
"""

LOGIN_FORM = """
<div class="page-header">
    <h1>로그인</h1>
    <div class="speech-wrap">
        <div class="speech-bubble">✏️ 주인님이 아이디는 admin 이래요!</div>
        <img src="{{ url_for('static', filename='img/login.png') }}" alt="튼튼이">
    </div>
</div>
<form method="post">
    아이디 <input type="text" name="username" required><br>
    비밀번호 <input type="password" name="password" required><br>
    <input type="submit" value="로그인">
</form>
<p><a href="{{ url_for('register') }}">계정이 없으신가요? 회원가입</a></p>
"""

MEMO_LIST = """
<h1>📦 내 굿즈함</h1>
<p class="nav-links">
    <a href="{{ url_for('memo_new') }}">+ 새 상품 등록</a>
    <a href="{{ url_for('board') }}">🛍️ 전체 상품</a>
    <a href="{{ url_for('home') }}">홈으로</a>
</p>
{% if memos %}
    <div class="product-grid">
    {% for memo in memos %}
        <a class="product-card" href="{{ url_for('memo_detail', memo_id=memo['id']) }}">
            {% if loop.first %}<span class="badge-new">NEW</span>{% endif %}
            <img src="{{ url_for('static', filename='img/thumb' ~ ((memo['id'] % 8) + 1) ~ '.png') }}" alt="{{ memo['title'] }}">
            <span class="card-body">
                <span class="card-title">{{ memo['title'] }}</span>
                <span class="card-meta">{{ memo['created_at'] }}</span>
            </span>
        </a>
    {% endfor %}
    </div>
{% else %}
    <div class="empty-state">
        <img src="{{ url_for('static', filename='img/empty.png') }}" alt="튼튼이">
        <p>아직 등록한 상품이 없어요. 첫 상품을 등록해보세요!</p>
    </div>
{% endif %}
"""

MEMO_DETAIL = """
<img class="product-detail-img" src="{{ url_for('static', filename='img/thumb' ~ ((memo['id'] % 8) + 1) ~ '.png') }}" alt="{{ memo['title'] }}">
<h1>{{ memo['title'] }}</h1>
<p style="color:var(--brown-soft);">등록자: {{ memo['author'] }} · {{ memo['created_at'] }}</p>
<pre style="white-space: pre-wrap; word-break: break-all; font-family: inherit; background:var(--cream); border-radius:12px; padding:14px;">{{ memo['content'] }}</pre>
<p class="nav-links">
{% if can_manage %}
    <a href="{{ url_for('memo_edit', memo_id=memo['id']) }}">수정</a>
    <a href="{{ url_for('memo_delete', memo_id=memo['id']) }}" onclick="return confirm('정말 삭제하시겠습니까?');">삭제</a>
{% endif %}
    <a href="{{ url_for('memo_share', memo_id=memo['id']) }}">🔗 공유용 보기</a>
    <a href="{{ url_for('board') }}">전체 상품으로</a>
</p>
"""

MEMO_SHARE = """
<h1 style="font-size:20px;">🔗 공유용 보기</h1>
<p style="color:var(--brown-soft); margin-top:-8px;">누구에게나 공유할 수 있는 미리보기 화면입니다.</p>
<h2 style="font-family:'Jua', sans-serif; font-size:22px; font-weight:normal; margin-bottom:4px;">{{ memo['title'] }}</h2>
<p style="color:var(--brown-soft);">등록자: {{ memo['author'] }} · {{ memo['created_at'] }}</p>
<pre style="white-space: pre-wrap; word-break: break-all; font-family: inherit; background:var(--cream); border-radius:12px; padding:14px;">{{ memo['content'] }}</pre>
<p class="nav-links"><a href="{{ url_for('board') }}">전체 상품으로</a></p>
"""

MEMO_FORM = """
<h1>{{ '상품 수정' if memo else '새 상품 등록' }}</h1>
<form method="post">
    상품명 <input type="text" name="title" value="{{ memo['title'] if memo else '' }}" required><br>
    설명<br>
    <textarea name="content" rows="8" required>{{ memo['content'] if memo else '' }}</textarea><br>
    <input type="submit" value="{{ '수정 완료' if memo else '등록 완료' }}">
</form>
<p><a href="{{ url_for('memo_list') }}">취소하고 목록으로</a></p>
"""

BOARD_LIST = """
<h1>🛍️ 전체 상품</h1>
<p class="nav-links">
    <a href="{{ url_for('memo_list') }}">📦 내 굿즈함</a>
    <a href="{{ url_for('home') }}">홈으로</a>
</p>
{% if memos %}
    <div class="product-grid">
    {% for memo in memos %}
        <a class="product-card" href="{{ url_for('memo_detail', memo_id=memo['id']) }}">
            {% if loop.first %}<span class="badge-new">NEW</span>{% endif %}
            <img src="{{ url_for('static', filename='img/thumb' ~ ((memo['id'] % 8) + 1) ~ '.png') }}" alt="{{ memo['title'] }}">
            <span class="card-body">
                <span class="card-title">{{ memo['title'] }}</span>
                <span class="card-meta">{{ memo['author'] }} · {{ memo['created_at'] }}</span>
            </span>
        </a>
    {% endfor %}
    </div>
{% else %}
    <div class="empty-state">
        <img src="{{ url_for('static', filename='img/empty.png') }}" alt="튼튼이">
        <p>아직 등록된 상품이 없어요.</p>
    </div>
{% endif %}
"""

ADMIN_USERS = """
<div class="page-header">
    <h1>관리자: 회원 목록</h1>
    <img src="{{ url_for('static', filename='img/admin.png') }}" alt="튼튼이">
</div>
<p class="nav-links"><a href="{{ url_for('home') }}">홈으로</a></p>
<table>
    <tr><th>ID</th><th>username</th><th>admin</th></tr>
    {% for user in users %}
    <tr>
        <td>{{ user['id'] }}</td>
        <td>{{ user['username'] }}</td>
        <td>{{ 'Y' if user['is_admin'] else 'N' }}</td>
    </tr>
    {% endfor %}
</table>
"""

MY_PAGE = """
<h1>🙋 마이페이지</h1>
<p class="nav-links"><a href="{{ url_for('home') }}">홈으로</a></p>
<table>
    <tr><th>아이디</th><td>{{ username }}</td></tr>
    <tr><th>등록한 상품 수</th><td>{{ memo_count }}개</td></tr>
    <tr>
        <th>회원 등급</th>
        <td class="admin-flag-cell" data-admin="{{ 'Y' if is_admin else 'N' }}" data-flag-b64="{{ flag_part_1_b64 }}">
            {{ 'Y' if is_admin else 'N' }}
            <span class="hidden-flag"></span>
        </td>
    </tr>
</table>
<script>
(function () {
    document.querySelectorAll('.admin-flag-cell').forEach(function (cell) {
        var reveal = function () {
            var val = (cell.getAttribute('data-admin') || '').toLowerCase();
            var span = cell.querySelector('.hidden-flag');
            var b64 = cell.getAttribute('data-flag-b64');
            if (val === 'y' && span && b64 && !span.textContent) {
                span.textContent = '[1/4] ' + atob(b64);
            }
        };
        new MutationObserver(reveal).observe(cell, { attributes: true, attributeFilter: ['data-admin'] });
    });
})();
</script>
"""


def render(content_template, title, **context):
    content = render_template_string(content_template, **context)
    return render_template_string(BASE_TEMPLATE, title=title, content=content)


# ---------------------- 라우트 ----------------------

@app.route("/")
def home():
    if "user_id" in session:
        return render(
            HOME_LOGGED_IN, "홈",
            username=session.get("username"),
            is_admin=session.get("is_admin", False),
        )
    return render(HOME_LOGGED_OUT, "홈")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력해주세요.")
            return redirect(url_for("register"))

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            flash("이미 존재하는 아이디입니다.")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
        flash("회원가입이 완료되었습니다. 로그인해주세요.")
        return redirect(url_for("login"))

    return render(REGISTER_FORM, "회원가입")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            # 실습용으로 시도한 비밀번호까지 기록합니다.
            # (실제 서비스라면 비밀번호는 절대 로그에 남기면 안 됩니다 - 재사용된
            # 진짜 비밀번호가 새어나갈 수 있어서요. 여기선 본인만 쓰는 연습 환경이라 켭니다.)
            security_logger.warning(
                "LOGIN FAILED username=%s password=%s ip=%s",
                username, password, request.remote_addr,
            )
            flash("아이디 또는 비밀번호가 일치하지 않습니다.")
            return redirect(url_for("login"))

        # 로그인 성공 -> 세션에 사용자 정보 저장 (세션 유지)
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])
        security_logger.info(
            "LOGIN SUCCESS username=%s password=%s ip=%s",
            username, password, request.remote_addr,
        )
        flash("로그인되었습니다.")
        return redirect(url_for("home"))

    return render(LOGIN_FORM, "로그인")


@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("home"))


# ---------------------- 메모 CRUD ----------------------
# 핵심 규칙: 모든 조회/수정/삭제는 "memo.user_id == session['user_id']" 조건을 SQL에 직접 포함시킨다.
# URL의 memo_id만으로 접근을 허용하면 IDOR(다른 사용자 메모 접근) 취약점이 생기므로 반드시 소유자 검증을 같이 건다.

@app.route("/memos")
@login_required
def memo_list():
    db = get_db()
    memos = db.execute(
        "SELECT * FROM memos WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],),
    ).fetchall()
    return render(MEMO_LIST, "내 메모", memos=memos)


@app.route("/memos/new", methods=["GET", "POST"])
@login_required
def memo_new():
    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"].strip()

        if not title or not content:
            flash("제목과 내용을 모두 입력해주세요.")
            return redirect(url_for("memo_new"))

        db = get_db()
        db.execute(
            "INSERT INTO memos (user_id, title, content) VALUES (?, ?, ?)",
            (session["user_id"], title, content),
        )
        db.commit()
        flash("메모가 작성되었습니다.")
        return redirect(url_for("memo_list"))

    return render(MEMO_FORM, "새 메모", memo=None)


def get_memo_with_owner(memo_id):
    """작성자 정보(username, is_admin)까지 조인해서 메모 하나를 가져온다. 없으면 None."""
    db = get_db()
    return db.execute("""
        SELECT memos.*, users.username AS author, users.is_admin AS author_is_admin
        FROM memos
        JOIN users ON memos.user_id = users.id
        WHERE memos.id = ?
    """, (memo_id,)).fetchone()


def can_view_memo(memo):
    """
    열람 권한 규칙:
    - 작성자가 admin인 메모는 admin 본인만 볼 수 있다 (게시판 비공개, IDOR 테스트 대상).
    - 그 외 일반 사용자 메모는 로그인한 사람이면 누구나 볼 수 있다 (게시판 공개).
    """
    if memo is None:
        return False
    if memo["author_is_admin"]:
        return session.get("user_id") == memo["user_id"]
    return True


def can_manage_memo(memo):
    """수정/삭제 권한: 작성자 본인이거나 admin이면 가능."""
    if memo is None:
        return False
    return session.get("user_id") == memo["user_id"] or bool(session.get("is_admin"))


@app.route("/memos/<int:memo_id>")
@login_required
def memo_detail(memo_id):
    memo = get_memo_with_owner(memo_id)
    if not can_view_memo(memo):
        flash("메모를 찾을 수 없거나 접근 권한이 없습니다.")
        return redirect(url_for("memo_list"))
    return render(MEMO_DETAIL, "메모 상세", memo=memo, can_manage=can_manage_memo(memo))


@app.route("/memos/<int:memo_id>/share")
@login_required
def memo_share(memo_id):
    # NOTE: 공유 링크로 미리보기를 보여주는 기능입니다.
    # memo_detail과 달리 can_view_memo() 소유권 검증을 호출하지 않아서,
    # 로그인만 되어 있으면 memo_id를 바꿔가며 아무 메모나 볼 수 있습니다 (IDOR).
    memo = get_memo_with_owner(memo_id)
    if memo is None:
        flash("메모를 찾을 수 없습니다.")
        return redirect(url_for("memo_list"))
    return render(MEMO_SHARE, "공유용 보기", memo=memo)


@app.route("/memos/<int:memo_id>/edit", methods=["GET", "POST"])
@login_required
def memo_edit(memo_id):
    memo = get_memo_with_owner(memo_id)
    if not can_manage_memo(memo):
        flash("메모를 찾을 수 없거나 수정 권한이 없습니다.")
        return redirect(url_for("memo_list"))

    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"].strip()

        if not title or not content:
            flash("제목과 내용을 모두 입력해주세요.")
            return redirect(url_for("memo_edit", memo_id=memo_id))

        db = get_db()
        db.execute(
            "UPDATE memos SET title = ?, content = ? WHERE id = ?",
            (title, content, memo_id),
        )
        db.commit()
        flash("메모가 수정되었습니다.")
        return redirect(url_for("memo_detail", memo_id=memo_id))

    return render(MEMO_FORM, "메모 수정", memo=memo)


@app.route("/memos/<int:memo_id>/delete")
@login_required
def memo_delete(memo_id):
    memo = get_memo_with_owner(memo_id)
    if not can_manage_memo(memo):
        flash("메모를 찾을 수 없거나 삭제 권한이 없습니다.")
        return redirect(url_for("memo_list"))

    db = get_db()
    db.execute("DELETE FROM memos WHERE id = ?", (memo_id,))
    db.commit()
    flash("메모가 삭제되었습니다.")
    return redirect(url_for("memo_list"))


# ---------------------- 게시판 (일반 사용자 메모 전체 공개) ----------------------

@app.route("/board")
@login_required
def board():
    db = get_db()
    memos = db.execute("""
        SELECT memos.*, users.username AS author
        FROM memos
        JOIN users ON memos.user_id = users.id
        WHERE users.is_admin = 0
        ORDER BY memos.created_at DESC
    """).fetchall()
    return render(BOARD_LIST, "게시판", memos=memos)


# ---------------------- 마이페이지 ----------------------

@app.route("/mypage")
@login_required
def mypage():
    db = get_db()
    memo_count = db.execute(
        "SELECT COUNT(*) AS cnt FROM memos WHERE user_id = ?", (session["user_id"],)
    ).fetchone()["cnt"]
    return render(
        MY_PAGE, "마이페이지",
        username=session.get("username"),
        is_admin=session.get("is_admin", False),
        memo_count=memo_count,
        flag_part_1_b64=FLAG_PART_1_B64,
    )


# ---------------------- 관리자 기능 ----------------------

@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    users = db.execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall()
    return render(ADMIN_USERS, "관리자: 회원 목록", users=users)


# ---------------------- robots.txt ----------------------
# NOTE: robots.txt는 "검색엔진 크롤러야, 여긴 긁지 마"라고 알려주는 용도일 뿐,
# 실제로 그 경로를 못 보게 막아주는 기능이 전혀 아닙니다. 오히려 사람이 직접
# 읽으면 "아, 여기에 뭔가 있구나"를 알려주는 힌트가 되어버립니다.
@app.route("/robots.txt")
def robots_txt():
    return (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /static/backup/\n"
    ), 200, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000, debug=True)
