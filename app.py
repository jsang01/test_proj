import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template_string, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key"  # 실제 배포 시엔 반드시 랜덤 문자열로 교체하세요

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
            admin_password_hash = generate_password_hash("admin1234!")  # 반드시 나중에 변경하세요
            cur = db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                ("admin", admin_password_hash),
            )
            admin_id = cur.lastrowid
            db.execute(
                "INSERT INTO memos (user_id, title, content) VALUES (?, ?, ?)",
                (admin_id, "관리자 전용 메모", "SBOB{admin_only_memo_change_me}"),
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

HACKER_CSS = """
<style>
    * {
        box-sizing: border-box;
    }
    html, body {
        margin: 0;
        padding: 0;
        background-color: #0d0d0d;
        color: #00ff41;
        font-family: 'Courier New', monospace;
    }
    #matrix-bg {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 0;
    }
    #terminal-bg {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        overflow: hidden;
        z-index: 0;
        opacity: 0.35;
        mask-image: linear-gradient(to bottom, transparent, black 10%, black 90%, transparent);
        -webkit-mask-image: linear-gradient(to bottom, transparent, black 10%, black 90%, transparent);
    }
    #terminal-text {
        margin: 0;
        padding: 0 16px;
        color: #00ff41;
        font-family: 'Courier New', monospace;
        font-size: 14px;
        white-space: pre-wrap;
        animation: scroll-up 40s linear infinite;
    }
    @keyframes scroll-up {
        from { transform: translateY(0); }
        to   { transform: translateY(-50%); }
    }
    .content-box {
        position: relative;
        z-index: 1;
        max-width: 480px;
        margin: 60px auto;
        padding: 20px 24px;
        background-color: rgba(0, 0, 0, 0.75);
        border: 1px solid #00ff41;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
        line-height: 1.6;
    }
    h1 {
        border-bottom: 1px solid #00ff41;
        padding-bottom: 10px;
        text-shadow: 0 0 6px #00ff41;
    }
    a {
        color: #00ff41;
        text-decoration: none;
        border-bottom: 1px dashed #00ff41;
    }
    a:hover {
        color: #0d0d0d;
        background-color: #00ff41;
    }
    input[type="text"], input[type="password"] {
        background-color: #000;
        color: #00ff41;
        border: 1px solid #00ff41;
        padding: 6px 8px;
        font-family: inherit;
        margin: 4px 0 12px 0;
        width: 100%;
        outline: none;
    }
    input[type="text"]:focus, input[type="password"]:focus {
        box-shadow: 0 0 6px #00ff41;
    }
    input[type="submit"] {
        background-color: #00ff41;
        color: #0d0d0d;
        border: none;
        padding: 8px 16px;
        font-family: inherit;
        font-weight: bold;
        cursor: pointer;
    }
    input[type="submit"]:hover {
        background-color: #00cc33;
    }
    ul {
        list-style: none;
        padding-left: 0;
        color: #ffcc00;
        border: 1px solid #ffcc00;
        padding: 8px 12px;
    }
    ::selection {
        background: #00ff41;
        color: #0d0d0d;
    }
</style>
"""

BASE_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>{{ title }}</title>
    """ + HACKER_CSS + """
</head>
<body>
    <div id="terminal-bg"><pre id="terminal-text"></pre></div>
    <div class="content-box">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <ul>
                {% for msg in messages %}
                    <li>&gt; {{ msg }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}
        {{ content|safe }}
    </div>
    <script>
        // 실제로 스캔을 실행하는 게 아니라, 화면 연출용으로 nmap 출력 형태의 텍스트를 흉내낸 것입니다.
        const nmapLines = [
            "Starting Nmap 7.94 ( https://nmap.org )",
            "Nmap scan report for 192.168.0.101",
            "Host is up (0.0021s latency).",
            "Not shown: 996 closed tcp ports (reset)",
            "PORT     STATE SERVICE     VERSION",
            "22/tcp   open  ssh         OpenSSH 8.9p1",
            "80/tcp   open  http        nginx 1.24.0",
            "443/tcp  open  https       nginx 1.24.0",
            "3306/tcp open  mysql       MySQL 8.0.34",
            "8080/tcp open  http-proxy",
            "Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel",
            "Nmap scan report for 192.168.0.102",
            "Host is up (0.0038s latency).",
            "PORT     STATE SERVICE",
            "21/tcp   open  ftp",
            "23/tcp   filtered telnet",
            "139/tcp  open  netbios-ssn",
            "445/tcp  open  microsoft-ds",
            "OS details: Linux 5.X - 6.X",
            "Nmap done: 2 IP addresses (2 hosts up) scanned in 6.42 seconds",
            "",
            "$ nmap -sV -O 192.168.0.0/24",
            "$ nmap -p- --min-rate 5000 192.168.0.101",
            "$ nmap --script vuln 192.168.0.101",
            ""
        ];

        const terminalEl = document.getElementById('terminal-text');
        // 화면을 꽉 채우도록 충분히 반복
        let fullText = "";
        for (let i = 0; i < 8; i++) {
            fullText += nmapLines.join("\\n") + "\\n";
        }
        terminalEl.textContent = fullText;
    </script>
</body>
</html>
"""

HOME_LOGGED_IN = """
<h1>&gt; ACCESS GRANTED: {{ username }}</h1>
<p><a href="{{ url_for('memo_list') }}">[ 내 메모 ]</a>
{% if is_admin %} &nbsp; <a href="{{ url_for('admin_users') }}">[ 관리자 페이지 ]</a>{% endif %}
&nbsp; <a href="{{ url_for('logout') }}">[ 로그아웃 ]</a></p>
"""

HOME_LOGGED_OUT = """
<h1>&gt; MEMO_SERVICE.exe</h1>
<p><a href="{{ url_for('login') }}">[ 로그인 ]</a> &nbsp; <a href="{{ url_for('register') }}">[ 회원가입 ]</a></p>
"""

REGISTER_FORM = """
<h1>&gt; NEW_USER_REGISTRATION</h1>
<form method="post">
    ID: <input type="text" name="username" required><br>
    PW: <input type="password" name="password" required><br>
    <input type="submit" value="가입하기">
</form>
<p><a href="{{ url_for('login') }}">이미 계정이 있으신가요? 로그인</a></p>
"""

LOGIN_FORM = """
<h1>&gt; LOGIN_TERMINAL</h1>
<form method="post">
    ID: <input type="text" name="username" required><br>
    PW: <input type="password" name="password" required><br>
    <input type="submit" value="로그인">
</form>
<p><a href="{{ url_for('register') }}">계정이 없으신가요? 회원가입</a></p>
"""

MEMO_LIST = """
<h1>&gt; MY_MEMOS</h1>
<p><a href="{{ url_for('memo_new') }}">[ + 새 메모 작성 ]</a> &nbsp; <a href="{{ url_for('home') }}">[ 홈으로 ]</a></p>
{% if memos %}
    <table style="width:100%; border-collapse: collapse;">
    {% for memo in memos %}
        <tr>
            <td style="padding:4px 0;">
                <a href="{{ url_for('memo_detail', memo_id=memo['id']) }}">{{ memo['title'] }}</a>
            </td>
            <td style="text-align:right; color:#888;">{{ memo['created_at'] }}</td>
        </tr>
    {% endfor %}
    </table>
{% else %}
    <p>&gt; 작성된 메모가 없습니다.</p>
{% endif %}
"""

MEMO_DETAIL = """
<h1>&gt; {{ memo['title'] }}</h1>
<pre style="white-space: pre-wrap; font-family: inherit;">{{ memo['content'] }}</pre>
<p style="color:#888;">작성일: {{ memo['created_at'] }}</p>
<p>
    <a href="{{ url_for('memo_edit', memo_id=memo['id']) }}">[ 수정 ]</a> &nbsp;
    <a href="{{ url_for('memo_delete', memo_id=memo['id']) }}" onclick="return confirm('정말 삭제하시겠습니까?');">[ 삭제 ]</a> &nbsp;
    <a href="{{ url_for('memo_list') }}">[ 목록으로 ]</a>
</p>
"""

MEMO_FORM = """
<h1>&gt; {{ '메모 수정' if memo else '새 메모 작성' }}</h1>
<form method="post">
    제목: <input type="text" name="title" value="{{ memo['title'] if memo else '' }}" required><br>
    내용:<br>
    <textarea name="content" rows="8" style="width:100%; background:#000; color:#00ff41; border:1px solid #00ff41; font-family:inherit; padding:6px;" required>{{ memo['content'] if memo else '' }}</textarea><br><br>
    <input type="submit" value="{{ '수정 완료' if memo else '작성 완료' }}">
</form>
<p><a href="{{ url_for('memo_list') }}">[ 취소하고 목록으로 ]</a></p>
"""

ADMIN_USERS = """
<h1>&gt; ADMIN: USER_LIST</h1>
<p><a href="{{ url_for('home') }}">[ 홈으로 ]</a></p>
<table style="width:100%; border-collapse: collapse;">
    <tr><th style="text-align:left;">ID</th><th style="text-align:left;">username</th><th style="text-align:left;">admin</th></tr>
    {% for user in users %}
    <tr>
        <td>{{ user['id'] }}</td>
        <td>{{ user['username'] }}</td>
        <td>{{ 'Y' if user['is_admin'] else 'N' }}</td>
    </tr>
    {% endfor %}
</table>
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
            flash("아이디 또는 비밀번호가 일치하지 않습니다.")
            return redirect(url_for("login"))

        # 로그인 성공 -> 세션에 사용자 정보 저장 (세션 유지)
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])
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


def get_own_memo_or_none(memo_id):
    """memo_id가 현재 로그인한 사용자의 메모일 때만 반환. 아니면 None (본인 메모 아님/존재하지 않음 모두 동일하게 처리)."""
    db = get_db()
    return db.execute(
        "SELECT * FROM memos WHERE id = ? AND user_id = ?",
        (memo_id, session["user_id"]),
    ).fetchone()


@app.route("/memos/<int:memo_id>")
@login_required
def memo_detail(memo_id):
    memo = get_own_memo_or_none(memo_id)
    if memo is None:
        flash("메모를 찾을 수 없거나 접근 권한이 없습니다.")
        return redirect(url_for("memo_list"))
    return render(MEMO_DETAIL, "메모 상세", memo=memo)


@app.route("/memos/<int:memo_id>/edit", methods=["GET", "POST"])
@login_required
def memo_edit(memo_id):
    memo = get_own_memo_or_none(memo_id)
    if memo is None:
        flash("메모를 찾을 수 없거나 접근 권한이 없습니다.")
        return redirect(url_for("memo_list"))

    if request.method == "POST":
        title = request.form["title"].strip()
        content = request.form["content"].strip()

        if not title or not content:
            flash("제목과 내용을 모두 입력해주세요.")
            return redirect(url_for("memo_edit", memo_id=memo_id))

        db = get_db()
        db.execute(
            "UPDATE memos SET title = ?, content = ? WHERE id = ? AND user_id = ?",
            (title, content, memo_id, session["user_id"]),
        )
        db.commit()
        flash("메모가 수정되었습니다.")
        return redirect(url_for("memo_detail", memo_id=memo_id))

    return render(MEMO_FORM, "메모 수정", memo=memo)


@app.route("/memos/<int:memo_id>/delete")
@login_required
def memo_delete(memo_id):
    memo = get_own_memo_or_none(memo_id)
    if memo is None:
        flash("메모를 찾을 수 없거나 접근 권한이 없습니다.")
        return redirect(url_for("memo_list"))

    db = get_db()
    db.execute(
        "DELETE FROM memos WHERE id = ? AND user_id = ?",
        (memo_id, session["user_id"]),
    )
    db.commit()
    flash("메모가 삭제되었습니다.")
    return redirect(url_for("memo_list"))


# ---------------------- 관리자 기능 ----------------------

@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    users = db.execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall()
    return render(ADMIN_USERS, "관리자: 회원 목록", users=users)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)