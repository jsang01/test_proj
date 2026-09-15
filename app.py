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
    """앱 최초 실행 시 users 테이블 생성"""
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        db.commit()


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
<p><a href="{{ url_for('logout') }}">[ 로그아웃 ]</a></p>
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


def render(content_template, title, **context):
    content = render_template_string(content_template, **context)
    return render_template_string(BASE_TEMPLATE, title=title, content=content)


# ---------------------- 라우트 ----------------------

@app.route("/")
def home():
    if "user_id" in session:
        return render(HOME_LOGGED_IN, "홈", username=session.get("username"))
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
        flash("로그인되었습니다.")
        return redirect(url_for("home"))

    return render(LOGIN_FORM, "로그인")


@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)