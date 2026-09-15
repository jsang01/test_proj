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

BASE_TEMPLATE = """
<!doctype html>
<html>
<head><title>{{ title }}</title></head>
<body>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>
            {% for msg in messages %}
                <li>{{ msg }}</li>
            {% endfor %}
            </ul>
        {% endif %}
    {% endwith %}
    {{ content|safe }}
</body>
</html>
"""

HOME_LOGGED_IN = """
<h1>환영합니다, {{ username }}님</h1>
<p><a href="{{ url_for('logout') }}">로그아웃</a></p>
"""

HOME_LOGGED_OUT = """
<h1>메모 서비스</h1>
<p><a href="{{ url_for('login') }}">로그인</a> | <a href="{{ url_for('register') }}">회원가입</a></p>
"""

REGISTER_FORM = """
<h1>회원가입</h1>
<form method="post">
    아이디: <input type="text" name="username" required><br>
    비밀번호: <input type="password" name="password" required><br>
    <input type="submit" value="가입하기">
</form>
<p><a href="{{ url_for('login') }}">이미 계정이 있으신가요? 로그인</a></p>
"""

LOGIN_FORM = """
<h1>로그인</h1>
<form method="post">
    아이디: <input type="text" name="username" required><br>
    비밀번호: <input type="password" name="password" required><br>
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
