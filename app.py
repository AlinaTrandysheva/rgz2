# app.py
import os
import sqlite3
import re
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# НАСТРОЙКИ

app = Flask(__name__)
app.config['SECRET_KEY'] = 'alina_tran_parol'   
app.config['DATABASE'] = os.path.join(app.root_path, 'dating.db')

app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Регулярки и константы для валидации
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')
PASSWORD_RE = re.compile(
    r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@#$%^&+=_.-]{6,50}$'
)  # минимум 6 символов (хотя бы буква и цифра)

MIN_AGE = 18
MAX_AGE = 80

# Ограничение на размер загружаемых файлов
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

STUDENT_FIO = "Трандышева Алина Константиновна"
STUDENT_GROUP = "ФБИ-34"


# БАЗА ДАННЫХ

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME NOT NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            gender TEXT NOT NULL,       -- 'M' / 'F'
            looking_for TEXT NOT NULL,  -- 'M' / 'F'
            about TEXT,
            photo_filename TEXT,
            is_hidden INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER NOT NULL,
            to_user_id INTEGER NOT NULL,
            created_at DATETIME NOT NULL,
            FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(from_user_id, to_user_id)  -- нельзя лайкнуть дважды
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER NOT NULL,
            to_user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at DATETIME NOT NULL,
            is_read INTEGER DEFAULT 0,  -- 0 = не прочитано, 1 = прочитано
            FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    conn.commit()
    conn.close()

init_db()


@app.context_processor
def inject_student_info():
    return dict(student_fio=STUDENT_FIO, student_group=STUDENT_GROUP)


def current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


def get_profile(user_id):
    conn = get_db()
    profile = conn.execute(
        "SELECT * FROM profiles WHERE user_id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return profile


def login_required(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            flash("Необходимо войти на сайт", "warning")
            return redirect(url_for('login', next=request.path))
        return func(*args, **kwargs)

    return wrapper


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


#  ФУНКЦИИ ВАЛИДАЦИИ

def validate_username(username: str):
    errors = []
    if not username:
        errors.append("Логин не должен быть пустым.")
    elif len(username) < 3 or len(username) > 30:
        errors.append("Длина логина должна быть от 3 до 30 символов.")
    elif not USERNAME_RE.match(username):
        errors.append(
            "Логин должен содержать только латинские буквы, цифры и символы ._-"
        )
    return errors


def validate_password(password: str):
    errors = []
    if not password:
        errors.append("Пароль не должен быть пустым.")
    elif not PASSWORD_RE.match(password):
        errors.append(
            "Пароль минимум 6 символов, должен содержать хотя бы одну букву "
            "и одну цифру. Разрешены @#$%^&+=_.-"
        )
    return errors


def validate_age(age_str: str):
    errors = []
    age_int = None
    try:
        age_int = int(age_str)
        if age_int < MIN_AGE or age_int > MAX_AGE:
            errors.append(f"Возраст должен быть от {MIN_AGE} до {MAX_AGE}.")
    except ValueError:
        errors.append("Возраст должен быть целым числом.")
    return age_int, errors


#  ГЛАВНАЯ 

@app.route("/")
def index():
    user = current_user()
    if user:
        # Перенаправляем авторизованных на dashboard
        return redirect(url_for('dashboard'))
    else:
        # Показываем лендинг неавторизованным
        return render_template("index.html")

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    # Получаем симпатии для превью
    conn = get_db()
    matches = conn.execute("""
        SELECT p.* FROM profiles p
        JOIN likes l1 ON l1.from_user_id = p.user_id AND l1.to_user_id = ?
        JOIN likes l2 ON l2.from_user_id = ? AND l2.to_user_id = p.user_id
        WHERE p.user_id != ?
        ORDER BY l1.created_at DESC
        LIMIT 5
    """, (user['id'], user['id'], user['id'])).fetchall()
    conn.close()
    return render_template("dashboard.html", matches=matches)

# РЕГИСТРАЦИЯ / ВХОД / ВЫХОД 

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # 1) данные для учётки
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        password2 = request.form.get("password2", "").strip()

        # 2) данные анкеты
        name = request.form.get("name", "").strip()
        age = request.form.get("age", "").strip()
        gender = request.form.get("gender")
        looking_for = request.form.get("looking_for")
        about = request.form.get("about", "").strip()

        file = request.files.get("photo")

        errors = []

        # валидация логина/пароля
        if not username or not USERNAME_RE.match(username):
            errors.append("Логин должен содержать только латинские буквы, цифры и ._-")

        if not password or not PASSWORD_RE.match(password):
            errors.append("Пароль должен быть длиной от 6 символов и содержать букву и цифру")

        if password != password2:
            errors.append("Пароли не совпадают")

        # валидация анкеты
        if not name:
            errors.append("Имя не должно быть пустым")

        try:
            age_int = int(age)
            if age_int < MIN_AGE or age_int > MAX_AGE:
                errors.append(f"Возраст должен быть от {MIN_AGE} до {MAX_AGE}")
        except ValueError:
            errors.append("Возраст должен быть числом")

        if gender not in ("M", "F") or looking_for not in ("M", "F"):
            errors.append("Укажите корректный пол и пол для поиска")

        photo_filename = None
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
            else:
                errors.append("Недопустимый формат фотографии (разрешены: jpg, jpeg, png, gif)")
        else:
            filename = None 

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template(
                "register.html",
                form_data={
                    "username": username,
                    "name": name,
                    "age": age,
                    "gender": gender,
                    "looking_for": looking_for,
                    "about": about,
                }
            )
        conn = get_db()
        try:
            cur = conn.cursor()

            cur.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), datetime.now())
            )
            user_id = cur.lastrowid

            if filename:
                photo_filename = f"{user_id}_{filename}"
                path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
                file.save(path)

            cur.execute(
                """
                INSERT INTO profiles (user_id, name, age, gender, looking_for, about, photo_filename)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, name, age_int, gender, looking_for, about, photo_filename)
            )

            conn.commit()

        except sqlite3.IntegrityError:
            conn.rollback()
            flash("Такой логин уже существует", "danger")
            return render_template(
                "register.html",
                form_data={
                    "username": "",
                    "name": name,
                    "age": age,
                    "gender": gender,
                    "looking_for": looking_for,
                    "about": about,
                }
            )
        finally:
            conn.close()

        session["user_id"] = user_id
        flash("Регистрация и анкета успешно сохранены!", "success")
        return redirect(url_for("profile_view"))

    return render_template("register.html", form_data={})



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Неверный логин или пароль", "danger")
            return render_template("login.html")

        session["user_id"] = user["id"]
        flash("Вы вошли на сайт", "success")
        next_page = request.args.get('next')
        return redirect(next_page or url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из аккаунта", "info")
    return redirect(url_for("index"))


# ПРОФИЛЬ (АНКЕТА) 

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    user = current_user()
    profile = get_profile(user['id'])

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        age = request.form.get("age", "").strip()
        gender = request.form.get("gender")
        looking_for = request.form.get("looking_for")
        about = request.form.get("about", "").strip()

        errors = []

        if not name:
            errors.append("Имя не должно быть пустым.")
        elif len(name) > 50:
            errors.append("Имя не должно быть длиннее 50 символов.")

        age_int, age_errors = validate_age(age)
        errors += age_errors

        if gender not in ("M", "F"):
            errors.append("Неверно указан ваш пол.")
        if looking_for not in ("M", "F"):
            errors.append("Неверно указан пол для поиска.")

        if len(about) > 1000:
            errors.append("Поле 'О себе' не должно быть длиннее 1000 символов.")

        photo_filename = profile["photo_filename"] if profile else None
        file = request.files.get("photo")
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"{user['id']}_{filename}"
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)
                photo_filename = filename
            else:
                errors.append("Фотография должна быть в формате: png, jpg, jpeg или gif.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("profile_edit.html", profile=profile)

        conn = get_db()
        if profile:
            conn.execute("""
                UPDATE profiles
                SET name = ?, age = ?, gender = ?, looking_for = ?,
                    about = ?, photo_filename = ?
                WHERE user_id = ?
            """, (name, age_int, gender, looking_for, about, photo_filename, user['id']))
        else:
            conn.execute("""
                INSERT INTO profiles (user_id, name, age, gender, looking_for, about, photo_filename)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user['id'], name, age_int, gender, looking_for, about, photo_filename))
        conn.commit()
        conn.close()

        flash("Анкета сохранена", "success")
        return redirect(url_for("index"))

    return render_template("profile_edit.html", profile=profile)

@app.route("/profile")
@login_required
def profile_view():
    user = current_user()
    profile = get_profile(user['id'])
    if not profile:
        flash("Сначала заполните анкету", "warning")
        return redirect(url_for("edit_profile"))
    return render_template("profile_view.html", user=user, profile=profile)


@app.route("/profile/hide", methods=["POST"])
@login_required
def hide_profile():
    user = current_user()
    profile = get_profile(user['id'])
    if not profile:
        flash("Сначала заполните анкету", "warning")
        return redirect(url_for("edit_profile"))

    new_value = 0 if profile["is_hidden"] else 1
    conn = get_db()
    conn.execute(
        "UPDATE profiles SET is_hidden = ? WHERE user_id = ?",
        (new_value, user['id'])
    )
    conn.commit()
    conn.close()

    if new_value:
        flash("Анкета скрыта из поиска", "info")
    else:
        flash("Анкета снова отображается в поиске", "info")

    return redirect(url_for("index"))


@app.route("/account/delete", methods=["POST"])
@login_required
def delete_account():
    user = current_user()
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user['id'],))
    conn.commit()
    conn.close()
    session.clear()
    flash("Аккаунт удалён", "info")
    return redirect(url_for("index"))


# ПОИСК АНКЕТ 

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    user = current_user()
    my_profile = get_profile(user['id'])
    if not my_profile:
        flash("Сначала заполните свою анкету", "warning")
        return redirect(url_for('edit_profile'))

    name_q = ""
    age_q = ""
    page = request.args.get("page", 1, type=int)

    if request.method == "POST":
        page = 1
        name_q = request.form.get("name", "").strip()
        age_q = request.form.get("age", "").strip()
    else:
        name_q = request.args.get("name", "").strip()
        age_q = request.args.get("age", "").strip()

    params = []
    where = [
        "is_hidden = 0",
        "user_id != ?",
        "gender = ?",
        "looking_for = ?"
    ]
    params.extend([user['id'], my_profile['looking_for'], my_profile['gender']])

    if name_q:
        where.append("name LIKE ?")
        params.append(f"%{name_q}%")

    if age_q:
        try:
            age_int = int(age_q)
            if age_int < MIN_AGE or age_int > MAX_AGE:
                flash(f"Возраст в поиске должен быть от {MIN_AGE} до {MAX_AGE}.", "warning")
            else:
                where.append("age = ?")
                params.append(age_int)
        except ValueError:
            flash("Возраст в поиске должен быть числом.", "warning")

    where_clause = " AND ".join(where)

    limit = 3
    offset = (page - 1) * limit

    conn = get_db()
    
    # Получаем профили
    rows = conn.execute(f"""
        SELECT p.* FROM profiles p
        WHERE {where_clause}
        ORDER BY id
        LIMIT ? OFFSET ?
    """, (*params, limit, offset)).fetchall()

    user_likes = conn.execute(
        "SELECT to_user_id FROM likes WHERE from_user_id = ?", 
        (user['id'],)
    ).fetchall()
    liked_user_ids = [like['to_user_id'] for like in user_likes]

    total = conn.execute(f"""
        SELECT COUNT(*) AS cnt FROM profiles
        WHERE {where_clause}
    """, params).fetchone()["cnt"]
    conn.close()

    has_next = (offset + limit) < total

    return render_template(
        "search.html",
        profiles=rows,
        page=page,
        has_next=has_next,
        name_q=name_q,
        age_q=age_q,
        liked_user_ids=liked_user_ids  
    )
# ЛАЙКИ И СООБЩЕНИЯ

@app.route("/like/<int:user_id>", methods=["POST"])
@login_required
def like_profile(user_id):
    current_user_id = session['user_id']
    conn = get_db()
    
    # Проверяем, не лайкали ли уже
    existing_like = conn.execute(
        "SELECT * FROM likes WHERE from_user_id = ? AND to_user_id = ?",
        (current_user_id, user_id)
    ).fetchone()
    
    if existing_like:
        flash("Вы уже лайкнули этого пользователя", "info")
        conn.close()
        return redirect(url_for('search'))
    
    # Проверяем взаимный лайк
    mutual_like = conn.execute(
        "SELECT * FROM likes WHERE from_user_id = ? AND to_user_id = ?",
        (user_id, current_user_id)
    ).fetchone()
    
    # Сохраняем лайк
    conn.execute(
        "INSERT INTO likes (from_user_id, to_user_id, created_at) VALUES (?, ?, ?)",
        (current_user_id, user_id, datetime.now())
    )
    conn.commit()
    
    if mutual_like:
        flash("❤️ Это взаимная симпатия! Теперь вы можете написать друг другу", "success")
    else:
        flash("❤️ Вы выразили симпатию! Ждем ответа", "info")
    
    conn.close()
    return redirect(url_for('search'))

@app.route("/matches")
@login_required
def matches():
    user_id = session['user_id']
    conn = get_db()
    
    matches = conn.execute("""
        SELECT p.* FROM profiles p
        JOIN likes l1 ON l1.from_user_id = p.user_id AND l1.to_user_id = ?
        JOIN likes l2 ON l2.from_user_id = ? AND l2.to_user_id = p.user_id
        WHERE p.user_id != ?
    """, (user_id, user_id, user_id)).fetchall()
    
    conn.close()
    return render_template("matches.html", matches=matches)

@app.route("/chat/<int:user_id>", methods=["GET", "POST"])
@login_required
def chat(user_id):
    current_user_id = session['user_id']
    conn = get_db()
    
    # Проверяем взаимные лайки
    mutual_like = conn.execute("""
        SELECT * FROM likes 
        WHERE from_user_id = ? AND to_user_id = ?
        AND EXISTS (
            SELECT 1 FROM likes 
            WHERE from_user_id = ? AND to_user_id = ?
        )
    """, (current_user_id, user_id, user_id, current_user_id)).fetchone()
    
    if not mutual_like:
        flash("Сначала нужно взаимно понравиться друг другу", "warning")
        conn.close()
        return redirect(url_for('matches'))
    
    if request.method == "POST":
        message_text = request.form.get('message', '').strip()
        if message_text:
            conn.execute(
                "INSERT INTO messages (from_user_id, to_user_id, message, created_at) VALUES (?, ?, ?, ?)",
                (current_user_id, user_id, message_text, datetime.now())
            )
            conn.commit()
            return redirect(url_for('chat', user_id=user_id))
    
    # Получаем историю сообщений
    messages = conn.execute("""
        SELECT m.*, u.username as from_username 
        FROM messages m 
        JOIN users u ON m.from_user_id = u.id 
        WHERE (m.from_user_id = ? AND m.to_user_id = ?) 
           OR (m.from_user_id = ? AND m.to_user_id = ?)
        ORDER BY m.created_at
    """, (current_user_id, user_id, user_id, current_user_id)).fetchall()
    
    partner = conn.execute(
        "SELECT p.* FROM profiles p WHERE p.user_id = ?", (user_id,)
    ).fetchone()
    
    conn.close()
    return render_template("chat.html", messages=messages, partner=partner)


if __name__ == "__main__":
    app.run(debug=True)
