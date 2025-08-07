# -*- coding: utf-8 -*-
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import pandas as pd

APP_FOLDER = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_FOLDER, "db.sqlite3")
ACCESS_LOG_PATH = os.getenv("ACCESS_LOG_PATH", os.path.join(APP_FOLDER, "access.log"))
TIMEZONE_SHIFT = int(os.getenv("TIMEZONE_SHIFT", 0))
PER_PAGE = 50

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
bcrypt = Bcrypt(app)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def parse_log_line(line):
    try:
        parts = line.strip().split()
        dt = " ".join(parts[0:2])
        ip_port = parts[3]
        protocol_dst = parts[5]
        protocol = protocol_dst.split(":")[0]
        domain = ":".join(protocol_dst.split(":")[1:])
        inbound = "-"
        direction = "-"
        if "[" in line and "]" in line:
            meta = line.split("[",1)[1].split("]",1)[0].strip()  # inbound-51561 >> direct
            if ">>" in meta:
                inbound = meta.split(">>")[0].strip()
                direction = meta.split(">>")[1].strip()
            else:
                inbound = meta
        email = "-"
        if "email:" in line:
            email = line.split("email:")[-1].strip()
        ip = ip_port.split(":")[0]
        dt_obj = datetime.strptime(dt, "%Y/%m/%d %H:%M:%S.%f") + timedelta(hours=TIMEZONE_SHIFT)
        return {
            "datetime": dt_obj.strftime("%d.%m.%Y %H:%M:%S"),
            "ip": ip,
            "protocol": protocol,
            "domain": domain,
            "inbound": inbound,
            "direction": direction,
            "email": email,
            "raw": line.strip()
        }
    except Exception:
        return None

def read_logs():
    logs = []
    if not os.path.exists(ACCESS_LOG_PATH):
        return logs
    with open(ACCESS_LOG_PATH, "r") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                logs.append(parsed)
    return list(reversed(logs))

def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.check_password_hash(hashed, password)

def get_admins():
    db = get_db()
    res = db.execute("SELECT id, username FROM admins").fetchall()
    db.close()
    return res

def init_admin(username, password):
    db = get_db()
    db.execute("INSERT INTO admins (username, password) VALUES (?, ?)", (username, hash_password(password)))
    db.commit()
    db.close()

def verify_admin(username, password):
    db = get_db()
    res = db.execute("SELECT password FROM admins WHERE username=?", (username,)).fetchone()
    db.close()
    if res and check_password(password, res["password"]):
        return True
    return False

@app.route("/", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if verify_admin(username, password):
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Неверный логин или пароль!", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    logs = read_logs()
    total = len(logs)
    return render_template("dashboard.html", logs=logs, total=total)

@app.route("/logs")
def logs():
    if "user" not in session:
        return redirect(url_for("login"))
    logs = read_logs()
    q_email = request.args.get("email", "").strip()
    q_ip = request.args.get("ip", "").strip()
    q_domain = request.args.get("domain", "").strip()
    q_inbound = request.args.get("inbound", "").strip()
    q_direction = request.args.get("direction", "").strip()
    q_date = request.args.get("date", "").strip()
    filtered = []
    for l in logs:
        if q_email and q_email not in l["email"]:
            continue
        if q_ip and q_ip not in l["ip"]:
            continue
        if q_domain and q_domain not in l["domain"]:
            continue
        if q_inbound and q_inbound not in l["inbound"]:
            continue
        if q_direction and q_direction not in l["direction"]:
            continue
        if q_date and q_date not in l["datetime"]:
            continue
        filtered.append(l)
    page = int(request.args.get("page", 1))
    total = len(filtered)
    per_page = PER_PAGE
    pages = (total + per_page - 1) // per_page
    paged = filtered[(page-1)*per_page:page*per_page]
    return render_template("logs.html", logs=paged, page=page, pages=pages, total=total,
                           q_email=q_email, q_ip=q_ip, q_domain=q_domain, q_inbound=q_inbound, q_direction=q_direction, q_date=q_date)

@app.route("/logs_json")
def logs_json():
    if "user" not in session:
        return jsonify({"logs": []})
    logs = read_logs()
    return jsonify({"logs": logs[:50]})  # Можно сделать больше/меньше

@app.route("/export")
def export():
    if "user" not in session:
        return redirect(url_for("login"))
    logs = read_logs()
    q_email = request.args.get("email", "").strip()
    q_ip = request.args.get("ip", "").strip()
    q_domain = request.args.get("domain", "").strip()
    q_inbound = request.args.get("inbound", "").strip()
    q_direction = request.args.get("direction", "").strip()
    q_date = request.args.get("date", "").strip()
    filtered = []
    for l in logs:
        if q_email and q_email not in l["email"]:
            continue
        if q_ip and q_ip not in l["ip"]:
            continue
        if q_domain and q_domain not in l["domain"]:
            continue
        if q_inbound and q_inbound not in l["inbound"]:
            continue
        if q_direction and q_direction not in l["direction"]:
            continue
        if q_date and q_date not in l["datetime"]:
            continue
        filtered.append(l)
    df = pd.DataFrame(filtered)
    export_type = request.args.get("type", "csv")
    if export_type == "xlsx":
        export_path = os.path.join(APP_FOLDER, "logs_export.xlsx")
        df.to_excel(export_path, index=False)
        return send_file(export_path, as_attachment=True)
    else:
        export_path = os.path.join(APP_FOLDER, "logs_export.csv")
        df.to_csv(export_path, index=False)
        return send_file(export_path, as_attachment=True)

@app.route("/clear", methods=["POST"])
def clear_logs():
    if "user" not in session:
        return redirect(url_for("login"))
    open(ACCESS_LOG_PATH, "w").close()
    flash("Логи успешно очищены!", "success")
    return redirect(url_for("logs"))

@app.route("/rotate", methods=["POST"])
def rotate_logs():
    if "user" not in session:
        return redirect(url_for("login"))
    logs = read_logs()[-500:]
    with open(ACCESS_LOG_PATH, "w") as f:
        for l in logs:
            f.write(l["raw"] + "\n")
    flash("Логи успешно ротированы (оставлено 500 последних)!", "success")
    return redirect(url_for("logs"))

@app.route("/delete_by_filter", methods=["POST"])
def delete_by_filter():
    if "user" not in session:
        return redirect(url_for("login"))
    logs = read_logs()
    q_email = request.form.get("email", "").strip()
    q_ip = request.form.get("ip", "").strip()
    q_domain = request.form.get("domain", "").strip()
    q_inbound = request.form.get("inbound", "").strip()
    q_direction = request.form.get("direction", "").strip()
    q_date = request.form.get("date", "").strip()
    to_keep = []
    for l in logs:
        if q_email and q_email not in l["email"]:
            to_keep.append(l)
            continue
        if q_ip and q_ip not in l["ip"]:
            to_keep.append(l)
            continue
        if q_domain and q_domain not in l["domain"]:
            to_keep.append(l)
            continue
        if q_inbound and q_inbound not in l["inbound"]:
            to_keep.append(l)
            continue
        if q_direction and q_direction not in l["direction"]:
            to_keep.append(l)
            continue
        if q_date and q_date not in l["datetime"]:
            to_keep.append(l)
            continue
    with open(ACCESS_LOG_PATH, "w") as f:
        for l in to_keep:
            f.write(l["raw"] + "\n")
    flash("Записи по фильтру удалены!", "success")
    return redirect(url_for("logs"))

@app.route("/top")
def top():
    if "user" not in session:
        return redirect(url_for("login"))
    logs = read_logs()
    from collections import Counter
    emails = Counter([l["email"] for l in logs if l["email"]])
    ips = Counter([l["ip"] for l in logs if l["ip"]])
    domains = Counter([l["domain"] for l in logs if l["domain"]])
    inbounds = Counter([l["inbound"] for l in logs if l["inbound"]])
    return render_template("top.html", emails=emails.most_common(10),
                           ips=ips.most_common(10),
                           domains=domains.most_common(10),
                           inbounds=inbounds.most_common(10))

@app.route("/settings", methods=["GET", "POST"])
def settings():
    global TIMEZONE_SHIFT
    if "user" not in session:
        return redirect(url_for("login"))
    tz = TIMEZONE_SHIFT
    if request.method == "POST":
        try:
            shift = int(request.form["tz"])
            os.environ["TIMEZONE_SHIFT"] = str(shift)
            TIMEZONE_SHIFT = shift
            flash("Часовой пояс успешно изменён!", "success")
        except Exception:
            flash("Ошибка изменения часового пояса!", "danger")
    return render_template("settings.html", tz=TIMEZONE_SHIFT)

@app.route("/admins", methods=["GET", "POST"])
def admins():
    if "user" not in session:
        return redirect(url_for("login"))
    admins = get_admins()
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or not password:
            flash("Заполните логин и пароль!", "danger")
        else:
            try:
                init_admin(username, password)
                flash("Админ добавлен!", "success")
            except:
                flash("Ошибка при добавлении админа!", "danger")
    return render_template("admins.html", admins=admins)

def init_db():
    if not os.path.exists(DB_PATH):
        db = get_db()
        db.execute("""
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
        """)
        db.commit()
        db.close()

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8060)))
