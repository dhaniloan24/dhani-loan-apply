import os, re, io, secrets, sqlite3, smtplib
from datetime import datetime
from email.message import EmailMessage
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None

APP_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(APP_DIR, "loan_portal.db"))
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(APP_DIR, "private_uploads"))
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "pdf"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "CHANGE-THIS-TO-A-LONG-RANDOM-SECRET")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
os.makedirs(UPLOAD_DIR, exist_ok=True)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL,
            full_name TEXT NOT NULL, aadhaar_enc TEXT NOT NULL, pan_enc TEXT NOT NULL,
            bank_enc TEXT NOT NULL, ifsc TEXT NOT NULL, amount REAL NOT NULL,
            work_type TEXT NOT NULL, monthly_income REAL NOT NULL,
            customer_photo TEXT, aadhaar_photo TEXT, pan_photo TEXT,
            status TEXT NOT NULL DEFAULT 'Received', admin_note TEXT DEFAULT ''
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )""")
        if not con.execute("SELECT id FROM admins LIMIT 1").fetchone():
            username = os.environ.get("ADMIN_USERNAME", "admin")
            password = os.environ.get("ADMIN_PASSWORD", "")
            if password:
                con.execute("INSERT INTO admins(username,password_hash) VALUES (?,?)",
                            (username, generate_password_hash(password)))

def cipher():
    key = os.environ.get("DATA_ENCRYPTION_KEY", "")
    if not key or Fernet is None:
        raise RuntimeError("Secure data encryption is not configured. Set DATA_ENCRYPTION_KEY and install requirements.")
    return Fernet(key.encode())

def encrypt(value):
    return cipher().encrypt(value.encode()).decode()

def decrypt(value):
    return cipher().decrypt(value.encode()).decode()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)
    return wrapper

def valid_upload(file):
    if not file or not file.filename:
        return None
    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Upload only JPG, PNG, WEBP or PDF files.")
    data = file.read(MAX_UPLOAD_BYTES + 1)
    file.seek(0)
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Each file must be 5 MB or smaller.")
    # Verify image bytes when image extensions are used. PDFs are allowed for documents.
    if ext in {"jpg", "jpeg"} and not data.startswith(b"\xff\xd8\xff"):
        raise ValueError("Invalid JPEG file.")
    if ext == "png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Invalid PNG file.")
    if ext == "pdf" and not data.startswith(b"%PDF"):
        raise ValueError("Invalid PDF file.")
    return data, ext

def save_upload(file, ref, kind):
    checked = valid_upload(file)
    if checked is None:
        return None
    data, ext = checked
    # Opaque filename; never use the supplied filename as a path.
    name = f"{ref}_{kind}_{secrets.token_hex(8)}.{ext}"
    with open(os.path.join(UPLOAD_DIR, name), "xb") as f:
        f.write(data)
    return name

def send_notification(reference, status, email_to=None):
    host = os.environ.get("SMTP_HOST")
    if not host:
        return
    msg = EmailMessage()
    msg["Subject"] = f"Loan application update: {reference}"
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", ""))
    recipient = email_to or os.environ.get("ADMIN_NOTIFY_EMAIL", "")
    if not recipient:
        return
    msg["To"] = recipient
    msg.set_content(f"Application reference: {reference}\nStatus: {status}\nPlease sign in to the admin portal for details.")
    port = int(os.environ.get("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=15) as server:
        server.starttls()
        user = os.environ.get("SMTP_USER")
        password = os.environ.get("SMTP_PASSWORD")
        if user and password:
            server.login(user, password)
        server.send_message(msg)

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    return response

@app.route("/", methods=["GET", "POST"])
def apply():
    if request.method == "POST":
        try:
            full_name = request.form.get("full_name", "").strip()
            aadhaar = re.sub(r"\s+", "", request.form.get("aadhaar", ""))
            pan = request.form.get("pan", "").strip().upper()
            bank = request.form.get("bank_account", "").strip()
            ifsc = request.form.get("ifsc", "").strip().upper()
            amount = float(request.form.get("amount", "0"))
            work_type = request.form.get("work_type", "")
            income = float(request.form.get("monthly_income", "0"))
            if len(full_name) < 2:
                raise ValueError("Please enter your full name.")
            if not re.fullmatch(r"\d{12}", aadhaar):
                raise ValueError("Aadhaar number must be 12 digits.")
            if not re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", pan):
                raise ValueError("Please enter a valid PAN format.")
            if not re.fullmatch(r"\d{6,18}", bank):
                raise ValueError("Bank account number must be 6–18 digits.")
            if not re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", ifsc):
                raise ValueError("Please enter a valid IFSC code.")
            if not (1000 <= amount <= 100000000):
                raise ValueError("Loan amount must be between ₹1,000 and ₹10,00,00,000.")
            if work_type not in {"Job", "Business", "Self-employed", "Other"}:
                raise ValueError("Please select job/business type.")
            if not (0 <= income <= 100000000):
                raise ValueError("Please enter a valid monthly income.")
            ref = "LN" + datetime.utcnow().strftime("%y%m%d") + secrets.token_hex(4).upper()
            saved = {}
            try:
                for field, kind in [("customer_photo", "customer"), ("aadhaar_photo", "aadhaar"), ("pan_photo", "pan")]:
                    saved[field] = save_upload(request.files.get(field), ref, kind)
            except Exception:
                for name in saved.values():
                    if name:
                        try: os.remove(os.path.join(UPLOAD_DIR, name))
                        except OSError: pass
                raise
            with db() as con:
                con.execute("""INSERT INTO applications
                    (reference,created_at,full_name,aadhaar_enc,pan_enc,bank_enc,ifsc,amount,work_type,monthly_income,customer_photo,aadhaar_photo,pan_photo)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (ref, datetime.utcnow().isoformat(timespec="seconds")+"Z", full_name,
                     encrypt(aadhaar), encrypt(pan), encrypt(bank), ifsc, amount, work_type, income,
                     saved.get("customer_photo"), saved.get("aadhaar_photo"), saved.get("pan_photo")))
            try:
                send_notification(ref, "Received")
            except Exception:
                app.logger.exception("Email notification failed")
            return render_template("success.html", reference=ref)
        except (ValueError, RuntimeError) as e:
            flash(str(e), "error")
        except Exception:
            app.logger.exception("Application submission failed")
            flash("Submission could not be completed. Please try again or contact the portal administrator.", "error")
    return render_template("apply.html")

@app.route("/status", methods=["GET", "POST"])
def check_status():
    application = None
    if request.method == "POST":
        ref = request.form.get("reference", "").strip().upper()
        with db() as con:
            application = con.execute("SELECT reference,created_at,status,admin_note FROM applications WHERE reference=?", (ref,)).fetchone()
        if not application:
            flash("Reference number not found.", "error")
    return render_template("status.html", application=application)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        with db() as con:
            admin = con.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_user"] = admin["username"]
            return redirect(url_for("admin_dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("admin_login.html")

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    q = request.args.get("q", "").strip()
    with db() as con:
        if q:
            rows = con.execute("SELECT * FROM applications WHERE reference LIKE ? OR full_name LIKE ? ORDER BY id DESC LIMIT 300",
                               (f"%{q}%", f"%{q}%")).fetchall()
        else:
            rows = con.execute("SELECT * FROM applications ORDER BY id DESC LIMIT 300").fetchall()
    return render_template("admin.html", applications=rows, q=q)

@app.route("/admin/application/<int:app_id>", methods=["GET", "POST"])
@admin_required
def admin_detail(app_id):
    with db() as con:
        row = con.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
    if not row:
        abort(404)
    if request.method == "POST":
        status = request.form.get("status", "")
        note = request.form.get("admin_note", "").strip()[:2000]
        allowed = {"Received", "Under Review", "Documents Required", "Approved", "Rejected", "Disbursed"}
        if status not in allowed:
            flash("Invalid status.", "error")
        else:
            with db() as con:
                con.execute("UPDATE applications SET status=?,admin_note=? WHERE id=?", (status, note, app_id))
            try:
                send_notification(row["reference"], status)
            except Exception:
                app.logger.exception("Status email failed")
            flash("Application status updated.", "success")
            return redirect(url_for("admin_detail", app_id=app_id))
    return render_template("admin_detail.html", application=row,
                           aadhaar=decrypt(row["aadhaar_enc"]), pan=decrypt(row["pan_enc"]),
                           bank=decrypt(row["bank_enc"]))

@app.route("/admin/file/<int:app_id>/<kind>")
@admin_required
def admin_file(app_id, kind):
    column = {"customer": "customer_photo", "aadhaar": "aadhaar_photo", "pan": "pan_photo"}.get(kind)
    if not column:
        abort(404)
    with db() as con:
        row = con.execute(f"SELECT {column} AS filename FROM applications WHERE id=?", (app_id,)).fetchone()
    if not row or not row["filename"]:
        abort(404)
    path = os.path.join(UPLOAD_DIR, os.path.basename(row["filename"]))
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=os.path.basename(path), conditional=False)

@app.errorhandler(413)
def too_large(_):
    return "Upload too large. Total request size must be under 20 MB.", 413

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
