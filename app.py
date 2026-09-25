import os
import sqlite3
from functools import wraps
from urllib.parse import quote

import qrcode
from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "resenatap.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "resenatap-dev-secret-change-me")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'business',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS businesses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '',
            color TEXT DEFAULT '#111827',
            review_url TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS plates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            business_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(business_id) REFERENCES businesses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plate_id INTEGER NOT NULL,
            source TEXT NOT NULL DEFAULT 'nfc',
            user_agent TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(plate_id) REFERENCES plates(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            business_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(business_id) REFERENCES businesses(id) ON DELETE CASCADE
        );
        """
    )
    db.commit()

    demo = db.execute("SELECT id FROM users WHERE email = ?", ("demo@resenatap.local",)).fetchone()
    if not demo:
        cur = db.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            ("demo@resenatap.local", generate_password_hash("demo1234"), "business"),
        )
        user_id = cur.lastrowid
        db.execute(
            """INSERT INTO businesses
               (user_id, name, slug, description, color, review_url)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                "Bar Pepe",
                "bar-pepe",
                "Un ejemplo de negocio para probar ReseñaTap.",
                "#111827",
                "https://www.google.com/search?q=Bar+Pepe+rese%C3%B1as",
            ),
        )
        business_id = db.execute("SELECT id FROM businesses WHERE user_id = ?", (user_id,)).fetchone()["id"]
        db.execute(
            "INSERT INTO plates (business_id, name, code) VALUES (?, ?, ?)",
            (business_id, "Entrada", "bar-pepe-entrada"),
        )
        db.execute(
            "INSERT INTO plates (business_id, name, code) VALUES (?, ?, ?)",
            (business_id, "Caja", "bar-pepe-caja"),
        )

    admin = db.execute("SELECT id FROM users WHERE email = ?", ("admin@resenatap.local",)).fetchone()
    if not admin:
        db.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            ("admin@resenatap.local", generate_password_hash("admin1234"), "admin"),
        )
    db.commit()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def business_for_user():
    user = current_user()
    if not user:
        return None
    return get_db().execute("SELECT * FROM businesses WHERE user_id = ?", (user["id"],)).fetchone()


@app.context_processor
def inject_globals():
    return {"current_user": current_user()}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        business_name = request.form.get("business_name", "").strip()

        if not email or not password or not business_name:
            flash("Completa todos los campos.", "error")
            return render_template("register.html")

        db = get_db()
        try:
            cur = db.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'business')",
                (email, generate_password_hash(password)),
            )
            user_id = cur.lastrowid
            base_slug = "".join(c.lower() if c.isalnum() else "-" for c in business_name).strip("-") or "negocio"
            slug = base_slug
            counter = 2
            while db.execute("SELECT id FROM businesses WHERE slug = ?", (slug,)).fetchone():
                slug = f"{base_slug}-{counter}"
                counter += 1
            db.execute(
                "INSERT INTO businesses (user_id, name, slug) VALUES (?, ?, ?)",
                (user_id, business_name, slug),
            )
            db.commit()
            flash("Cuenta creada correctamente.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            db.rollback()
            flash("Ese email ya está registrado.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            if user["role"] == "admin":
                return redirect(url_for("admin"))
            return redirect(url_for("dashboard"))

        flash("Email o contraseña incorrectos.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    business = business_for_user()
    if not business:
        abort(404)
    db = get_db()
    stats = db.execute(
        """
        SELECT
          COUNT(scans.id) AS total_scans,
          SUM(CASE WHEN scans.source = 'nfc' THEN 1 ELSE 0 END) AS nfc_scans,
          SUM(CASE WHEN scans.source = 'qr' THEN 1 ELSE 0 END) AS qr_scans
        FROM plates
        LEFT JOIN scans ON scans.plate_id = plates.id
        WHERE plates.business_id = ?
        """,
        (business["id"],),
    ).fetchone()
    plates = db.execute(
        """
        SELECT p.*,
               COUNT(s.id) AS scans,
               SUM(CASE WHEN s.source = 'nfc' THEN 1 ELSE 0 END) AS nfc_scans,
               SUM(CASE WHEN s.source = 'qr' THEN 1 ELSE 0 END) AS qr_scans
        FROM plates p
        LEFT JOIN scans s ON s.plate_id = p.id
        WHERE p.business_id = ?
        GROUP BY p.id
        ORDER BY p.id DESC
        """,
        (business["id"],),
    ).fetchall()
    return render_template("dashboard.html", business=business, stats=stats, plates=plates)


@app.route("/plates", methods=["GET", "POST"])
@login_required
def plates():
    business = business_for_user()
    if not business:
        abort(404)
    db = get_db()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        code = request.form.get("code", "").strip().lower()
        if not name or not code:
            flash("Indica un nombre y un código.", "error")
        else:
            try:
                db.execute(
                    "INSERT INTO plates (business_id, name, code) VALUES (?, ?, ?)",
                    (business["id"], name, code),
                )
                db.commit()
                flash("Placa creada.", "success")
            except sqlite3.IntegrityError:
                db.rollback()
                flash("Ese código ya existe.", "error")

    rows = db.execute(
        "SELECT * FROM plates WHERE business_id = ? ORDER BY id DESC", (business["id"],)
    ).fetchall()
    return render_template("plates.html", business=business, plates=rows)


@app.post("/plates/<int:plate_id>/delete")
@login_required
def delete_plate(plate_id):
    business = business_for_user()
    db = get_db()
    db.execute(
        "DELETE FROM plates WHERE id = ? AND business_id = ?",
        (plate_id, business["id"]),
    )
    db.commit()
    flash("Placa eliminada.", "success")
    return redirect(url_for("plates"))


@app.route("/plates/<int:plate_id>/qr.png")
@login_required
def plate_qr(plate_id):
    business = business_for_user()
    plate = get_db().execute(
        "SELECT * FROM plates WHERE id = ? AND business_id = ?", (plate_id, business["id"])
    ).fetchone()
    if not plate:
        abort(404)

    base = request.host_url.rstrip("/")
    target = f"{base}{url_for('scan', code=plate['code'])}?src=qr"
    img = qrcode.make(target)

    path = os.path.join(BASE_DIR, f"_qr_{plate_id}.png")
    img.save(path)
    return send_file(path, mimetype="image/png", as_attachment=False)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    business = business_for_user()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        color = request.form.get("color", "#111827").strip()
        review_url = request.form.get("review_url", "").strip()
        if not name:
            flash("El nombre es obligatorio.", "error")
        else:
            get_db().execute(
                """UPDATE businesses
                   SET name = ?, description = ?, color = ?, review_url = ?
                   WHERE id = ?""",
                (name, description, color, review_url, business["id"]),
            )
            get_db().commit()
            flash("Configuración guardada.", "success")
            business = business_for_user()

    return render_template("settings.html", business=business)


@app.post("/orders")
@login_required
def create_order():
    business = business_for_user()
    quantity = max(1, int(request.form.get("quantity", 1)))
    get_db().execute(
        "INSERT INTO orders (business_id, quantity) VALUES (?, ?)",
        (business["id"], quantity),
    )
    get_db().commit()
    flash("Pedido registrado correctamente.", "success")
    return redirect(url_for("dashboard"))


@app.route("/business/<slug>")
def public_business(slug):
    business = get_db().execute("SELECT * FROM businesses WHERE slug = ?", (slug,)).fetchone()
    if not business:
        abort(404)
    return render_template("business.html", business=business)


@app.route("/r/<code>")
def scan(code):
    db = get_db()
    plate = db.execute(
        """
        SELECT p.*, b.review_url, b.slug
        FROM plates p
        JOIN businesses b ON b.id = p.business_id
        WHERE p.code = ?
        """,
        (code,),
    ).fetchone()

    if not plate:
        abort(404)

    source = request.args.get("src", "nfc").lower()
    if source not in ("nfc", "qr"):
        source = "nfc"

    db.execute(
        "INSERT INTO scans (plate_id, source, user_agent, ip) VALUES (?, ?, ?, ?)",
        (plate["id"], source, request.headers.get("User-Agent", ""), request.remote_addr or ""),
    )
    db.commit()

    if plate["review_url"]:
        return redirect(plate["review_url"])
    return redirect(url_for("public_business", slug=plate["slug"]))


@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    businesses = db.execute(
        """
        SELECT b.*, u.email,
               (SELECT COUNT(*) FROM plates p WHERE p.business_id = b.id) AS plates_count,
               (SELECT COUNT(*) FROM scans s JOIN plates p2 ON p2.id = s.plate_id
                WHERE p2.business_id = b.id) AS scans_count
        FROM businesses b
        JOIN users u ON u.id = b.user_id
        ORDER BY b.id DESC
        """
    ).fetchall()
    orders = db.execute(
        """
        SELECT o.*, b.name AS business_name
        FROM orders o
        JOIN businesses b ON b.id = o.business_id
        ORDER BY o.id DESC
        """
    ).fetchall()
    return render_template("admin.html", businesses=businesses, orders=orders)


with app.app_context():
    init_db()


if __name__ == "__main__":
    import os
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )