import hashlib
import os
import pickle
import sqlite3
import subprocess
import tempfile

import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file
from werkzeug.security import safe_join
from werkzeug.utils import secure_filename

app = Flask(__name__)

API_TOKEN = "Zx9fK2mQ7xLp4RtV8nZ3wB6yHcT1aE5u"

DB_PATH = "/tmp/shop.db"
FILES_DIR = "/srv/files"
AVATAR_DIR = "/srv/avatars"


def db():
    return sqlite3.connect(DB_PATH)


@app.route("/")
def index():
    return "Shop API"


@app.route("/users")
def search_user():
    username = request.args.get("name", "")
    query = "SELECT id, name FROM users WHERE name = '" + username + "'"
    return str(db().execute(query).fetchall())


@app.route("/orders/<order_id>")
def get_order(order_id):
    query = "SELECT * FROM orders WHERE id = %d" % int(order_id)
    return str(db().execute(query).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/uptime")
def uptime():
    return subprocess.check_output("uptime", shell=True)


@app.route("/config", methods=["POST"])
def load_config():
    data = yaml.load(request.data)
    return str(data)


@app.route("/hello")
def greet():
    name = request.args.get("name", "")
    return "<h1>Hello %s</h1>" % name


@app.route("/preview")
def preview():
    title = request.args.get("title", "")
    return render_template_string("<h2>" + title + "</h2>")


@app.route("/about")
def about():
    return render_template_string("<p>Shop API version {{ version }}</p>", version="1.0")


@app.route("/files")
def download():
    name = request.args.get("name", "")
    return send_file(os.path.join(FILES_DIR, name))


@app.route("/avatars")
def get_avatar():
    name = secure_filename(request.args.get("name", "default.png"))
    return send_file(safe_join(AVATAR_DIR, name))


@app.route("/go")
def go():
    return redirect(request.args.get("next", "/"))


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "0")
    return str(eval(expression))


@app.route("/session", methods=["POST"])
def restore_session():
    session = pickle.loads(request.data)
    return str(session)


@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password", "")
    digest = hashlib.md5(password.encode()).hexdigest()
    db().execute("INSERT INTO users (name, password) VALUES (?, ?)",
                 (request.form.get("name", ""), digest))
    return "ok"


@app.route("/etag")
def etag():
    with open(__file__, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest()


@app.route("/thumbs")
def thumbnail_key():
    name = request.args.get("name", "")
    return hashlib.sha1(name.encode()).hexdigest()


@app.route("/stats/<kind>")
def stats(kind):
    table = "orders" if kind == "orders" else "users"
    query = f"SELECT COUNT(*) FROM {table}"
    return str(db().execute(query).fetchall())


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    return requests.get(url, verify=False, timeout=5).text


@app.route("/export")
def export_report():
    path = tempfile.mktemp(suffix=".csv")
    with open(path, "w") as fh:
        fh.write("id,name\n")
    return send_file(path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
