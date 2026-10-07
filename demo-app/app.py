"""Application de démonstration VOLONTAIREMENT vulnérable.
Utilisée pour tester le pipeline TriageX. Ne jamais déployer en production."""
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

# Faux secret, présent volontairement pour tester Gitleaks
API_TOKEN = "Zx9fK2mQ7xLp4RtV8nZ3wB6yHcT1aE5u"

DB_PATH = "/tmp/users.db"


@app.route("/")
def index():
    return "TriageX demo app"


@app.route("/user")
def get_user():
    username = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    # Faille 1 : injection SQL (requête construite par concaténation)
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    rows = conn.execute(query).fetchall()
    return str(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Faille 2 : injection de commande (entrée utilisateur passée au shell)
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/config", methods=["POST"])
def load_config():
    # Faille 3 : désérialisation dangereuse (yaml.load sans chargeur sûr)
    data = yaml.load(request.data)
    return str(data)


if __name__ == "__main__":
    # Faille 4 : mode debug activé
    app.run(host="0.0.0.0", port=3000, debug=True)
