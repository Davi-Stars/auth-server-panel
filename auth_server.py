"""
Servidor de autenticação central (gratuito).
Uma única base de usuários: quando você bloqueia ou altera uma conta aqui,
todos os painéis que usam este servidor passam a respeitar na hora.

Como usar de graça:
  1. Suba este arquivo em um host gratuito (Render, Railway, PythonAnywhere, etc.).
  2. No painel (web_panel), configure a URL deste servidor (config ou variável de ambiente).
  3. Login, bloqueio e expiração passam a ser globais para todos os clientes.

Uso local (teste):
  python auth_server.py
  Roda em http://localhost:5001 (ou PORT da variável de ambiente).
"""

import os
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Diretório de dados (em produção use PWD ou variável; em Render/Railway há disco efêmero ou volume)
BASE = Path(os.environ.get("AUTH_DATA_DIR", "."))
USERS_FILE = BASE / "auth_users.json"
TOKENS_FILE = BASE / "auth_tokens.json"

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False

# Tokens ativos: token -> { "username", "is_admin" }. Persistido em arquivo para sobreviver restart.
def _load_tokens():
    if not TOKENS_FILE.exists():
        return {}
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_tokens(tokens):
    try:
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def _load_users():
    if not USERS_FILE.exists():
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def _save_users(users):
    try:
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
    except Exception as e:
        return False
    return True

def _user_by_name(username):
    for u in _load_users():
        if (u.get("username") or "").strip().lower() == (username or "").strip().lower():
            return u
    return None

def _user_blocked(username):
    u = _user_by_name(username)
    return u is not None and u.get("blocked", False)

def _user_expired(username):
    u = _user_by_name(username)
    if not u or not u.get("expires_at"):
        return False
    try:
        s = (u.get("expires_at") or "").strip()
        if not s:
            return False
        exp = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if exp.tzinfo:
            now = datetime.now(timezone.utc)
            exp_utc = exp.astimezone(timezone.utc)
            return now >= exp_utc
        return datetime.now() >= exp
    except Exception:
        return False

def _validate_login(username, password):
    u = _user_by_name(username)
    if not u or not u.get("password_hash"):
        return False
    if u.get("blocked", False):
        return False
    if _user_expired(username):
        return False
    return check_password_hash(u["password_hash"], password)

def _token_user():
    """Retorna (username, is_admin) se o token no request for válido e usuário ativo."""
    token = request.headers.get("Authorization") or request.headers.get("X-Token") or request.args.get("token")
    if token and token.startswith("Bearer "):
        token = token[7:].strip()
    if not token:
        return None, False
    tokens = _load_tokens()
    data = tokens.get(token)
    if not data:
        return None, False
    username = data.get("username")
    if not username or _user_blocked(username) or _user_expired(username):
        # invalida token
        tokens.pop(token, None)
        _save_tokens(tokens)
        return None, False
    return username, data.get("is_admin", False)


# ---------- Rotas públicas ----------

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username:
        return jsonify({"ok": False, "msg": "Usuário obrigatório"}), 400
    if not _validate_login(username, password):
        return jsonify({"ok": False, "msg": "Usuário, senha inválidos, conta bloqueada ou expirada"}), 401
    u = _user_by_name(username)
    token = secrets.token_urlsafe(32)
    tokens = _load_tokens()
    tokens[token] = {"username": u.get("username"), "is_admin": u.get("is_admin", False)}
    _save_tokens(tokens)
    return jsonify({
        "ok": True,
        "token": token,
        "username": u.get("username"),
        "is_admin": u.get("is_admin", False),
    })


@app.route("/api/check", methods=["GET"])
def api_check():
    """Verifica se o token ainda é válido (usuário não bloqueado/expirado)."""
    token = request.args.get("token") or request.headers.get("X-Token")
    if token and token.startswith("Bearer "):
        token = token[7:].strip()
    if not token:
        return jsonify({"ok": False}), 401
    tokens = _load_tokens()
    data = tokens.get(token)
    if not data:
        return jsonify({"ok": False}), 401
    username = data.get("username")
    if not username or _user_blocked(username) or _user_expired(username):
        tokens.pop(token, None)
        _save_tokens(tokens)
        return jsonify({"ok": False}), 401
    return jsonify({
        "ok": True,
        "username": data.get("username"),
        "is_admin": data.get("is_admin", False),
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    data = request.get_json() or {}
    token = data.get("token") or request.headers.get("X-Token")
    if token and token.startswith("Bearer "):
        token = token[7:].strip()
    if token:
        tokens = _load_tokens()
        tokens.pop(token, None)
        _save_tokens(tokens)
    return jsonify({"ok": True})


# ---------- Rotas admin (exigem token de admin) ----------

def _require_admin():
    username, is_admin = _token_user()
    if not username:
        return None, jsonify({"ok": False, "msg": "Não autorizado"}), 401
    if not is_admin:
        return None, jsonify({"ok": False, "msg": "Acesso negado"}), 403
    return username, None


@app.route("/api/admin/users", methods=["GET"])
def api_admin_list_users():
    _, err = _require_admin()
    if err:
        return err
    users = _load_users()
    out = []
    for u in users:
        out.append({
            "username": u.get("username"),
            "expires_at": u.get("expires_at"),
            "blocked": u.get("blocked", False),
            "is_admin": u.get("is_admin", False),
        })
    return jsonify({"ok": True, "users": out})


@app.route("/api/admin/users", methods=["POST"])
def api_admin_add_user():
    _, err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"ok": False, "msg": "Usuário e senha obrigatórios"}), 400
    if _user_by_name(username):
        return jsonify({"ok": False, "msg": "Usuário já existe"}), 400
    users = _load_users()
    users.append({
        "username": username,
        "password_hash": generate_password_hash(password, method="pbkdf2:sha256"),
        "expires_at": None,
        "blocked": False,
        "is_admin": False,
    })
    if not _save_users(users):
        return jsonify({"ok": False, "msg": "Erro ao salvar"}), 500
    return jsonify({"ok": True, "msg": "Conta criada"})


@app.route("/api/admin/users/<username>/block", methods=["POST"])
def api_admin_block(username):
    _, err = _require_admin()
    if err:
        return err
    users = _load_users()
    for u in users:
        if (u.get("username") or "").strip().lower() == username.strip().lower():
            u["blocked"] = True
            _save_users(users)
            # Invalida tokens desse usuário
            tokens = _load_tokens()
            to_del = [t for t, d in tokens.items() if (d.get("username") or "").lower() == username.strip().lower()]
            for t in to_del:
                del tokens[t]
            _save_tokens(tokens)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Usuário não encontrado"}), 404


@app.route("/api/admin/users/<username>/desbloquear", methods=["POST"])
def api_admin_desbloquear(username):
    _, err = _require_admin()
    if err:
        return err
    users = _load_users()
    for u in users:
        if (u.get("username") or "").strip().lower() == username.strip().lower():
            u["blocked"] = False
            _save_users(users)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Usuário não encontrado"}), 404


@app.route("/api/admin/users/<username>/delete", methods=["POST"])
def api_admin_delete(username):
    _, err = _require_admin()
    if err:
        return err
    users = _load_users()
    before = len(users)
    users = [u for u in users if (u.get("username") or "").strip().lower() != username.strip().lower()]
    if len(users) == before:
        return jsonify({"ok": False, "msg": "Usuário não encontrado"}), 404
    _save_users(users)
    tokens = _load_tokens()
    to_del = [t for t, d in tokens.items() if (d.get("username") or "").lower() == username.strip().lower()]
    for t in to_del:
        del tokens[t]
    _save_tokens(tokens)
    return jsonify({"ok": True})


@app.route("/api/admin/users/<username>/password", methods=["POST"])
def api_admin_password(username):
    _, err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    password = data.get("password") or ""
    if not password:
        return jsonify({"ok": False, "msg": "Senha obrigatória"}), 400
    users = _load_users()
    for u in users:
        if (u.get("username") or "").strip().lower() == username.strip().lower():
            u["password_hash"] = generate_password_hash(password, method="pbkdf2:sha256")
            _save_users(users)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Usuário não encontrado"}), 404


@app.route("/api/admin/users/<username>/expira", methods=["POST"])
def api_admin_expira(username):
    _, err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    expires_at = data.get("expires_at")
    if expires_at is not None and expires_at != "":
        expires_at = (expires_at or "").strip() or None
    users = _load_users()
    for u in users:
        if (u.get("username") or "").strip().lower() == username.strip().lower():
            u["expires_at"] = expires_at
            _save_users(users)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Usuário não encontrado"}), 404


# ---------- Setup: criar primeiro admin (quando não há usuários) ----------

@app.route("/api/setup", methods=["GET"])
def api_setup_status():
    """Retorna se já existe algum usuário (setup já feito)."""
    users = _load_users()
    return jsonify({"ok": True, "has_users": len(users) > 0})


@app.route("/api/setup", methods=["POST"])
def api_setup_create():
    """Cria o primeiro usuário (admin). Só funciona quando não há usuários."""
    users = _load_users()
    if users:
        return jsonify({"ok": False, "msg": "Setup já realizado"}), 400
    data = request.get_json() or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"ok": False, "msg": "Usuário e senha obrigatórios"}), 400
    users = [{
        "username": username,
        "password_hash": generate_password_hash(password, method="pbkdf2:sha256"),
        "expires_at": None,
        "blocked": False,
        "is_admin": True,
    }]
    if not _save_users(users):
        return jsonify({"ok": False, "msg": "Erro ao salvar"}), 500
    return jsonify({"ok": True, "msg": "Administrador criado"})


@app.route("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"Servidor de autenticação em http://0.0.0.0:{port}")
    print("Endpoints: /api/login, /api/check, /api/admin/users, /api/setup")
    app.run(host="0.0.0.0", port=port, debug=False)
