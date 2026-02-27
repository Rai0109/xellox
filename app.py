from flask import Flask, jsonify, render_template, request, session, redirect, url_for, send_from_directory
import json
import os
import datetime
import uuid
import hashlib
import threading
import time
import logging
import sys
import traceback


MB_USERNAME = os.environ.get("MB_USERNAME", "")
MB_PASSWORD = os.environ.get("MB_PASSWORD", "")
MB_ACCOUNT_NUMBER = os.environ.get("MB_ACCOUNT", "")
MB_POLLING_INTERVAL = 15
VND_TO_XU_RATE = 1000

mb_instance = None
mb_lock = threading.Lock()
mb_enabled = False

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "xelloxx_secret_key_2024"
DB_FILE = "database.json"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("mbbank_polling")

def load_db():
    default_db = {
        "products": [],
        "users": [],
        "orders": [],
        "topup_requests": [],
        "processed_txids": [],
        "categories": ["Bot Zalo", "Bot Facebook", "Bot Discord", "API", "Source Code", "Tool"],
        "coupons": [],
        "admins": [{"username": "admin", "password": hash_pw("admin123")}],
        "mb_settings": {
            "username": "",
            "password": "",
            "account_number": "",
            "bank_name": "MB Bank",
            "account_holder": "",
            "enabled": False
        }
    }
    
    if not os.path.exists(DB_FILE):
        return default_db
    
    try:
        with open(DB_FILE, "r", encoding="utf8") as f:
            data = json.load(f)
            # Kiem tra neu data rong hoac khong co cac truong can thiet
            if not data or not isinstance(data, dict):
                return default_db
            # Kiem tra xem co du cac truong cua database khong
            if "products" not in data or "users" not in data:
                return default_db
            return data
    except (json.JSONDecodeError, IOError):
        return default_db

def save_db(db):
    with open(DB_FILE, "w", encoding="utf8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def init_db():
    if not os.path.exists(DB_FILE):
        db = load_db()
        save_db(db)

init_db()

# ===== MB BANK =====

def get_mb_settings():
    db = load_db()
    return db.get("mb_settings", {})

def get_transaction_history(mb_inst, account_number, from_date, to_date):
    """
    Lay lich su giao dich su dung getTransactionAccountHistory.
    from_date, to_date: string "DD/MM/YYYY" hoac datetime object
    """
    # Chuan bi datetime objects
    if isinstance(from_date, str):
        from_dt = datetime.datetime.strptime(from_date, "%d/%m/%Y")
    else:
        from_dt = from_date

    if isinstance(to_date, str):
        to_dt = datetime.datetime.strptime(to_date, "%d/%m/%Y")
    else:
        to_dt = to_date

    method_name = "getTransactionAccountHistory"
    if not hasattr(mb_inst, method_name):
        all_tx_methods = [m for m in dir(mb_inst) if not m.startswith('_') and
                          any(k in m.lower() for k in ['trans', 'history', 'account'])]
        raise AttributeError(
            f"Khong tim thay method {method_name}. "
            f"Methods lien quan trong mbbank: {all_tx_methods}"
        )

    # Goi dung signature: getTransactionAccountHistory(*, accountNo=None, from_date, to_date)
    try:
        logger.info(f"Calling {method_name}(accountNo={account_number}, from_date={from_dt}, to_date={to_dt})")
        result = mb_inst.getTransactionAccountHistory(
            accountNo=account_number,
            from_date=from_dt,
            to_date=to_dt
        )
        key = f"{method_name}(accountNo, from_date, to_date)"
        logger.info(f"SUCCESS: {key}")
        return result, key
    except Exception as e:
        logger.error(f"getTransactionAccountHistory that bai: {type(e).__name__}: {e}")
        raise

def extract_tx_list(result):
    """Lay danh sach giao dich tu nhieu kieu tra ve khac nhau"""
    if result is None:
        return []
    if isinstance(result, list):
        return result
    for attr in ['transactionHistoryList', 'transactions', 'data', 'items', 'result']:
        val = getattr(result, attr, None)
        if val is not None:
            return val if isinstance(val, list) else []
    if isinstance(result, dict):
        for key in ['transactionHistoryList', 'transactions', 'data', 'items']:
            if key in result and isinstance(result[key], list):
                return result[key]
    return []

def get_tx_field(tx, *field_names, default=None):
    """Lay gia tri field tu tx object hoac dict"""
    for name in field_names:
        if isinstance(tx, dict):
            if name in tx:
                return tx[name]
        else:
            val = getattr(tx, name, None)
            if val is not None:
                return val
    return default

def try_init_mb(debug=False):
    global mb_instance, mb_enabled
    logs = []

    def log(msg, level="INFO"):
        logs.append(f"[{level}] {msg}")
        getattr(logger, level.lower(), logger.info)(msg)

    settings = get_mb_settings()
    log(f"Settings: enabled={settings.get('enabled')}, username='{settings.get('username')}', account='{settings.get('account_number')}'")

    if not settings.get("enabled"):
        log("MB Bank chua duoc bat (enabled=False). Vao Admin Settings de bat.", "WARNING")
        mb_enabled = False
        return (False, logs) if debug else False

    if not settings.get("username"):
        log("Thieu username MB Bank.", "ERROR")
        mb_enabled = False
        return (False, logs) if debug else False

    if not settings.get("password"):
        log("Thieu password MB Bank.", "ERROR")
        mb_enabled = False
        return (False, logs) if debug else False

    log(f"Python version: {sys.version}")
    log("Dang import thu vien mbbank...")
    try:
        import mbbank
        ver = getattr(mbbank, '__version__', 'unknown')
        log(f"Import mbbank thanh cong. Version: {ver}")
        log(f"mbbank path: {getattr(mbbank, '__file__', 'unknown')}")
        all_methods = [m for m in dir(mbbank.MBBank) if not m.startswith('_')]
        log(f"Available methods: {all_methods}")
    except ImportError as e:
        log(f"Khong tim thay thu vien mbbank: {e}. Chay: pip install mbbank-lib", "ERROR")
        mb_enabled = False
        return (False, logs) if debug else False
    except Exception as e:
        log(f"Loi khi import mbbank: {e}\n{traceback.format_exc()}", "ERROR")
        mb_enabled = False
        return (False, logs) if debug else False

    log(f"Dang khoi tao MBBank(username='{settings['username']}', password='***{settings['password'][-2:] if len(settings.get('password',''))>=2 else '?'}')...")
    try:
        with mb_lock:
            mb_instance = mbbank.MBBank(
                username=settings["username"],
                password=settings["password"]
            )
        mb_enabled = True
        log("Khoi tao MBBank instance thanh cong!")
        return (True, logs) if debug else True
    except Exception as e:
        log(f"Loi khi khoi tao MBBank: {type(e).__name__}: {e}", "ERROR")
        log(f"Traceback:\n{traceback.format_exc()}", "ERROR")
        mb_enabled = False
        mb_instance = None
        return (False, logs) if debug else False

def poll_mb_transactions():
    global mb_instance, mb_enabled
    logger.info("MB Bank polling thread started")
    consecutive_errors = 0

    while True:
        time.sleep(MB_POLLING_INTERVAL)
        settings = get_mb_settings()
        if not settings.get("enabled"):
            consecutive_errors = 0
            continue

        if not mb_enabled or mb_instance is None:
            if not try_init_mb():
                consecutive_errors += 1
                if consecutive_errors > 5:
                    time.sleep(300)
                continue

        try:
            account_number = settings.get("account_number", "")
            if not account_number:
                continue

            today = datetime.datetime.now().strftime("%d/%m/%Y")
            with mb_lock:
                result, used_method = get_transaction_history(mb_instance, account_number, today, today)

            tx_list = extract_tx_list(result)
            if not tx_list:
                continue

            db = load_db()
            processed = set(db.get("processed_txids", []))
            updated = False

            for tx in tx_list:
                ref_no  = get_tx_field(tx, 'refNo', 'ref', 'transactionId', 'id', default='')
                tx_date = get_tx_field(tx, 'transactionDate', 'date', 'createdAt', default='')
                credit  = float(get_tx_field(tx, 'creditAmount', 'credit', 'amount', default=0) or 0)
                desc    = str(get_tx_field(tx, 'description', 'remark', 'note', default='') or '').upper()

                tx_id = str(ref_no).strip() or (str(tx_date) + str(credit))
                if tx_id in processed:
                    continue

                if credit <= 0:
                    processed.add(tx_id)
                    continue

                matched_request = None
                for req in db.get("topup_requests", []):
                    if req.get("status") == "pending" and req.get("code", "").upper() in desc:
                        matched_request = req
                        break

                if matched_request:
                    xu_amount = int(credit)
                    for user in db["users"]:
                        if user["username"] == matched_request["username"]:
                            user["balance"] = user.get("balance", 0) + xu_amount
                            break

                    matched_request["status"] = "completed"
                    matched_request["amount_received"] = int(credit)
                    matched_request["xu_added"] = xu_amount
                    matched_request["completed_at"] = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                    matched_request["tx_ref"] = tx_id
                    logger.info(f"Nap tien thanh cong: {matched_request['username']} +{xu_amount} xu ({credit:,.0f}d)")
                    updated = True

                processed.add(tx_id)

            if updated or len(processed) != len(db.get("processed_txids", [])):
                db["processed_txids"] = list(processed)[-2000:]
                save_db(db)

            consecutive_errors = 0

        except Exception as e:
            consecutive_errors += 1
            logger.error(f"MB Bank polling error: {e}\n{traceback.format_exc()}")
            if consecutive_errors >= 3:
                mb_enabled = False
                mb_instance = None
                logger.warning("MB Bank: Reset instance do loi lien tuc")

polling_thread = threading.Thread(target=poll_mb_transactions, daemon=True)
polling_thread.start()

# ===== PUBLIC ROUTES =====

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/product/<pid>")
def product_detail(pid):
    return render_template("product.html", product_id=pid)

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/checkout")
def checkout_page():
    return render_template("checkout.html")

@app.route("/topup")
def topup_page():
    return render_template("topup.html")

@app.route("/orders")
def orders_page():
    return render_template("orders.html")

# ===== API PUBLIC =====

@app.route("/api/products")
def get_products():
    db = load_db()
    category = request.args.get("category", "")
    search = request.args.get("search", "").lower()
    ptype = request.args.get("type", "")
    products = db["products"]
    if category:
        products = [p for p in products if p["category"] == category]
    if search:
        products = [p for p in products if search in p["name"].lower() or search in p["description"].lower()]
    if ptype:
        products = [p for p in products if p["type"] == ptype]
    return jsonify(products)

@app.route("/api/products/<pid>")
def get_product(pid):
    db = load_db()
    p = next((x for x in db["products"] if x["id"] == pid), None)
    if not p:
        return jsonify({"error": "Not found"}), 404
    p["views"] = p.get("views", 0) + 1
    save_db(db)
    return jsonify(p)

@app.route("/api/categories")
def get_categories():
    db = load_db()
    return jsonify(db["categories"])

@app.route("/api/stats")
def get_stats():
    db = load_db()
    return jsonify({
        "products": len(db["products"]),
        "users": len(db["users"]),
        "orders": len(db["orders"])
    })

@app.route("/api/register", methods=["POST"])
def register():
    db = load_db()
    data = request.json
    if any(u["username"] == data["username"] for u in db["users"]):
        return jsonify({"ok": False, "msg": "Ten dang nhap da ton tai"})
    if any(u["email"] == data["email"] for u in db["users"]):
        return jsonify({"ok": False, "msg": "Email da duoc su dung"})
    db["users"].append({
        "id": str(uuid.uuid4()),
        "username": data["username"],
        "email": data["email"],
        "password": hash_pw(data["password"]),
        "balance": 0,
        "created_at": datetime.datetime.now().strftime("%d/%m/%Y")
    })
    save_db(db)
    return jsonify({"ok": True})

@app.route("/api/login", methods=["POST"])
def login():
    db = load_db()
    data = request.json
    user = next((u for u in db["users"] if u["username"] == data["username"] and u["password"] == hash_pw(data["password"])), None)
    if user:
        session["user"] = user["username"]
        return jsonify({"ok": True, "user": user["username"]})
    return jsonify({"ok": False, "msg": "Sai ten dang nhap hoac mat khau"})

@app.route("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/my-orders")
def my_orders():
    if "user" not in session:
        return jsonify({"ok": False, "orders": []})
    db = load_db()
    orders = [o for o in db.get("orders", []) if o.get("user") == session["user"]]
    orders.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify({"ok": True, "orders": orders[:50]})

@app.route("/api/me")
def me():
    if "user" not in session:
        return jsonify({"ok": False})
    db = load_db()
    user = next((u for u in db["users"] if u["username"] == session["user"]), None)
    if not user:
        return jsonify({"ok": False})
    return jsonify({"ok": True, "username": user["username"], "balance": user.get("balance", 0)})

# ===== TOPUP API =====

@app.route("/api/topup/info")
def topup_info():
    db = load_db()
    settings = db.get("mb_settings", {})
    return jsonify({
        "bank_name": settings.get("bank_name", "MB Bank"),
        "account_number": settings.get("account_number", ""),
        "account_holder": settings.get("account_holder", ""),
        "enabled": settings.get("enabled", False)
    })

@app.route("/api/topup/create", methods=["POST"])
def topup_create():
    if "user" not in session:
        return jsonify({"ok": False, "msg": "Chua dang nhap"}), 401
    db = load_db()
    data = request.json
    amount = int(data.get("amount", 0))
    if amount < 10000:
        return jsonify({"ok": False, "msg": "So tien toi thieu 10,000d"})
    if amount > 50000000:
        return jsonify({"ok": False, "msg": "So tien toi da 50,000,000d"})

    short_id = str(uuid.uuid4())[:6].upper()
    code = f"NAP{session['user'].upper()[:6]}{short_id}"

    req = {
        "id": str(uuid.uuid4()),
        "username": session["user"],
        "amount": amount,
        "code": code,
        "status": "pending",
        "created_at": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "expires_at": (datetime.datetime.now() + datetime.timedelta(minutes=30)).strftime("%d/%m/%Y %H:%M:%S")
    }
    if "topup_requests" not in db:
        db["topup_requests"] = []
    db["topup_requests"].append(req)
    save_db(db)
    return jsonify({"ok": True, "request": req})

@app.route("/api/topup/status/<req_id>")
def topup_status(req_id):
    if "user" not in session:
        return jsonify({"ok": False, "msg": "Chua dang nhap"}), 401
    db = load_db()
    req = next((r for r in db.get("topup_requests", []) if r["id"] == req_id and r["username"] == session["user"]), None)
    if not req:
        return jsonify({"ok": False, "msg": "Khong tim thay yeu cau"})
    user = next((u for u in db["users"] if u["username"] == session["user"]), None)
    return jsonify({
        "ok": True,
        "status": req["status"],
        "amount": req.get("amount"),
        "xu_added": req.get("xu_added", 0),
        "balance": user.get("balance", 0) if user else 0
    })

@app.route("/api/topup/history")
def topup_history():
    if "user" not in session:
        return jsonify({"ok": False, "msg": "Chua dang nhap"}), 401
    db = load_db()
    history = [r for r in db.get("topup_requests", []) if r["username"] == session["user"]]
    history.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify(history[:20])

# ===== CHECKOUT API =====

@app.route("/api/checkout", methods=["POST"])
def do_checkout():
    if "user" not in session:
        return jsonify({"ok": False, "msg": "Chua dang nhap"}), 401
    db = load_db()
    data = request.json
    pid = data.get("product_id")
    coupon = data.get("coupon", "").strip().upper()

    product = next((p for p in db["products"] if p["id"] == pid), None)
    if not product:
        return jsonify({"ok": False, "msg": "San pham khong ton tai"}), 404

    user = next((u for u in db["users"] if u["username"] == session["user"]), None)
    price = product["sale_price"] if product["sale_price"] > 0 else product["price"]

    discount = 0
    coupon_used = None
    if coupon:
        coupon_obj = next((c for c in db.get("coupons", []) if c["code"].upper() == coupon and c.get("active", True)), None)
        if coupon_obj:
            # Kiem tra so luot con lai
            uses_left = coupon_obj.get("max_uses", 0) - coupon_obj.get("used_count", 0)
            if uses_left != 0:  # 0 = khong gioi han
                if uses_left < 0:
                    return jsonify({"ok": False, "msg": f"Ma giam gia da het luot su dung"})
            # Kiem tra gia tri toi thieu
            min_price = coupon_obj.get("min_price", 0)
            if price < min_price:
                return jsonify({"ok": False, "msg": f"Don hang toi thieu {min_price:,}d de dung ma nay"})
            # Tinh giam gia
            if coupon_obj["type"] == "percent":
                discount = int(price * coupon_obj["value"] / 100)
                max_discount = coupon_obj.get("max_discount", 0)
                if max_discount > 0:
                    discount = min(discount, max_discount)
            else:  # fixed
                discount = coupon_obj["value"]
            coupon_used = coupon_obj
        else:
            return jsonify({"ok": False, "msg": "Ma giam gia khong hop le hoac da het han"})

    final = max(0, price - discount)
    if user["balance"] < final:
        return jsonify({"ok": False, "msg": "So du khong du. Vui long nap them xu."})

    for u in db["users"]:
        if u["username"] == session["user"]:
            u["balance"] -= final
            break

    order = {
        "id": str(uuid.uuid4()),
        "user": session["user"],
        "product_id": pid,
        "product_name": product["name"],
        "amount": final,
        "coupon": coupon if coupon_used else "",
        "discount": discount,
        "file_url": product.get("file_url", ""),
        "created_at": datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    }
    db["orders"].append(order)

    # Tang so luot su dung coupon
    if coupon_used:
        for c in db["coupons"]:
            if c["code"] == coupon_used["code"]:
                c["used_count"] = c.get("used_count", 0) + 1
                break

    save_db(db)
    return jsonify({"ok": True, "order": order, "file_url": product.get("file_url", "")})

# ===== ADMIN ROUTES =====

@app.route("/admin")
def admin_redirect():
    return redirect("/admin/dashboard")

@app.route("/admin/dashboard")
@app.route("/admin/products")
@app.route("/admin/orders")
@app.route("/admin/users")
@app.route("/admin/settings")
def admin_panel():
    return render_template("admin.html")

@app.route("/admin/login")
def admin_login_page():
    return render_template("admin_login.html")

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    db = load_db()
    data = request.json
    admin = next((a for a in db["admins"] if a["username"] == data["username"] and a["password"] == hash_pw(data["password"])), None)
    if admin:
        session["admin"] = admin["username"]
        return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Sai thong tin dang nhap"})

@app.route("/api/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return jsonify({"ok": True})

@app.route("/api/admin/check")
def admin_check():
    return jsonify({"ok": "admin" in session, "username": session.get("admin")})

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin" not in session:
            return jsonify({"ok": False, "msg": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/api/admin/stats")
@require_admin
def admin_stats():
    db = load_db()
    revenue = sum(o.get("amount", 0) for o in db["orders"])
    return jsonify({
        "products": len(db["products"]),
        "users": len(db["users"]),
        "orders": len(db["orders"]),
        "revenue": revenue
    })

@app.route("/api/admin/products", methods=["GET"])
@require_admin
def admin_products():
    db = load_db()
    return jsonify(db["products"])

@app.route("/api/admin/products", methods=["POST"])
@require_admin
def admin_add_product():
    db = load_db()
    data = request.json
    product = {
        "id": str(uuid.uuid4()),
        "name": data["name"],
        "description": data.get("description", ""),
        "price": int(data.get("price", 0)),
        "sale_price": int(data.get("sale_price", 0)),
        "category": data.get("category", ""),
        "type": data.get("type", "sell"),
        "image": data.get("image", ""),
        "file_url": data.get("file_url", ""),
        "views": 0,
        "created_at": datetime.datetime.now().strftime("%d/%m/%Y"),
        "featured": bool(data.get("featured", False)),
        "stock": int(data.get("stock", -1))
    }
    db["products"].append(product)
    save_db(db)
    return jsonify({"ok": True, "product": product})

@app.route("/api/admin/products/<pid>", methods=["PUT"])
@require_admin
def admin_update_product(pid):
    db = load_db()
    data = request.json
    for i, p in enumerate(db["products"]):
        if p["id"] == pid:
            db["products"][i].update({
                "name": data.get("name", p["name"]),
                "description": data.get("description", p["description"]),
                "price": int(data.get("price", p["price"])),
                "sale_price": int(data.get("sale_price", p["sale_price"])),
                "category": data.get("category", p["category"]),
                "type": data.get("type", p["type"]),
                "image": data.get("image", p["image"]),
                "file_url": data.get("file_url", p["file_url"]),
                "featured": bool(data.get("featured", p["featured"])),
                "stock": int(data.get("stock", p["stock"]))
            })
            save_db(db)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Not found"}), 404

@app.route("/api/admin/products/<pid>", methods=["DELETE"])
@require_admin
def admin_delete_product(pid):
    db = load_db()
    db["products"] = [p for p in db["products"] if p["id"] != pid]
    save_db(db)
    return jsonify({"ok": True})

@app.route("/api/admin/users")
@require_admin
def admin_users():
    db = load_db()
    users = [{k: v for k, v in u.items() if k != "password"} for u in db["users"]]
    return jsonify(users)

@app.route("/api/admin/orders")
@require_admin
def admin_orders():
    db = load_db()
    return jsonify(db["orders"])

@app.route("/api/admin/topup-requests")
@require_admin
def admin_topup_requests():
    db = load_db()
    requests_list = db.get("topup_requests", [])
    requests_list.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jsonify(requests_list)

@app.route("/api/admin/mb-settings", methods=["GET"])
@require_admin
def admin_get_mb_settings():
    db = load_db()
    s = db.get("mb_settings", {})
    safe = {k: v for k, v in s.items() if k != "password"}
    safe["password_set"] = bool(s.get("password", ""))
    return jsonify(safe)

@app.route("/api/admin/mb-settings", methods=["POST"])
@require_admin
def admin_save_mb_settings():
    global mb_instance, mb_enabled
    db = load_db()
    data = request.json
    if "mb_settings" not in db:
        db["mb_settings"] = {}

    db["mb_settings"]["username"] = data.get("username", "")
    db["mb_settings"]["account_number"] = data.get("account_number", "")
    db["mb_settings"]["account_holder"] = data.get("account_holder", "")
    db["mb_settings"]["bank_name"] = data.get("bank_name", "MB Bank")
    db["mb_settings"]["enabled"] = bool(data.get("enabled", False))
    if data.get("password"):
        db["mb_settings"]["password"] = data["password"]

    save_db(db)
    with mb_lock:
        mb_instance = None
        mb_enabled = False
    return jsonify({"ok": True})

@app.route("/api/admin/mb-test")
@require_admin
def admin_mb_test():
    global mb_instance, mb_enabled

    success, logs = try_init_mb(debug=True)
    if not success:
        return jsonify({"ok": False, "msg": "Khong the khoi tao MB Bank. Xem debug_logs.", "debug_logs": logs})

    # Test getBalance
    try:
        logs.append("[INFO] Dang goi getBalance()...")
        with mb_lock:
            bal = mb_instance.getBalance()
        logs.append(f"[INFO] getBalance() OK: {bal}")
    except Exception as e:
        logs.append(f"[ERROR] getBalance() that bai: {type(e).__name__}: {e}")
        logs.append(traceback.format_exc())
        return jsonify({"ok": False, "msg": f"Init OK nhung loi getBalance: {e}", "debug_logs": logs})

    # Test get transaction history
    settings = get_mb_settings()
    account_number = settings.get("account_number", "")
    if account_number:
        try:
            today = datetime.datetime.now().strftime("%d/%m/%Y")
            logs.append(f"[INFO] Dang lay lich su giao dich...")
            with mb_lock:
                result, used_method = get_transaction_history(mb_instance, account_number, today, today)

            # Debug raw result
            logs.append(f"[INFO] result type: {type(result).__name__}")
            if hasattr(result, '__dict__'):
                logs.append(f"[INFO] result.__dict__ keys: {list(result.__dict__.keys())}")
            if hasattr(result, 'model_fields'):
                logs.append(f"[INFO] result.model_fields: {list(result.model_fields.keys())}")
            if isinstance(result, dict):
                logs.append(f"[INFO] result dict keys: {list(result.keys())}")
            for attr in ['transactionHistoryList', 'transactions', 'data', 'items', 'result', 'records']:
                val = getattr(result, attr, None)
                if val is not None:
                    logs.append(f"[INFO] result.{attr} = {type(val).__name__}(len={len(val) if hasattr(val, '__len__') else '?'})")

            tx_list = extract_tx_list(result)
            logs.append(f"[INFO] Thanh cong! Method su dung: {used_method}")
            logs.append(f"[INFO] So giao dich hom nay: {len(tx_list)}")
            if tx_list:
                sample = tx_list[0]
                if isinstance(sample, dict):
                    logs.append(f"[INFO] Sample tx fields: {list(sample.keys())}")
                    logs.append(f"[INFO] Sample tx data: {sample}")
                else:
                    attrs = [a for a in dir(sample) if not a.startswith('_')]
                    logs.append(f"[INFO] Sample tx attrs: {attrs}")
                    sample_data = {}
                    for a in attrs:
                        try:
                            sample_data[a] = str(getattr(sample, a, None))
                        except:
                            pass
                    logs.append(f"[INFO] Sample tx data: {sample_data}")
            else:
                logs.append("[WARNING] tx_list rong! Kiem tra extract_tx_list hoac chua co GD hom nay.")
        except Exception as e:
            logs.append(f"[ERROR] Lay lich su that bai: {type(e).__name__}: {e}")
            logs.append(traceback.format_exc())
            return jsonify({"ok": False, "msg": f"getBalance OK nhung loi lich su: {e}", "debug_logs": logs})
    else:
        logs.append("[WARNING] Chua nhap Account Number, bo qua test lich su.")

    return jsonify({"ok": True, "msg": "Ket noi thanh cong!", "debug_logs": logs})

@app.route("/api/coupon/check", methods=["POST"])
def coupon_check():
    """API kiem tra coupon truoc khi checkout"""
    db = load_db()
    data = request.json
    code = data.get("code", "").strip().upper()
    price = int(data.get("price", 0))
    if not code:
        return jsonify({"ok": False, "msg": "Vui long nhap ma giam gia"})
    coupon_obj = next((c for c in db.get("coupons", []) if c["code"].upper() == code and c.get("active", True)), None)
    if not coupon_obj:
        return jsonify({"ok": False, "msg": "Ma giam gia khong hop le hoac da bi vo hieu hoa"})
    uses_left = coupon_obj.get("max_uses", 0) - coupon_obj.get("used_count", 0)
    if coupon_obj.get("max_uses", 0) > 0 and uses_left <= 0:
        return jsonify({"ok": False, "msg": "Ma giam gia da het luot su dung"})
    min_price = coupon_obj.get("min_price", 0)
    if price > 0 and price < min_price:
        return jsonify({"ok": False, "msg": f"Don hang toi thieu {min_price:,}d de dung ma nay"})
    # Tinh so tien giam
    if coupon_obj["type"] == "percent":
        discount = int(price * coupon_obj["value"] / 100) if price > 0 else 0
        max_discount = coupon_obj.get("max_discount", 0)
        if max_discount > 0:
            discount = min(discount, max_discount)
        desc = f"Giam {coupon_obj['value']}%"
        if max_discount > 0:
            desc += f" (toi da {max_discount:,}d)"
    else:
        discount = coupon_obj["value"]
        desc = f"Giam {discount:,}d"
    return jsonify({"ok": True, "discount": discount, "description": desc,
                    "uses_left": uses_left if coupon_obj.get("max_uses", 0) > 0 else -1})

# ===== ADMIN COUPON ROUTES =====

@app.route("/api/admin/coupons", methods=["GET"])
@require_admin
def admin_get_coupons():
    db = load_db()
    return jsonify(db.get("coupons", []))

@app.route("/api/admin/coupons", methods=["POST"])
@require_admin
def admin_add_coupon():
    db = load_db()
    data = request.json
    code = data.get("code", "").strip().upper()
    if not code:
        return jsonify({"ok": False, "msg": "Vui long nhap ma giam gia"})
    if any(c["code"] == code for c in db.get("coupons", [])):
        return jsonify({"ok": False, "msg": "Ma giam gia da ton tai"})
    coupon = {
        "id": str(uuid.uuid4()),
        "code": code,
        "type": data.get("type", "fixed"),       # "fixed" hoac "percent"
        "value": int(data.get("value", 0)),       # so tien hoac %
        "max_uses": int(data.get("max_uses", 0)), # 0 = khong gioi han
        "used_count": 0,
        "min_price": int(data.get("min_price", 0)),       # gia toi thieu de ap dung
        "max_discount": int(data.get("max_discount", 0)), # cap giam toi da (cho loai %)
        "description": data.get("description", ""),
        "active": True,
        "created_at": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    }
    if "coupons" not in db:
        db["coupons"] = []
    db["coupons"].append(coupon)
    save_db(db)
    return jsonify({"ok": True, "coupon": coupon})

@app.route("/api/admin/coupons/<cid>", methods=["PUT"])
@require_admin
def admin_update_coupon(cid):
    db = load_db()
    data = request.json
    for i, c in enumerate(db.get("coupons", [])):
        if c["id"] == cid:
            db["coupons"][i].update({
                "code": data.get("code", c["code"]).strip().upper(),
                "type": data.get("type", c["type"]),
                "value": int(data.get("value", c["value"])),
                "max_uses": int(data.get("max_uses", c["max_uses"])),
                "min_price": int(data.get("min_price", c.get("min_price", 0))),
                "max_discount": int(data.get("max_discount", c.get("max_discount", 0))),
                "description": data.get("description", c.get("description", "")),
                "active": bool(data.get("active", c.get("active", True)))
            })
            save_db(db)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "Khong tim thay coupon"}), 404

@app.route("/api/admin/coupons/<cid>", methods=["DELETE"])
@require_admin
def admin_delete_coupon(cid):
    db = load_db()
    db["coupons"] = [c for c in db.get("coupons", []) if c["id"] != cid]
    save_db(db)
    return jsonify({"ok": True})

@app.route("/api/admin/coupons/<cid>/toggle", methods=["POST"])
@require_admin
def admin_toggle_coupon(cid):
    db = load_db()
    for c in db.get("coupons", []):
        if c["id"] == cid:
            c["active"] = not c.get("active", True)
            save_db(db)
            return jsonify({"ok": True, "active": c["active"]})
    return jsonify({"ok": False, "msg": "Khong tim thay coupon"}), 404

@app.route("/api/admin/categories", methods=["POST"])
@require_admin
def admin_add_category():
    db = load_db()
    cat = request.json.get("name")
    if cat and cat not in db["categories"]:
        db["categories"].append(cat)
        save_db(db)
    return jsonify({"ok": True, "categories": db["categories"]})

@app.route("/api/admin/categories/<cat>", methods=["DELETE"])
@require_admin
def admin_delete_category(cat):
    db = load_db()
    db["categories"] = [c for c in db["categories"] if c != cat]
    save_db(db)
    return jsonify({"ok": True, "categories": db["categories"]})

@app.route("/api/admin/topup-requests/<req_id>/approve", methods=["POST"])
@require_admin
def admin_approve_topup(req_id):
    """Duyet nap tien thu cong cho truong hop user quen ghi ma"""
    db = load_db()
    req = next((r for r in db.get("topup_requests", []) if r["id"] == req_id), None)
    if not req:
        return jsonify({"ok": False, "msg": "Khong tim thay yeu cau"}), 404
    if req["status"] != "pending":
        return jsonify({"ok": False, "msg": f"Yeu cau da o trang thai: {req['status']}"}), 400

    data = request.json or {}
    amount = int(data.get("amount", req.get("amount", 0)))
    if amount <= 0:
        return jsonify({"ok": False, "msg": "So tien khong hop le"}), 400

    for user in db["users"]:
        if user["username"] == req["username"]:
            user["balance"] = user.get("balance", 0) + amount
            break
    else:
        return jsonify({"ok": False, "msg": f"Khong tim thay user: {req['username']}"}), 404

    req["status"] = "completed"
    req["amount_received"] = amount
    req["xu_added"] = amount
    req["completed_at"] = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    req["approved_by"] = "admin"

    save_db(db)
    return jsonify({"ok": True, "msg": f"Da nap {amount:,} xu cho {req['username']}"})

@app.route("/api/admin/topup-requests/<req_id>/reject", methods=["POST"])
@require_admin
def admin_reject_topup(req_id):
    """Huy yeu cau nap tien"""
    db = load_db()
    req = next((r for r in db.get("topup_requests", []) if r["id"] == req_id), None)
    if not req:
        return jsonify({"ok": False, "msg": "Khong tim thay yeu cau"}), 404
    if req["status"] != "pending":
        return jsonify({"ok": False, "msg": f"Yeu cau da o trang thai: {req['status']}"}), 400
    req["status"] = "rejected"
    req["rejected_at"] = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    req["rejected_by"] = "admin"
    save_db(db)
    return jsonify({"ok": True, "msg": "Da huy yeu cau nap tien"})

@app.route("/api/admin/users/<uid>/balance", methods=["POST"])
@require_admin
def admin_adjust_balance(uid):
    """Chinh sua so du truc tiep"""
    db = load_db()
    data = request.json
    amount = int(data.get("amount", 0))
    note = data.get("note", "Admin dieu chinh")
    user = next((u for u in db["users"] if u["id"] == uid), None)
    if not user:
        return jsonify({"ok": False, "msg": "Khong tim thay user"}), 404
    old_balance = user.get("balance", 0)
    user["balance"] = max(0, old_balance + amount)
    save_db(db)
    return jsonify({"ok": True, "msg": f"{user['username']}: {old_balance:,} -> {user['balance']:,} xu ({note})"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8002))
    app.run(host="0.0.0.0", port=port, debug=False)