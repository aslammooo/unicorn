"""
سيرفر الشات v2
- حسابات (باسورد مشفر PBKDF2) + بروفايل (نيك نيم / صورة / بانر)
- أصدقاء + حالة أونلاين
- شات خاص وجروبات، رد على رسالة، حذف (من عندي / من عند الكل)
- مكالمات صوتية (خاصة وجماعية) + مشاركة شاشة (ترحيل فقط، السيرفر مش بيفك الصوت)
- ريبورتات + لوحة أدمن (باند / تايم أوت / حذف حساب / إعادة تعيين باسورد / طرد من الصوت / مراجعة الشاتات)
- أداة تعيين الأدمن المستقلة (make_admin.py) بتشتغل بمتغير بيئة ADMIN_SECRET

متغيرات البيئة (على Railway → Variables):
  ADMIN_SECRET  سر طويل لتعيين الأدمن (لو مش موجود، تعيين الأدمن بيتقفل)
  DATA_DIR      مسار التخزين الدائم (مثلاً /data لو ربطت Volume)
  PORT          بيتحط تلقائي من Railway
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, Optional

from fastapi import (FastAPI, File, Form, Header, HTTPException, UploadFile, WebSocket)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uvicorn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR") or BASE_DIR
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "chat.db")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

MAX_UPLOAD = 10 * 1024 * 1024
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
RESERVED_NAMES = {"admin", "administrator", "system", "moderator", "root", "support"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-؀-ۿ]{3,24}$")
REPORT_REASONS = {"spam", "harassment", "inappropriate", "scam", "threat", "other"}
RING_SECONDS = float(os.environ.get("RING_SECONDS", "45"))

app = FastAPI(title="Chat Server v2")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ---------------------------------------------------------------------------
# أدوات عامة
# ---------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_ts() -> float:
    return time.time()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_column(conn, table, column, decl):
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    c = conn
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL)""")
    for col, decl in (("nickname", "TEXT DEFAULT ''"), ("avatar", "TEXT DEFAULT ''"),
                      ("banner", "TEXT DEFAULT ''"), ("role", "TEXT DEFAULT 'user'"),
                      ("banned", "INTEGER DEFAULT 0"), ("ban_reason", "TEXT DEFAULT ''"),
                      ("timeout_until", "REAL DEFAULT 0"), ("timeout_reason", "TEXT DEFAULT ''")):
        ensure_column(c, "users", col, decl)
    c.execute("""CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, from_user TEXT NOT NULL, to_user TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL)""")
    c.execute("CREATE TABLE IF NOT EXISTS friends (user_a TEXT NOT NULL, user_b TEXT NOT NULL)")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user TEXT NOT NULL, to_user TEXT NOT NULL,
        msg_type TEXT NOT NULL DEFAULT 'text', content TEXT, image_path TEXT,
        created_at TEXT NOT NULL)""")
    ensure_column(c, "messages", "group_id", "INTEGER")
    ensure_column(c, "messages", "reply_to", "INTEGER")
    ensure_column(c, "messages", "deleted_all", "INTEGER DEFAULT 0")
    c.execute("CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(from_user, to_user)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_msg_group ON messages(group_id)")
    c.execute("CREATE TABLE IF NOT EXISTS message_hidden (msg_id INTEGER NOT NULL, username TEXT NOT NULL, "
              "PRIMARY KEY (msg_id, username))")
    c.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL)")
    c.execute("""CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, owner TEXT NOT NULL, created_at TEXT NOT NULL)""")
    c.execute("CREATE TABLE IF NOT EXISTS group_members (group_id INTEGER NOT NULL, username TEXT NOT NULL, "
              "PRIMARY KEY (group_id, username))")
    c.execute("""CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, reporter TEXT NOT NULL, reported TEXT NOT NULL,
        reason TEXT NOT NULL, details TEXT, group_id INTEGER, msg_id INTEGER,
        created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', handled_by TEXT, note TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, admin TEXT NOT NULL, action TEXT NOT NULL,
        target TEXT, details TEXT, created_at TEXT NOT NULL)""")
    conn.commit()
    conn.close()


init_db()


def hash_password(password: str, salt: Optional[str] = None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return salt, h.hex()


def verify_password(password: str, salt: str, hashed: str) -> bool:
    _, h = hash_password(password, salt)
    return secrets.compare_digest(h, hashed)


def audit(db, admin, action, target="", details=""):
    db.execute("INSERT INTO audit (admin, action, target, details, created_at) VALUES (?,?,?,?,?)",
               (admin, action, target, details, now_iso()))


# ---------------------------------------------------------------------------
# البروفايلات والمستخدمين
# ---------------------------------------------------------------------------
def profile_of(row) -> dict:
    return {"username": row["username"], "nickname": row["nickname"] or "", "avatar": row["avatar"] or "",
            "banner": row["banner"] or "", "role": row["role"] or "user"}


def get_user(db, username):
    return db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def user_from_token(token: str, allow_banned=False):
    with get_db() as db:
        s = db.execute("SELECT username FROM sessions WHERE token=?", (token,)).fetchone()
        if not s:
            raise HTTPException(401, "الجلسة انتهت، سجل دخول تاني")
        u = get_user(db, s["username"])
        if not u:
            db.execute("DELETE FROM sessions WHERE token=?", (token,))
            raise HTTPException(401, "الحساب مش موجود")
        if u["banned"] and not allow_banned:
            raise HTTPException(403, "حسابك محظور: " + (u["ban_reason"] or "مخالفة القوانين"))
        return dict(u)


def need_admin(token: str) -> dict:
    u = user_from_token(token)
    if u["role"] != "admin":
        raise HTTPException(403, "للأدمن بس")
    return u


def are_friends(db, a, b) -> bool:
    return db.execute("SELECT 1 FROM friends WHERE (user_a=? AND user_b=?) OR (user_a=? AND user_b=?)",
                      (a, b, b, a)).fetchone() is not None


def friends_of(db, username):
    rows = db.execute("SELECT user_a, user_b FROM friends WHERE user_a=? OR user_b=?", (username, username)).fetchall()
    return [r["user_b"] if r["user_a"] == username else r["user_a"] for r in rows]


def group_members_of(db, gid):
    return [r["username"] for r in db.execute("SELECT username FROM group_members WHERE group_id=?", (gid,)).fetchall()]


def is_group_member(db, gid, username) -> bool:
    return db.execute("SELECT 1 FROM group_members WHERE group_id=? AND username=?", (gid, username)).fetchone() is not None


def related_users(db, username):
    """الناس اللي لازم يعرفوا لما بروفايلي يتغير: الأصدقاء + أعضاء جروباتي."""
    out = set(friends_of(db, username))
    for g in db.execute("SELECT group_id FROM group_members WHERE username=?", (username,)).fetchall():
        out.update(group_members_of(db, g["group_id"]))
    out.discard(username)
    return out


def valid_image_id(image_id: str) -> bool:
    return bool(image_id) and re.fullmatch(r"[A-Za-z0-9_.\-]{1,80}", image_id) is not None and \
        os.path.exists(os.path.join(UPLOAD_DIR, image_id))


# ---------------------------------------------------------------------------
# إدارة الاتصالات (طابور إرسال لكل مستخدم عشان بطء واحد ميعطلش الباقي)
# ---------------------------------------------------------------------------
class Conn:
    def __init__(self, ws: WebSocket, username: str):
        self.ws = ws
        self.username = username
        self.q: asyncio.Queue = asyncio.Queue(maxsize=800)
        self.closed = False
        self.task: Optional[asyncio.Task] = None
        self.msg_times = deque(maxlen=30)

    def push(self, item, media=False, media_limit=150) -> bool:
        if self.closed:
            return False
        if media and self.q.qsize() > media_limit:
            return False
        try:
            self.q.put_nowait(item)
            return True
        except asyncio.QueueFull:
            if not media:
                self.closed = True
                asyncio.ensure_future(self._force_close())
            return False

    async def _force_close(self):
        try:
            await self.ws.close()
        except Exception:
            pass

    async def writer(self):
        try:
            while True:
                item = await self.q.get()
                if item is None:
                    break
                if isinstance(item, (bytes, bytearray)):
                    await self.ws.send_bytes(bytes(item))
                else:
                    await self.ws.send_text(json.dumps(item, ensure_ascii=False))
        except Exception:
            self.closed = True

    async def close(self, code=1000):
        self.closed = True
        try:
            self.q.put_nowait(None)
        except Exception:
            pass
        try:
            await self.ws.close(code=code)
        except Exception:
            pass


class Manager:
    def __init__(self):
        self.conns: Dict[str, Conn] = {}

    def is_online(self, u) -> bool:
        c = self.conns.get(u)
        return bool(c and not c.closed)

    def send(self, u, data) -> bool:
        c = self.conns.get(u)
        return c.push(data) if c else False

    def send_many(self, users, data):
        for u in users:
            self.send(u, data)


manager = Manager()


async def notify_presence(db_username, online: bool):
    with get_db() as db:
        targets = related_users(db, db_username)
    manager.send_many(targets, {"type": "presence", "username": db_username, "online": online})


# ---------------------------------------------------------------------------
# غرف الصوت
# ---------------------------------------------------------------------------
class Room:
    def __init__(self, rid, kind, group_id=None):
        self.id = rid
        self.kind = kind
        self.group_id = group_id
        self.members: Dict[str, dict] = {}
        self.watch: Dict[str, set] = {}
        self.caller = None
        self.callee = None
        self.answered = False
        self.started = now_ts()
        self.answered_at = 0.0
        self.ring_task: Optional[asyncio.Task] = None


rooms: Dict[str, Room] = {}
user_room: Dict[str, str] = {}


def room_participants(room: Room):
    return [{"username": u, "muted": s["muted"], "deafened": s["deafened"], "sharing": s["sharing"]}
            for u, s in room.members.items()]


def broadcast_room_state(room: Room):
    msg = {"type": "voice_state", "room": room.id, "kind": room.kind, "group_id": room.group_id,
           "participants": room_participants(room)}
    manager.send_many(list(room.members.keys()), msg)


def broadcast_group_call(gid):
    room = rooms.get(f"group-{gid}")
    with get_db() as db:
        members = group_members_of(db, gid)
    manager.send_many(members, {"type": "group_call_active", "group_id": gid,
                                "participants": list(room.members.keys()) if room else []})


def add_system_message(a, b, gid, text):
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO messages (from_user, to_user, group_id, msg_type, content, created_at) VALUES (?,?,?,?,?,?)",
            (a or "", b or "", gid, "system", text, now_iso()))
        mid = cur.lastrowid
        created = db.execute("SELECT created_at FROM messages WHERE id=?", (mid,)).fetchone()["created_at"]
    payload = {"type": "message", "id": mid, "from": a or "", "to": b or None, "group_id": gid,
               "msg_type": "system", "content": text, "image_id": None, "reply_to": None, "reply": None,
               "created_at": created}
    if gid:
        with get_db() as db:
            members = group_members_of(db, gid)
        manager.send_many(members, payload)
    else:
        manager.send_many([a, b], payload)


def fmt_duration(sec):
    sec = int(sec)
    return f"{sec // 60:02d}:{sec % 60:02d}"


async def end_dm_room(room: Room, reason: str, by: Optional[str] = None):
    """بينهي مكالمة خاصة ويبلغ الطرفين."""
    if room.id not in rooms:
        return
    if room.ring_task and not room.ring_task.done() and room.ring_task is not asyncio.current_task():
        room.ring_task.cancel()
    caller, callee = room.caller, room.callee
    members = list(room.members.keys())
    for u in members:
        user_room.pop(u, None)
    rooms.pop(room.id, None)
    if room.answered:
        manager.send_many(members, {"type": "call_ended", "room": room.id, "reason": reason, "by": by})
        add_system_message(caller, callee, None, f"انتهت المكالمة الصوتية ({fmt_duration(now_ts() - room.answered_at)})")
    else:
        if reason == "declined":
            manager.send(caller, {"type": "call_declined", "room": room.id, "by": callee})
            add_system_message(caller, callee, None, "مكالمة مرفوضة")
        elif reason == "cancelled":
            manager.send(callee, {"type": "call_missed", "room": room.id, "from": caller})
            add_system_message(caller, callee, None, "مكالمة فائتة")
        elif reason == "no_answer":
            manager.send(caller, {"type": "call_failed", "room": room.id, "reason": "no_answer", "to": callee})
            manager.send(callee, {"type": "call_missed", "room": room.id, "from": caller})
            add_system_message(caller, callee, None, "مكالمة فائتة")
        else:
            manager.send_many([caller], {"type": "call_failed", "room": room.id, "reason": reason, "to": callee})


async def leave_room(user: str, reason="left", notify_self=True):
    rid = user_room.get(user)
    room = rooms.get(rid) if rid else None
    if not room:
        user_room.pop(user, None)
        return
    if room.kind == "dm":
        if notify_self:
            manager.send(user, {"type": "voice_left", "room": rid, "reason": reason})
        if not room.answered and user == room.caller:
            await end_dm_room(room, "cancelled", user)
        elif room.answered:
            await end_dm_room(room, reason, user)
        else:
            await end_dm_room(room, "declined", user)
        return
    # group room
    st = room.members.pop(user, None)
    user_room.pop(user, None)
    room.watch.pop(user, None)
    for watchers in room.watch.values():
        watchers.discard(user)
    if notify_self:
        manager.send(user, {"type": "voice_left", "room": rid, "reason": reason})
    if st and st.get("sharing"):
        manager.send_many(list(room.members.keys()), {"type": "screen_stopped", "room": rid, "by": user})
    if not room.members:
        rooms.pop(rid, None)
    else:
        broadcast_room_state(room)
    broadcast_group_call(room.group_id)


async def ring_timeout(room: Room):
    try:
        await asyncio.sleep(RING_SECONDS)
        if room.id in rooms and not room.answered:
            await end_dm_room(room, "no_answer")
    except asyncio.CancelledError:
        pass


def relay_media(room: Room, sender: str, kind: int, payload: bytes):
    st = room.members.get(sender)
    if not st:
        return
    nb = sender.encode()
    frame = bytes([kind, len(nb)]) + nb + payload
    if kind == 1:
        if st["muted"]:
            return
        for u, s in room.members.items():
            if u == sender or s["deafened"]:
                continue
            c = manager.conns.get(u)
            if c:
                c.push(frame, media=True, media_limit=150)
    elif kind == 2:
        if not st["sharing"]:
            return
        for w in list(room.watch.get(sender, ())):
            c = manager.conns.get(w)
            if c:
                c.push(frame, media=True, media_limit=40)


# ---------------------------------------------------------------------------
# مساعدات الرسائل
# ---------------------------------------------------------------------------
def reply_preview(db, parent_id):
    if not parent_id:
        return None
    p = db.execute("SELECT id, from_user, msg_type, content, deleted_all FROM messages WHERE id=?", (parent_id,)).fetchone()
    if not p:
        return None
    gone = bool(p["deleted_all"])
    content = None if gone else (p["content"] or "")[:120]
    return {"id": p["id"], "from": p["from_user"], "msg_type": p["msg_type"], "content": content, "deleted": gone}


def msg_dict(db, r, admin_view=False):
    gone = bool(r["deleted_all"])
    d = {"id": r["id"], "from": r["from_user"], "to": r["to_user"] or None, "group_id": r["group_id"],
         "msg_type": r["msg_type"], "content": r["content"], "image_id": r["image_path"],
         "reply_to": r["reply_to"], "created_at": r["created_at"], "deleted": gone}
    if gone and not admin_view:
        d["content"], d["image_id"] = None, None
    d["reply"] = reply_preview(db, r["reply_to"])
    return d


# ---------------------------------------------------------------------------
# تسجيل / دخول / بروفايل
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"ok": True, "version": 2, "voice": True, "t": now_ts()}


@app.post("/register")
async def register(username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "اسم المستخدم من 3 لـ 24 حرف (حروف وأرقام و _ . - بس)")
    if username.lower() in RESERVED_NAMES:
        raise HTTPException(400, "الاسم ده محجوز")
    if len(password) < 4:
        raise HTTPException(400, "الباسورد 4 أحرف على الأقل")
    with get_db() as db:
        if db.execute("SELECT 1 FROM users WHERE lower(username)=lower(?)", (username,)).fetchone():
            raise HTTPException(400, "اسم المستخدم ده مستخدم قبل كدا")
        salt, h = hash_password(password)
        db.execute("INSERT INTO users (username, salt, password_hash, created_at) VALUES (?,?,?,?)",
                   (username, salt, h, now_iso()))
    return {"ok": True}


_login_fail: Dict[str, deque] = {}


@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    key = username.lower()
    dq = _login_fail.setdefault(key, deque(maxlen=10))
    now = now_ts()
    if len(dq) >= 8 and now - dq[0] < 300:
        raise HTTPException(429, "محاولات كتير غلط، استنى خمس دقايق")
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not verify_password(password, row["salt"], row["password_hash"]):
            dq.append(now)
            raise HTTPException(401, "اسم المستخدم أو الباسورد غلط")
        if row["banned"]:
            raise HTTPException(403, "حسابك محظور: " + (row["ban_reason"] or "مخالفة القوانين"))
        dq.clear()
        token = secrets.token_hex(24)
        db.execute("INSERT INTO sessions (token, username) VALUES (?,?)", (token, row["username"]))
        prof = profile_of(row)
    return {"ok": True, "token": token, "username": row["username"], "profile": prof,
            "timeout_until": row["timeout_until"] or 0}


@app.get("/me")
async def me(token: str):
    u = user_from_token(token)
    return {"profile": profile_of(u), "timeout_until": u["timeout_until"] or 0,
            "timeout_reason": u["timeout_reason"] or ""}


@app.post("/profile")
async def update_profile(token: str = Form(...), nickname: Optional[str] = Form(None),
                         avatar: Optional[str] = Form(None), banner: Optional[str] = Form(None)):
    u = user_from_token(token)
    sets, vals = [], []
    if nickname is not None:
        nickname = nickname.strip()[:32]
        sets.append("nickname=?")
        vals.append(nickname)
    for name, val in (("avatar", avatar), ("banner", banner)):
        if val is not None:
            if val and not valid_image_id(val):
                raise HTTPException(400, "الصورة مش موجودة")
            sets.append(f"{name}=?")
            vals.append(val)
    if sets:
        with get_db() as db:
            db.execute(f"UPDATE users SET {', '.join(sets)} WHERE username=?", (*vals, u["username"]))
            row = get_user(db, u["username"])
            targets = related_users(db, u["username"])
        prof = profile_of(row)
        manager.send_many(list(targets) + [u["username"]], {"type": "profile_update", "profile": prof})
        return {"ok": True, "profile": prof}
    return {"ok": True, "profile": profile_of(u)}


@app.get("/user/{username}")
async def user_profile(username: str, token: str):
    user_from_token(token)
    with get_db() as db:
        row = get_user(db, username)
        if not row:
            raise HTTPException(404, "المستخدم مش موجود")
        prof = profile_of(row)
    prof["online"] = manager.is_online(username)
    return prof


@app.get("/search")
async def search_users(query: str, token: str):
    me_ = user_from_token(token)
    q = query.replace("%", "").replace("_", "\\_")
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM users WHERE (username LIKE ? ESCAPE '\\' OR nickname LIKE ? ESCAPE '\\') "
            "AND username != ? AND banned=0 LIMIT 20", (f"%{q}%", f"%{q}%", me_["username"])).fetchall()
    return {"results": [profile_of(r) for r in rows]}


# ---------------------------------------------------------------------------
# الأصدقاء
# ---------------------------------------------------------------------------
@app.post("/friend_request")
async def send_friend_request(token: str = Form(...), to_user: str = Form(...)):
    me_ = user_from_token(token)["username"]
    if me_ == to_user:
        raise HTTPException(400, "متقدرش تبعت طلب لنفسك")
    with get_db() as db:
        target = get_user(db, to_user)
        if not target or target["banned"]:
            raise HTTPException(404, "المستخدم مش موجود")
        if are_friends(db, me_, to_user):
            raise HTTPException(400, "انتو أصحاب بالفعل")
        if db.execute("SELECT 1 FROM friend_requests WHERE from_user=? AND to_user=? AND status='pending'",
                      (me_, to_user)).fetchone():
            raise HTTPException(400, "الطلب اتبعت قبل كدا ولسه معلق")
        db.execute("INSERT INTO friend_requests (from_user, to_user, status, created_at) VALUES (?,?,?,?)",
                   (me_, to_user, "pending", now_iso()))
    manager.send(to_user, {"type": "friend_request", "from": me_})
    return {"ok": True}


@app.get("/friend_requests")
async def list_requests(token: str):
    me_ = user_from_token(token)["username"]
    with get_db() as db:
        rows = db.execute(
            "SELECT r.id, r.from_user, r.created_at, u.nickname, u.avatar, u.role FROM friend_requests r "
            "JOIN users u ON u.username = r.from_user WHERE r.to_user=? AND r.status='pending'", (me_,)).fetchall()
    return {"requests": [dict(r) for r in rows]}


@app.post("/friend_response")
async def respond_request(token: str = Form(...), request_id: int = Form(...), action: str = Form(...)):
    me_ = user_from_token(token)["username"]
    with get_db() as db:
        row = db.execute("SELECT * FROM friend_requests WHERE id=? AND to_user=? AND status='pending'",
                         (request_id, me_)).fetchone()
        if not row:
            raise HTTPException(404, "الطلب مش موجود")
        if action == "accept":
            db.execute("UPDATE friend_requests SET status='accepted' WHERE id=?", (request_id,))
            if not are_friends(db, row["from_user"], me_):
                db.execute("INSERT INTO friends (user_a, user_b) VALUES (?,?)", (row["from_user"], me_))
        elif action == "reject":
            db.execute("UPDATE friend_requests SET status='rejected' WHERE id=?", (request_id,))
        else:
            raise HTTPException(400, "action لازم تكون accept أو reject")
    manager.send(row["from_user"], {"type": "friend_response", "by": me_, "action": action})
    if action == "accept":
        manager.send(me_, {"type": "friends_changed"})
    return {"ok": True}


@app.post("/unfriend")
async def unfriend(token: str = Form(...), username: str = Form(...)):
    me_ = user_from_token(token)["username"]
    with get_db() as db:
        db.execute("DELETE FROM friends WHERE (user_a=? AND user_b=?) OR (user_a=? AND user_b=?)",
                   (me_, username, username, me_))
    manager.send(username, {"type": "friends_changed"})
    manager.send(me_, {"type": "friends_changed"})
    return {"ok": True}


@app.get("/friends")
async def friends(token: str):
    me_ = user_from_token(token)["username"]
    with get_db() as db:
        names = friends_of(db, me_)
        rows = [get_user(db, n) for n in names]
    out = []
    for r in rows:
        if r and not r["banned"]:
            p = profile_of(r)
            p["online"] = manager.is_online(r["username"])
            out.append(p)
    return {"friends": out}


# ---------------------------------------------------------------------------
# الرسائل
# ---------------------------------------------------------------------------
@app.get("/messages")
async def messages(token: str, other: str, limit: int = 100):
    me_ = user_from_token(token)["username"]
    limit = max(1, min(limit, 300))
    with get_db() as db:
        rows = db.execute(
            """SELECT * FROM messages WHERE group_id IS NULL
               AND ((from_user=? AND to_user=?) OR (from_user=? AND to_user=?))
               AND id NOT IN (SELECT msg_id FROM message_hidden WHERE username=?)
               ORDER BY id DESC LIMIT ?""", (me_, other, other, me_, me_, limit)).fetchall()
        out = [msg_dict(db, r) for r in rows]
    out.reverse()
    return {"messages": out}


@app.get("/group_messages")
async def group_messages(token: str, group_id: int, limit: int = 100):
    me_ = user_from_token(token)["username"]
    limit = max(1, min(limit, 300))
    with get_db() as db:
        if not is_group_member(db, group_id, me_):
            raise HTTPException(403, "انت مش في الجروب ده")
        rows = db.execute(
            """SELECT * FROM messages WHERE group_id=?
               AND id NOT IN (SELECT msg_id FROM message_hidden WHERE username=?)
               ORDER BY id DESC LIMIT ?""", (group_id, me_, limit)).fetchall()
        out = [msg_dict(db, r) for r in rows]
    out.reverse()
    return {"messages": out}


def conversation_audience(db, r):
    if r["group_id"]:
        return group_members_of(db, r["group_id"])
    return [x for x in (r["from_user"], r["to_user"]) if x]


@app.post("/delete_message")
async def delete_message(token: str = Form(...), msg_id: int = Form(...), scope: str = Form("me")):
    u = user_from_token(token)
    me_ = u["username"]
    with get_db() as db:
        r = db.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
        if not r:
            raise HTTPException(404, "الرسالة مش موجودة")
        audience = conversation_audience(db, r)
        if me_ not in audience:
            raise HTTPException(403, "مش من حقك")
        if scope == "me":
            db.execute("INSERT OR IGNORE INTO message_hidden (msg_id, username) VALUES (?,?)", (msg_id, me_))
        elif scope == "all":
            if r["from_user"] != me_ and u["role"] != "admin":
                raise HTTPException(403, "تقدر تحذف من عند الكل رسايلك انت بس")
            if r["msg_type"] == "system":
                raise HTTPException(400, "مينفعش")
            db.execute("UPDATE messages SET deleted_all=1 WHERE id=?", (msg_id,))
            if u["role"] == "admin" and r["from_user"] != me_:
                audit(db, me_, "delete_message", r["from_user"], f"msg {msg_id}")
        else:
            raise HTTPException(400, "scope لازم me أو all")
    if scope == "all":
        manager.send_many(audience, {"type": "message_deleted", "id": msg_id, "group_id": r["group_id"],
                                     "from": r["from_user"], "to": r["to_user"] or None})
    return {"ok": True}


# ---------------------------------------------------------------------------
# الجروبات
# ---------------------------------------------------------------------------
def group_info(db, gid, with_members=True):
    g = db.execute("SELECT * FROM groups WHERE id=?", (gid,)).fetchone()
    if not g:
        return None
    members = group_members_of(db, gid)
    room = rooms.get(f"group-{gid}")
    info = {"id": g["id"], "name": g["name"], "owner": g["owner"],
            "call": list(room.members.keys()) if room else []}
    if with_members:
        profs = []
        for m in members:
            r = get_user(db, m)
            if r:
                p = profile_of(r)
                p["online"] = manager.is_online(m)
                profs.append(p)
        info["members"] = profs
    return info


@app.get("/groups")
async def list_groups(token: str):
    me_ = user_from_token(token)["username"]
    with get_db() as db:
        ids = [r["group_id"] for r in db.execute("SELECT group_id FROM group_members WHERE username=?", (me_,)).fetchall()]
        out = [group_info(db, g) for g in ids]
    return {"groups": [g for g in out if g]}


@app.post("/groups_create")
async def create_group(token: str = Form(...), name: str = Form(...), members: str = Form("[]")):
    me_ = user_from_token(token)["username"]
    name = name.strip()[:40]
    if not name:
        raise HTTPException(400, "اكتب اسم للجروب")
    try:
        wanted = [str(x) for x in json.loads(members)]
    except Exception:
        raise HTTPException(400, "قايمة الأعضاء غلط")
    with get_db() as db:
        cur = db.execute("INSERT INTO groups (name, owner, created_at) VALUES (?,?,?)", (name, me_, now_iso()))
        gid = cur.lastrowid
        db.execute("INSERT INTO group_members (group_id, username) VALUES (?,?)", (gid, me_))
        added = []
        for w in dict.fromkeys(wanted):
            if w != me_ and are_friends(db, me_, w):
                db.execute("INSERT OR IGNORE INTO group_members (group_id, username) VALUES (?,?)", (gid, w))
                added.append(w)
        info = group_info(db, gid)
    manager.send_many(added + [me_], {"type": "group_update", "group_id": gid})
    add_system_message(me_, None, gid, f"{me_} عمل الجروب")
    return {"ok": True, "group": info}


def need_owner(db, gid, me_):
    g = db.execute("SELECT * FROM groups WHERE id=?", (gid,)).fetchone()
    if not g:
        raise HTTPException(404, "الجروب مش موجود")
    if g["owner"] != me_:
        raise HTTPException(403, "صاحب الجروب بس يقدر يعمل كده")
    return g


@app.post("/groups_add")
async def group_add(token: str = Form(...), group_id: int = Form(...), username: str = Form(...)):
    me_ = user_from_token(token)["username"]
    with get_db() as db:
        need_owner(db, group_id, me_)
        if not get_user(db, username):
            raise HTTPException(404, "المستخدم مش موجود")
        if not are_friends(db, me_, username):
            raise HTTPException(400, "لازم يكون صديقك")
        if is_group_member(db, group_id, username):
            raise HTTPException(400, "هو في الجروب بالفعل")
        db.execute("INSERT INTO group_members (group_id, username) VALUES (?,?)", (group_id, username))
        members = group_members_of(db, group_id)
    manager.send_many(members, {"type": "group_update", "group_id": group_id})
    add_system_message(me_, None, group_id, f"{me_} ضاف {username}")
    return {"ok": True}


async def _remove_member(gid, username, actor, kicked):
    with get_db() as db:
        db.execute("DELETE FROM group_members WHERE group_id=? AND username=?", (gid, username))
        members = group_members_of(db, gid)
    rid = user_room.get(username)
    if rid == f"group-{gid}":
        await leave_room(username, "removed")
    manager.send(username, {"type": "group_removed", "group_id": gid})
    manager.send_many(members, {"type": "group_update", "group_id": gid})
    add_system_message(actor, None, gid, f"{actor} شال {username}" if kicked else f"{username} خرج من الجروب")


@app.post("/groups_remove")
async def group_remove(token: str = Form(...), group_id: int = Form(...), username: str = Form(...)):
    me_ = user_from_token(token)["username"]
    with get_db() as db:
        need_owner(db, group_id, me_)
        if username == me_:
            raise HTTPException(400, "استخدم خروج من الجروب")
        if not is_group_member(db, group_id, username):
            raise HTTPException(404, "مش عضو")
    await _remove_member(group_id, username, me_, True)
    return {"ok": True}


@app.post("/groups_leave")
async def group_leave(token: str = Form(...), group_id: int = Form(...)):
    me_ = user_from_token(token)["username"]
    with get_db() as db:
        g = db.execute("SELECT * FROM groups WHERE id=?", (group_id,)).fetchone()
        if not g or not is_group_member(db, group_id, me_):
            raise HTTPException(404, "مش موجود")
        members = group_members_of(db, group_id)
        new_owner = None
        if g["owner"] == me_:
            rest = [m for m in members if m != me_]
            if rest:
                new_owner = rest[0]
                db.execute("UPDATE groups SET owner=? WHERE id=?", (new_owner, group_id))
    await _remove_member(group_id, me_, me_, False)
    with get_db() as db:
        left = group_members_of(db, group_id)
        if not left:
            db.execute("DELETE FROM groups WHERE id=?", (group_id,))
            db.execute("DELETE FROM messages WHERE group_id=?", (group_id,))
    return {"ok": True}


@app.post("/groups_rename")
async def group_rename(token: str = Form(...), group_id: int = Form(...), name: str = Form(...)):
    me_ = user_from_token(token)["username"]
    name = name.strip()[:40]
    if not name:
        raise HTTPException(400, "اكتب اسم")
    with get_db() as db:
        need_owner(db, group_id, me_)
        db.execute("UPDATE groups SET name=? WHERE id=?", (name, group_id))
        members = group_members_of(db, group_id)
    manager.send_many(members, {"type": "group_update", "group_id": group_id})
    return {"ok": True}


@app.post("/groups_delete")
async def group_delete(token: str = Form(...), group_id: int = Form(...)):
    me_ = user_from_token(token)["username"]
    with get_db() as db:
        need_owner(db, group_id, me_)
        members = group_members_of(db, group_id)
    for m in members:
        if user_room.get(m) == f"group-{group_id}":
            await leave_room(m, "group_deleted")
    with get_db() as db:
        db.execute("DELETE FROM group_members WHERE group_id=?", (group_id,))
        db.execute("DELETE FROM groups WHERE id=?", (group_id,))
        db.execute("DELETE FROM messages WHERE group_id=?", (group_id,))
    manager.send_many(members, {"type": "group_removed", "group_id": group_id})
    return {"ok": True}


# ---------------------------------------------------------------------------
# الصور
# ---------------------------------------------------------------------------
@app.post("/upload_image")
async def upload_image(token: str = Form(...), file: UploadFile = File(...)):
    user_from_token(token)
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in IMAGE_EXTS:
        raise HTTPException(400, "الصيغة مش مدعومة (png / jpg / gif / webp / bmp)")
    content = await file.read(MAX_UPLOAD + 1)
    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, "الصورة أكبر من 10 ميجا")
    if len(content) < 16:
        raise HTTPException(400, "الملف فاضي")
    fname = f"{secrets.token_hex(12)}{ext}"
    with open(os.path.join(UPLOAD_DIR, fname), "wb") as f:
        f.write(content)
    return {"ok": True, "image_id": fname}


@app.get("/image/{image_id}")
async def get_image(image_id: str):
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,80}", image_id):
        raise HTTPException(404, "الصورة مش موجودة")
    path = os.path.join(UPLOAD_DIR, image_id)
    if not os.path.isfile(path):
        raise HTTPException(404, "الصورة مش موجودة")
    return FileResponse(path, headers={"Cache-Control": "public, max-age=86400"})


# ---------------------------------------------------------------------------
# الريبورتات
# ---------------------------------------------------------------------------
@app.post("/report")
async def report_user(token: str = Form(...), reported: str = Form(...), reason: str = Form("other"),
                      details: str = Form(""), group_id: Optional[int] = Form(None), msg_id: Optional[int] = Form(None)):
    me_ = user_from_token(token)["username"]
    if reported == me_:
        raise HTTPException(400, "متقدرش تبلغ عن نفسك")
    if reason not in REPORT_REASONS:
        reason = "other"
    details = details.strip()[:2000]
    if len(details) < 3:
        raise HTTPException(400, "اكتب تفاصيل المشكلة")
    with get_db() as db:
        if not get_user(db, reported):
            raise HTTPException(404, "المستخدم مش موجود")
        if db.execute("SELECT COUNT(*) c FROM reports WHERE reporter=? AND created_at > ?",
                      (me_, datetime.fromtimestamp(now_ts() - 3600, timezone.utc).isoformat())).fetchone()["c"] >= 10:
            raise HTTPException(429, "بلاغات كتير في وقت قصير")
        cur = db.execute(
            "INSERT INTO reports (reporter, reported, reason, details, group_id, msg_id, created_at) VALUES (?,?,?,?,?,?,?)",
            (me_, reported, reason, details, group_id, msg_id, now_iso()))
        rid = cur.lastrowid
        admins = [r["username"] for r in db.execute("SELECT username FROM users WHERE role='admin'").fetchall()]
    manager.send_many(admins, {"type": "new_report", "id": rid, "reporter": me_, "reported": reported, "reason": reason})
    return {"ok": True, "id": rid}


# ---------------------------------------------------------------------------
# لوحة الأدمن
# ---------------------------------------------------------------------------
def protect_target(db, admin, target):
    row = get_user(db, target)
    if not row:
        raise HTTPException(404, "المستخدم مش موجود")
    if target == admin:
        raise HTTPException(403, "مينفعش تعمل كده على نفسك")
    if row["role"] == "admin":
        raise HTTPException(403, "مينفعش تعمل كده على أدمن")
    return row


async def disconnect_user(username, payload=None):
    c = manager.conns.get(username)
    await leave_room(username, "removed", notify_self=False)
    if c:
        if payload:
            c.push(payload)
            await asyncio.sleep(0.15)
        await c.close(code=4001)
        manager.conns.pop(username, None)
        await notify_presence(username, False)


@app.get("/admin/users")
async def admin_users(token: str, q: str = "", limit: int = 200):
    need_admin(token)
    q = q.replace("%", "").replace("_", "\\_")
    with get_db() as db:
        rows = db.execute("SELECT * FROM users WHERE username LIKE ? ESCAPE '\\' OR nickname LIKE ? ESCAPE '\\' "
                          "ORDER BY id DESC LIMIT ?", (f"%{q}%", f"%{q}%", max(1, min(limit, 500)))).fetchall()
    out = []
    for r in rows:
        d = profile_of(r)
        d.update({"banned": bool(r["banned"]), "ban_reason": r["ban_reason"] or "",
                  "timeout_until": r["timeout_until"] or 0, "created_at": r["created_at"],
                  "online": manager.is_online(r["username"]), "in_voice": user_room.get(r["username"])})
        out.append(d)
    return {"users": out}


@app.get("/admin/user_chats")
async def admin_user_chats(token: str, username: str):
    adm = need_admin(token)
    with get_db() as db:
        partners = db.execute(
            """SELECT CASE WHEN from_user=? THEN to_user ELSE from_user END AS partner, COUNT(*) c, MAX(created_at) last
               FROM messages WHERE group_id IS NULL AND msg_type!='system' AND (from_user=? OR to_user=?)
               GROUP BY partner ORDER BY last DESC""", (username, username, username)).fetchall()
        groups = db.execute(
            "SELECT g.id, g.name FROM groups g JOIN group_members m ON m.group_id=g.id WHERE m.username=?",
            (username,)).fetchall()
        audit(db, adm["username"], "browse_chats", username, "")
    return {"partners": [dict(p) for p in partners if p["partner"]], "groups": [dict(g) for g in groups]}


@app.get("/admin/conversation")
async def admin_conversation(token: str, user_a: str, user_b: str, limit: int = 300):
    adm = need_admin(token)
    with get_db() as db:
        rows = db.execute(
            """SELECT * FROM messages WHERE group_id IS NULL
               AND ((from_user=? AND to_user=?) OR (from_user=? AND to_user=?)) ORDER BY id DESC LIMIT ?""",
            (user_a, user_b, user_b, user_a, max(1, min(limit, 1000)))).fetchall()
        out = [msg_dict(db, r, admin_view=True) for r in rows]
        audit(db, adm["username"], "view_chat", f"{user_a}<->{user_b}", "")
    out.reverse()
    return {"messages": out}


@app.get("/admin/group_messages")
async def admin_group_messages(token: str, group_id: int, limit: int = 300):
    adm = need_admin(token)
    with get_db() as db:
        rows = db.execute("SELECT * FROM messages WHERE group_id=? ORDER BY id DESC LIMIT ?",
                          (group_id, max(1, min(limit, 1000)))).fetchall()
        out = [msg_dict(db, r, admin_view=True) for r in rows]
        audit(db, adm["username"], "view_group", str(group_id), "")
    out.reverse()
    return {"messages": out}


@app.get("/admin/reports")
async def admin_reports(token: str, status: str = "open"):
    need_admin(token)
    with get_db() as db:
        if status == "all":
            rows = db.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 300").fetchall()
        else:
            rows = db.execute("SELECT * FROM reports WHERE status=? ORDER BY id DESC LIMIT 300", (status,)).fetchall()
    return {"reports": [dict(r) for r in rows]}


@app.post("/admin/report_status")
async def admin_report_status(token: str = Form(...), report_id: int = Form(...), status: str = Form(...),
                              note: str = Form("")):
    adm = need_admin(token)
    if status not in ("open", "resolved", "dismissed"):
        raise HTTPException(400, "status غلط")
    with get_db() as db:
        db.execute("UPDATE reports SET status=?, handled_by=?, note=? WHERE id=?",
                   (status, adm["username"], note[:500], report_id))
        audit(db, adm["username"], f"report_{status}", str(report_id), note[:200])
    return {"ok": True}


@app.post("/admin/ban")
async def admin_ban(token: str = Form(...), username: str = Form(...), reason: str = Form("")):
    adm = need_admin(token)
    with get_db() as db:
        protect_target(db, adm["username"], username)
        db.execute("UPDATE users SET banned=1, ban_reason=? WHERE username=?", (reason[:200], username))
        db.execute("DELETE FROM sessions WHERE username=?", (username,))
        audit(db, adm["username"], "ban", username, reason[:200])
    await disconnect_user(username, {"type": "banned", "reason": reason or "مخالفة القوانين"})
    return {"ok": True}


@app.post("/admin/unban")
async def admin_unban(token: str = Form(...), username: str = Form(...)):
    adm = need_admin(token)
    with get_db() as db:
        if not get_user(db, username):
            raise HTTPException(404, "المستخدم مش موجود")
        db.execute("UPDATE users SET banned=0, ban_reason='' WHERE username=?", (username,))
        audit(db, adm["username"], "unban", username, "")
    return {"ok": True}


@app.post("/admin/timeout")
async def admin_timeout(token: str = Form(...), username: str = Form(...), minutes: float = Form(...),
                        reason: str = Form("")):
    adm = need_admin(token)
    minutes = max(0.0, min(minutes, 60 * 24 * 28))
    until = now_ts() + minutes * 60 if minutes > 0 else 0
    with get_db() as db:
        protect_target(db, adm["username"], username)
        db.execute("UPDATE users SET timeout_until=?, timeout_reason=? WHERE username=?", (until, reason[:200], username))
        audit(db, adm["username"], "timeout" if minutes > 0 else "untimeout", username, f"{minutes}m {reason[:150]}")
    if minutes > 0:
        await leave_room(username, "timeout")
    manager.send(username, {"type": "timeout", "until": until, "reason": reason})
    return {"ok": True, "until": until}


@app.post("/admin/delete_user")
async def admin_delete_user(token: str = Form(...), username: str = Form(...)):
    adm = need_admin(token)
    with get_db() as db:
        protect_target(db, adm["username"], username)
        owned = [r["id"] for r in db.execute("SELECT id FROM groups WHERE owner=?", (username,)).fetchall()]
        for gid in owned:
            rest = [m for m in group_members_of(db, gid) if m != username]
            if rest:
                db.execute("UPDATE groups SET owner=? WHERE id=?", (rest[0], gid))
        audit(db, adm["username"], "delete_user", username, "")
    await disconnect_user(username, {"type": "banned", "reason": "تم حذف حسابك"})
    with get_db() as db:
        affected = related_users(db, username)
        db.execute("DELETE FROM sessions WHERE username=?", (username,))
        db.execute("DELETE FROM friends WHERE user_a=? OR user_b=?", (username, username))
        db.execute("DELETE FROM friend_requests WHERE from_user=? OR to_user=?", (username, username))
        db.execute("DELETE FROM message_hidden WHERE username=?", (username,))
        db.execute("DELETE FROM group_members WHERE username=?", (username,))
        db.execute("DELETE FROM messages WHERE from_user=? OR to_user=?", (username, username))
        db.execute("DELETE FROM users WHERE username=?", (username,))
        empty = [r["id"] for r in db.execute(
            "SELECT id FROM groups WHERE id NOT IN (SELECT DISTINCT group_id FROM group_members)").fetchall()]
        for gid in empty:
            db.execute("DELETE FROM groups WHERE id=?", (gid,))
            db.execute("DELETE FROM messages WHERE group_id=?", (gid,))
    manager.send_many(affected, {"type": "friends_changed"})
    manager.send_many(affected, {"type": "group_update", "group_id": 0})
    return {"ok": True}


@app.post("/admin/reset_password")
async def admin_reset_password(token: str = Form(...), username: str = Form(...), new_password: str = Form(...)):
    adm = need_admin(token)
    if len(new_password) < 4:
        raise HTTPException(400, "الباسورد 4 أحرف على الأقل")
    with get_db() as db:
        protect_target(db, adm["username"], username)
        salt, h = hash_password(new_password)
        db.execute("UPDATE users SET salt=?, password_hash=? WHERE username=?", (salt, h, username))
        db.execute("DELETE FROM sessions WHERE username=?", (username,))
        audit(db, adm["username"], "reset_password", username, "")
    await disconnect_user(username, {"type": "banned", "reason": "الأدمن غيّر الباسورد بتاعك، سجل دخول بالجديد"})
    return {"ok": True}


@app.post("/admin/voice_kick")
async def admin_voice_kick(token: str = Form(...), username: str = Form(...)):
    adm = need_admin(token)
    with get_db() as db:
        protect_target(db, adm["username"], username)
        audit(db, adm["username"], "voice_kick", username, "")
    if username not in user_room:
        raise HTTPException(404, "مش في مكالمة")
    manager.send(username, {"type": "voice_kicked", "by": "admin"})
    await leave_room(username, "kicked")
    return {"ok": True}


@app.get("/admin/voice_rooms")
async def admin_voice_rooms(token: str):
    need_admin(token)
    return {"rooms": [{"id": r.id, "kind": r.kind, "group_id": r.group_id,
                       "participants": room_participants(r)} for r in rooms.values()]}


@app.get("/admin/audit")
async def admin_audit(token: str, limit: int = 200):
    need_admin(token)
    with get_db() as db:
        rows = db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),)).fetchall()
    return {"audit": [dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# أداة تعيين الأدمن المستقلة (make_admin.py) - محمية بـ ADMIN_SECRET
# ---------------------------------------------------------------------------
async def check_secret(secret: Optional[str]):
    if not ADMIN_SECRET:
        raise HTTPException(503, "ADMIN_SECRET مش متظبط على السيرفر")
    if not secret or not secrets.compare_digest(secret, ADMIN_SECRET):
        await asyncio.sleep(1.0)
        raise HTTPException(403, "السر غلط")


@app.post("/tool/set_role")
async def tool_set_role(username: str = Form(...), role: str = Form(...), x_admin_secret: Optional[str] = Header(None)):
    await check_secret(x_admin_secret)
    if role not in ("admin", "user"):
        raise HTTPException(400, "role لازم admin أو user")
    with get_db() as db:
        row = get_user(db, username)
        if not row:
            raise HTTPException(404, "المستخدم مش موجود")
        db.execute("UPDATE users SET role=? WHERE username=?", (role, username))
        audit(db, "<tool>", f"set_role_{role}", username, "")
        prof = profile_of(get_user(db, username))
        targets = related_users(db, username)
    manager.send_many(list(targets) + [username], {"type": "profile_update", "profile": prof})
    return {"ok": True, "profile": prof}


@app.get("/tool/admins")
async def tool_admins(x_admin_secret: Optional[str] = Header(None)):
    await check_secret(x_admin_secret)
    with get_db() as db:
        rows = db.execute("SELECT username, nickname FROM users WHERE role='admin'").fetchall()
    return {"admins": [dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# WebSocket: الشات اللحظي + المكالمات
# ---------------------------------------------------------------------------
def timeout_info(username):
    with get_db() as db:
        r = get_user(db, username)
    if r and (r["timeout_until"] or 0) > now_ts():
        return r["timeout_until"], r["timeout_reason"] or ""
    return None


async def on_message(conn: Conn, data: dict):
    me_ = conn.username
    cid = data.get("cid")
    t = timeout_info(me_)
    if t:
        conn.push({"type": "error", "code": "timeout", "until": t[0], "reason": t[1], "cid": cid})
        return
    now = now_ts()
    conn.msg_times.append(now)
    if len(conn.msg_times) >= 20 and now - conn.msg_times[-20] < 10:
        conn.push({"type": "error", "code": "rate", "cid": cid})
        return
    msg_type = data.get("msg_type", "text")
    content = (data.get("content") or "")[:4000]
    image_id = data.get("image_id")
    if msg_type == "text":
        if not content.strip():
            return
        image_id = None
    elif msg_type == "image":
        if not valid_image_id(image_id or ""):
            conn.push({"type": "error", "code": "bad_image", "cid": cid})
            return
        content = ""
    else:
        return
    gid = data.get("group_id")
    to = data.get("to")
    reply_to = data.get("reply_to")
    with get_db() as db:
        if gid:
            if not is_group_member(db, int(gid), me_):
                conn.push({"type": "error", "code": "not_member", "cid": cid})
                return
            recipients = [m for m in group_members_of(db, int(gid)) if m != me_]
            gid = int(gid)
            to_store = ""
        else:
            if not to or not are_friends(db, me_, to):
                conn.push({"type": "error", "code": "not_friends", "cid": cid})
                return
            recipients, to_store, gid = [to], to, None
        if reply_to:
            p = db.execute("SELECT * FROM messages WHERE id=?", (int(reply_to),)).fetchone()
            ok = p and ((gid and p["group_id"] == gid) or
                        (not gid and p["group_id"] is None and {p["from_user"], p["to_user"]} == {me_, to}))
            if not ok:
                reply_to = None
        cur = db.execute(
            "INSERT INTO messages (from_user, to_user, group_id, msg_type, content, image_path, reply_to, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)", (me_, to_store, gid, msg_type, content, image_id, reply_to, now_iso()))
        mid = cur.lastrowid
        row = db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        payload = msg_dict(db, row)
    payload["type"] = "message"
    conn.push({"type": "ack", "cid": cid, "id": mid, "created_at": row["created_at"]})
    manager.send_many(recipients, payload)


async def on_voice_json(conn: Conn, data: dict):
    me_ = conn.username
    t = data.get("type")
    if t in ("call_invite", "group_call_join"):
        tm = timeout_info(me_)
        if tm:
            conn.push({"type": "error", "code": "timeout", "until": tm[0], "reason": tm[1]})
            return
    if t == "call_invite":
        to = data.get("to")
        with get_db() as db:
            ok = to and are_friends(db, me_, to)
        if not ok:
            conn.push({"type": "call_failed", "reason": "not_friends", "to": to})
            return
        if not manager.is_online(to):
            conn.push({"type": "call_failed", "reason": "offline", "to": to})
            return
        if to in user_room:
            conn.push({"type": "call_failed", "reason": "busy", "to": to})
            return
        if timeout_info(to):
            pass
        await leave_room(me_, "switch")
        room = Room(f"dm-{uuid.uuid4().hex[:8]}", "dm")
        room.caller, room.callee = me_, to
        room.members[me_] = {"muted": False, "deafened": False, "sharing": False}
        rooms[room.id] = room
        user_room[me_] = room.id
        room.ring_task = asyncio.ensure_future(ring_timeout(room))
        conn.push({"type": "call_ringing", "room": room.id, "to": to})
        manager.send(to, {"type": "incoming_call", "room": room.id, "from": me_, "kind": "dm"})
    elif t == "call_accept":
        room = rooms.get(data.get("room"))
        if not room or room.kind != "dm" or room.callee != me_ or room.answered:
            conn.push({"type": "call_failed", "reason": "gone"})
            return
        await leave_room(me_, "switch")
        room.answered, room.answered_at = True, now_ts()
        if room.ring_task:
            room.ring_task.cancel()
        room.members[me_] = {"muted": False, "deafened": False, "sharing": False}
        user_room[me_] = room.id
        manager.send(room.caller, {"type": "call_accepted", "room": room.id, "by": me_})
        manager.send_many([room.caller, me_], {"type": "voice_joined", "room": room.id, "kind": "dm", "group_id": None,
                                               "participants": room_participants(room)})
        broadcast_room_state(room)
    elif t == "call_decline":
        room = rooms.get(data.get("room"))
        if room and room.kind == "dm" and room.callee == me_ and not room.answered:
            await end_dm_room(room, "declined", me_)
    elif t == "call_leave":
        if user_room.get(me_) == data.get("room") or data.get("room") is None:
            await leave_room(me_, "left")
    elif t == "group_call_join":
        gid = int(data.get("group_id") or 0)
        with get_db() as db:
            if not is_group_member(db, gid, me_):
                conn.push({"type": "call_failed", "reason": "not_member"})
                return
            members = group_members_of(db, gid)
            gname = db.execute("SELECT name FROM groups WHERE id=?", (gid,)).fetchone()["name"]
        rid = f"group-{gid}"
        if user_room.get(me_) == rid:
            return
        await leave_room(me_, "switch")
        room = rooms.get(rid)
        fresh = room is None
        if fresh:
            room = Room(rid, "group", gid)
            rooms[rid] = room
        room.members[me_] = {"muted": False, "deafened": False, "sharing": False}
        user_room[me_] = rid
        manager.send(me_, {"type": "voice_joined", "room": rid, "kind": "group", "group_id": gid,
                           "participants": room_participants(room)})
        broadcast_room_state(room)
        if fresh:
            for m in members:
                if m != me_ and manager.is_online(m) and m not in user_room:
                    manager.send(m, {"type": "incoming_group_call", "room": rid, "group_id": gid,
                                     "group_name": gname, "from": me_})
        broadcast_group_call(gid)
    elif t == "voice_state":
        room = rooms.get(user_room.get(me_))
        if room and room.id == data.get("room"):
            st = room.members[me_]
            st["deafened"] = bool(data.get("deafened"))
            st["muted"] = bool(data.get("muted")) or st["deafened"]
            broadcast_room_state(room)
    elif t == "screen_start":
        room = rooms.get(user_room.get(me_))
        if room and room.id == data.get("room"):
            room.members[me_]["sharing"] = True
            room.watch.setdefault(me_, set())
            broadcast_room_state(room)
            manager.send_many([u for u in room.members if u != me_],
                              {"type": "screen_started", "room": room.id, "by": me_})
    elif t == "screen_stop":
        room = rooms.get(user_room.get(me_))
        if room and room.id == data.get("room") and room.members[me_]["sharing"]:
            room.members[me_]["sharing"] = False
            room.watch.pop(me_, None)
            broadcast_room_state(room)
            manager.send_many([u for u in room.members if u != me_],
                              {"type": "screen_stopped", "room": room.id, "by": me_})
    elif t in ("screen_watch", "screen_unwatch"):
        room = rooms.get(user_room.get(me_))
        target = data.get("target")
        if room and room.id == data.get("room") and target in room.members and room.members[target]["sharing"]:
            ws_ = room.watch.setdefault(target, set())
            if t == "screen_watch":
                ws_.add(me_)
            else:
                ws_.discard(me_)
            manager.send(target, {"type": "screen_viewers", "room": room.id, "count": len(ws_)})


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    conn: Optional[Conn] = None
    username = None
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=15)
        token = first.get("token")
        with get_db() as db:
            s = db.execute("SELECT username FROM sessions WHERE token=?", (token,)).fetchone()
            row = get_user(db, s["username"]) if s else None
        if not row or row["banned"]:
            await ws.send_text(json.dumps({"type": "error", "code": "auth", "message": "توكن غلط"}))
            await ws.close()
            return
        username = row["username"]
        old = manager.conns.get(username)
        if old:
            old.push({"type": "replaced"})
            await asyncio.sleep(0.05)
            await old.close(code=4002)
            await leave_room(username, "replaced", notify_self=False)
        conn = Conn(ws, username)
        conn.task = asyncio.ensure_future(conn.writer())
        manager.conns[username] = conn
        conn.push({"type": "connected", "username": username, "profile": profile_of(row)})
        await notify_presence(username, True)

        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            if msg.get("bytes") is not None:
                b = msg["bytes"]
                if len(b) < 2:
                    continue
                kind = b[0]
                room = rooms.get(user_room.get(username))
                if room:
                    if kind == 1 and len(b) <= 4000:
                        relay_media(room, username, 1, b[1:])
                    elif kind == 2 and len(b) <= 600_000:
                        relay_media(room, username, 2, b[1:])
                continue
            text = msg.get("text")
            if not text:
                continue
            try:
                data = json.loads(text)
            except Exception:
                continue
            t = data.get("type")
            if t == "message":
                await on_message(conn, data)
            elif t == "typing":
                to = data.get("to")
                with get_db() as db:
                    ok = to and are_friends(db, username, to)
                if ok:
                    manager.send(to, {"type": "typing", "from": username})
            elif t == "ping":
                conn.push({"type": "pong"})
            elif t in ("call_invite", "call_accept", "call_decline", "call_leave", "group_call_join",
                       "voice_state", "screen_start", "screen_stop", "screen_watch", "screen_unwatch"):
                await on_voice_json(conn, data)
    except Exception:
        pass
    finally:
        if conn is not None:
            conn.closed = True
            if manager.conns.get(username) is conn:
                manager.conns.pop(username, None)
                try:
                    await leave_room(username, "disconnected", notify_self=False)
                except Exception:
                    pass
                try:
                    await notify_presence(username, False)
                except Exception:
                    pass
            try:
                conn.q.put_nowait(None)
            except Exception:
                pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
