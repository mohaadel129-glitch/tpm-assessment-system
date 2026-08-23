import base64
import hashlib
import hmac
import io
import json
import os
import random
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import cloudinary
import cloudinary.uploader
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="Enterprise Skill Matrix & Assessment System")

# مفاتيح الصلاحيات المتاحة لحسابات الأدمن الفرعية (المديرين العاديين)
# الأدمن المركزي (admin_settings) يملك كل الصلاحيات دائمًا تلقائيًا
ADMIN_PERMISSION_KEYS = [
    "resets", "gallery", "create", "manage", "users", "teams", "analytics", "skills"
]

# ==================== تشفير كلمات المرور (بدون أي مكتبات خارجية) ====================
PBKDF2_ITERATIONS = 260000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """يتحقق من كلمة المرور. يدعم كلمات المرور القديمة المخزّنة كنص صريح توافقًا رجعيًا
    (لضمان استمرار عمل تسجيل الدخول لكل المستخدمين الحاليين دون أي تعطيل)."""
    if not stored or password is None:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt, hash_hex = stored.split("$")
            dk = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iterations)
            )
            return hmac.compare_digest(dk.hex(), hash_hex)
        except Exception:
            return False
    # توافق رجعي: كلمة مرور قديمة مخزّنة كنص صريح من قبل هذا التحديث
    return hmac.compare_digest(stored, password)


def is_hashed_password(stored: str) -> bool:
    return bool(stored) and stored.startswith("pbkdf2_sha256$")


# ==================== جلسات الدخول الموقّعة (بدون أي مكتبات خارجية) ====================
# ملحوظة هامة للنشر: الأفضل ضبط متغيّر بيئة SECRET_KEY ثابت وسرّي يدويًا على السيرفر.
# إن لم يكن مضبوطًا، نشتق مفتاحًا احتياطيًا مستقرًا من DATABASE_URL (ثابت بين كل تشغيل)
# بدلاً من توليد مفتاح عشوائي جديد في كل مرة، لتفادي إبطال كل جلسات الدخول عند أي
# إعادة تشغيل للسيرفر (وهو الخطأ الذي كان يظهر كـ "انتهت صلاحية الجلسة أو أنها غير صالحة").
SECRET_KEY = os.getenv("SECRET_KEY") or hashlib.sha256(
    (os.getenv("DATABASE_URL", "") or "tpm-assessment-system-default-seed-CHANGE-ME").encode("utf-8")
).hexdigest()
TOKEN_VALID_HOURS = 12


def create_token(payload: Dict[str, object]) -> str:
    data = dict(payload)
    data["exp"] = time.time() + TOKEN_VALID_HOURS * 3600
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def decode_token(token: str) -> Dict[str, object]:
    try:
        b64, sig = token.split(".")
        expected_sig = hmac.new(
            SECRET_KEY.encode("utf-8"), b64.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("invalid signature")
        data = json.loads(base64.urlsafe_b64decode(b64.encode("utf-8")))
        if data.get("exp", 0) < time.time():
            raise ValueError("expired")
        return data
    except Exception:
        raise HTTPException(
            status_code=401, detail="انتهت صلاحية الجلسة أو أنها غير صالحة، يرجى تسجيل الدخول مرة أخرى."
        )


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, object]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="يلزم تسجيل الدخول أولاً.")
    payload = decode_token(authorization.split(" ", 1)[1])
    if payload.get("type") != "user":
        raise HTTPException(status_code=401, detail="جلسة غير صالحة.")
    return payload


async def get_current_admin(authorization: Optional[str] = Header(None)) -> Dict[str, object]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="يلزم تسجيل دخول الإدارة أولاً.")
    payload = decode_token(authorization.split(" ", 1)[1])
    if payload.get("type") not in ("admin", "super_admin"):
        raise HTTPException(status_code=401, detail="جلسة إدارة غير صالحة.")
    return payload


async def get_current_super_admin(
    admin: Dict[str, object] = Depends(get_current_admin)
) -> Dict[str, object]:
    if admin.get("type") != "super_admin":
        raise HTTPException(
            status_code=403, detail="هذا الإجراء متاح للأدمن المركزي فقط."
        )
    return admin


def require_permission(perm_key: str):
    async def _dep(admin: Dict[str, object] = Depends(get_current_admin)):
        if admin.get("type") == "super_admin":
            return admin
        if perm_key in (admin.get("permissions") or []):
            return admin
        raise HTTPException(
            status_code=403, detail="ليس لديك صلاحية الوصول إلى هذا القسم."
        )
    return _dep

# مسار القوالب المتوافق مع بيئة Vercel
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# استدعاء المتغيرات البيئية
DATABASE_URL = os.getenv("DATABASE_URL", "")
CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME", "")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY", "")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET", "")

if CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY:
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET,
        secure=True,
    )


def get_db():
    if DATABASE_URL:
        db_url = DATABASE_URL
        if "sslmode=" not in db_url:
            db_url += "?sslmode=require" if "?" not in db_url else "&sslmode=require"
        conn = psycopg2.connect(db_url, connect_timeout=10)
        return conn, True
    else:
        import sqlite3

        conn = sqlite3.connect("/tmp/database.db")
        return conn, False


def init_db_tables():
    """دالة لإنشاء الجداول عند أول طلب فقط وليس عند إقلاع الكود لمنع انهيار السيرفر"""
    try:
        conn, is_pg = get_db()
        c = conn.cursor()

        id_type = (
            "SERIAL PRIMARY KEY" if is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
        )
        ts_default = "CURRENT_TIMESTAMP"

        # 1. إعدادات الأدمن
        c.execute(f"""CREATE TABLE IF NOT EXISTS admin_settings (
            id INTEGER PRIMARY KEY,
            sap_id TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )""")

        # ملاحظة: إنشاء أدمن افتراضي أول مرة فقط (لو الجدول فاضي تمامًا) — بدون قيم مكتوبة في الكود
        c.execute("SELECT COUNT(*) FROM admin_settings WHERE id = 1")
        if c.fetchone()[0] == 0:
            import secrets
            temp_password = secrets.token_urlsafe(9)
            q_admin = (
                "INSERT INTO admin_settings (id, sap_id, name, email, password) VALUES (1, %s, %s, %s, %s)"
                if is_pg
                else "INSERT INTO admin_settings (id, sap_id, name, email, password) VALUES (1, ?, ?, ?, ?)"
            )
            c.execute(q_admin, ("ADMIN01", "مدير النظام", "admin@company.com", temp_password))
            print(f"[SETUP] تم إنشاء حساب أدمن مبدئي - الباسورد المؤقت: {temp_password}")

        # 2. جدول المستخدمين
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            sap_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'فني',
            department TEXT DEFAULT 'عام'
        )""")

        # 3. جدول الامتحانات
        c.execute(f"""CREATE TABLE IF NOT EXISTS exams (
            id {id_type},
            name TEXT UNIQUE NOT NULL,
            duration_minutes INTEGER DEFAULT 30,
            departments TEXT DEFAULT '["الكل"]',
            is_active INTEGER DEFAULT 1,
            valid_until TEXT
        )""")

        # 4. جدول الأسئلة
        c.execute(f"""CREATE TABLE IF NOT EXISTS questions (
            id {id_type},
            exam_id INTEGER,
            branch TEXT NOT NULL,
            question TEXT NOT NULL,
            image_url TEXT,
            options TEXT NOT NULL,
            correct_option TEXT NOT NULL,
            FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE
        )""")

        # 5. جدول معرض الصور
        c.execute(f"""CREATE TABLE IF NOT EXISTS media_gallery (
            id {id_type},
            filename TEXT NOT NULL,
            file_url TEXT NOT NULL,
            public_id TEXT,
            uploaded_at TIMESTAMP DEFAULT {ts_default}
        )""")
        # ترحيل: إضافة عمود public_id لو الجدول كان موجود من قبل بدونه
        try:
            if is_pg:
                c.execute("ALTER TABLE media_gallery ADD COLUMN IF NOT EXISTS public_id TEXT")
            else:
                c.execute("PRAGMA table_info(media_gallery)")
                cols = [r[1] for r in c.fetchall()]
                if "public_id" not in cols:
                    c.execute("ALTER TABLE media_gallery ADD COLUMN public_id TEXT")
        except Exception:
            pass

        # 6. طلبات استعادة كلمة المرور
        c.execute(f"""CREATE TABLE IF NOT EXISTS reset_requests (
            id {id_type},
            sap_id TEXT NOT NULL,
            user_name TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT {ts_default}
        )""")

        # 7. جدول النتائج
        c.execute(f"""CREATE TABLE IF NOT EXISTS submissions (
            id {id_type},
            exam_id INTEGER,
            sap_id TEXT NOT NULL,
            user_name TEXT NOT NULL,
            total_score REAL,
            total_questions INTEGER,
            total_pct REAL,
            overall_level TEXT,
            branch_details TEXT,
            submitted_at TIMESTAMP DEFAULT {ts_default},
            FOREIGN KEY (exam_id) REFERENCES exams (id) ON DELETE CASCADE
        )""")

        # 8. جدول أذونات الإعادة
        c.execute(f"""CREATE TABLE IF NOT EXISTS retake_permissions (
            id {id_type},
            exam_id INTEGER,
            sap_id TEXT,
            allowed INTEGER DEFAULT 0,
            UNIQUE(exam_id, sap_id)
        )""")

        # ترحيل: إضافة عمود hidden لجدول النتائج (تعليق ظهور نتيجة فرد معين في لوحة الشرف)
        try:
            if is_pg:
                c.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS hidden INTEGER DEFAULT 0")
            else:
                c.execute("PRAGMA table_info(submissions)")
                cols = [r[1] for r in c.fetchall()]
                if "hidden" not in cols:
                    c.execute("ALTER TABLE submissions ADD COLUMN hidden INTEGER DEFAULT 0")
        except Exception:
            pass

        # ترحيل: إضافة عمود hide_leaderboard لجدول الامتحانات (تعليق ظهور نتائج الامتحان بالكامل في لوحة الشرف)
        try:
            if is_pg:
                c.execute("ALTER TABLE exams ADD COLUMN IF NOT EXISTS hide_leaderboard INTEGER DEFAULT 0")
            else:
                c.execute("PRAGMA table_info(exams)")
                cols = [r[1] for r in c.fetchall()]
                if "hide_leaderboard" not in cols:
                    c.execute("ALTER TABLE exams ADD COLUMN hide_leaderboard INTEGER DEFAULT 0")
        except Exception:
            pass

        # ترحيل: إضافة عمود teams لجدول الامتحانات (تخصيص الامتحان لفرق معينة)
        try:
            if is_pg:
                c.execute("ALTER TABLE exams ADD COLUMN IF NOT EXISTS teams TEXT DEFAULT '[\"الكل\"]'")
            else:
                c.execute("PRAGMA table_info(exams)")
                cols = [r[1] for r in c.fetchall()]
                if "teams" not in cols:
                    c.execute("ALTER TABLE exams ADD COLUMN teams TEXT DEFAULT '[\"الكل\"]'")
        except Exception:
            pass

        # ترحيل: إضافة عمود answers_detail لجدول النتائج (تفاصيل إجابة كل سؤال لاستخراج الإكسل)
        try:
            if is_pg:
                c.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS answers_detail TEXT")
            else:
                c.execute("PRAGMA table_info(submissions)")
                cols = [r[1] for r in c.fetchall()]
                if "answers_detail" not in cols:
                    c.execute("ALTER TABLE submissions ADD COLUMN answers_detail TEXT")
        except Exception:
            pass

        # 9. جدول حسابات المديرين (أدمن عادي بصلاحيات محددة - يدخل نفس بوابة الإدارة)
        c.execute(f"""CREATE TABLE IF NOT EXISTS admins (
            id {id_type},
            sap_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            permissions TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT {ts_default}
        )""")

        # 10. جدول الفرق
        c.execute(f"""CREATE TABLE IF NOT EXISTS teams (
            id {id_type},
            name TEXT UNIQUE NOT NULL
        )""")

        # 11. جدول ربط المستخدمين بالفرق (فرد يمكن أن يكون في فريقين كحد أقصى)
        c.execute(f"""CREATE TABLE IF NOT EXISTS user_teams (
            id {id_type},
            sap_id TEXT NOT NULL,
            team_id INTEGER NOT NULL,
            UNIQUE(sap_id, team_id)
        )""")

        # 12. جدول جلسات دخول الامتحان (لمنع دخول الامتحان مرتين أو تركه دون تسليم)
        c.execute(f"""CREATE TABLE IF NOT EXISTS exam_sessions (
            id {id_type},
            exam_id INTEGER NOT NULL,
            sap_id TEXT NOT NULL,
            status TEXT DEFAULT 'in_progress',
            started_at TIMESTAMP DEFAULT {ts_default},
            submitted_at TIMESTAMP,
            UNIQUE(exam_id, sap_id)
        )""")

        # 13. جدول متطلبات مصفوفة المهارات (المهارات المطلوبة لكل مسمى وظيفي)
        c.execute(f"""CREATE TABLE IF NOT EXISTS skill_requirements (
            id {id_type},
            role TEXT NOT NULL,
            skill_group TEXT DEFAULT 'عام',
            skill_name TEXT NOT NULL,
            description TEXT,
            linked_exam_id INTEGER,
            required_level TEXT DEFAULT 'المستوى 2 (متوسط)',
            created_at TIMESTAMP DEFAULT {ts_default}
        )""")

        # ترحيل: إضافة عمود مجموعة المهارة لجدول مصفوفة المهارات (لتجميع المهارات تحت عنوان واحد)
        try:
            if is_pg:
                c.execute("ALTER TABLE skill_requirements ADD COLUMN IF NOT EXISTS skill_group TEXT DEFAULT 'عام'")
            else:
                c.execute("PRAGMA table_info(skill_requirements)")
                cols = [r[1] for r in c.fetchall()]
                if "skill_group" not in cols:
                    c.execute("ALTER TABLE skill_requirements ADD COLUMN skill_group TEXT DEFAULT 'عام'")
        except Exception:
            pass

        # ملاحظة: تم حذف الإدراج التلقائي لمستخدم تجريبي هنا نهائيًا لمنع رجوعه بعد الحذف

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Lazy Database Init Exception: {e}")


def get_level(percentage: float) -> str:
    if percentage < 60:
        return "المستوى 1 (مبتدئ)"
    elif percentage < 75:
        return "المستوى 2 (متوسط)"
    elif percentage < 85:
        return "المستوى 3 (متقدم)"
    else:
        return "المستوى 4 (خبير)"


LEVEL_ORDER = [
    "المستوى 1 (مبتدئ)",
    "المستوى 2 (متوسط)",
    "المستوى 3 (متقدم)",
    "المستوى 4 (خبير)",
]


def parse_correct_answers(raw: str) -> List[str]:
    """يحوّل قيمة الإجابة الصحيحة المخزّنة إلى قائمة نصوص، مع دعم التوافق الرجعي
    للأسئلة القديمة المخزّنة كنص واحد (قبل دعم تعدد الإجابات الصحيحة)."""
    if not raw:
        return []
    try:
        val = json.loads(raw)
        if isinstance(val, list):
            return [str(x).strip() for x in val if str(x).strip()]
    except Exception:
        pass
    return [str(raw).strip()] if str(raw).strip() else []


def parse_correct_answers_from_excel_cell(raw) -> List[str]:
    """يدعم كتابة أكثر من إجابة صحيحة في نفس الخلية في ملف الإكسل، مفصولة بفاصلة
    عادية أو فاصلة عربية أو '|'، مثال: 'اختيار أ، اختيار ج' """
    if raw is None:
        return []
    text = str(raw).strip()
    if not text or text.lower() == "nan":
        return []
    parts = re.split(r"[،,|]", text)
    return [p.strip() for p in parts if p.strip()]


@app.get("/api/health")
async def health_check():
    try:
        conn, is_pg = get_db()
        conn.close()
        return {"status": "ok", "db_connected": True, "type": "Supabase PostgreSQL" if is_pg else "SQLite"}
    except Exception as e:
        return {"status": "error", "db_connected": False, "message": str(e)}


@app.get("/", response_class=HTMLResponse)
async def serve_home(request: Request):
    try:
        init_db_tables()
    except Exception:
        pass
    return templates.TemplateResponse(request, "index.html", {})


# --- المصادقة والأدمن ---
@app.post("/api/auth/admin-login")
async def admin_login(
    sap_id: str = Form(...), email: str = Form(...), password: str = Form(...)
):
    sap_id_clean, email_clean, pass_clean = sap_id.strip(), email.strip().lower(), password.strip()
    conn, is_pg = get_db()
    c = conn.cursor()

    # 1) تجربة الدخول كأدمن مركزي (صلاحيات كاملة دائمًا)
    q_super = (
        "SELECT sap_id, name, email, password FROM admin_settings WHERE id = 1 AND sap_id = %s AND LOWER(email) = %s"
        if is_pg
        else "SELECT sap_id, name, email, password FROM admin_settings WHERE id = 1 AND sap_id = ? AND LOWER(email) = ?"
    )
    c.execute(q_super, (sap_id_clean, email_clean))
    super_admin = c.fetchone()
    if super_admin and verify_password(pass_clean, super_admin[3]):
        if not is_hashed_password(super_admin[3]):
            q_upg = (
                "UPDATE admin_settings SET password = %s WHERE id = 1"
                if is_pg
                else "UPDATE admin_settings SET password = ? WHERE id = 1"
            )
            c.execute(q_upg, (hash_password(pass_clean),))
            conn.commit()
        conn.close()
        token = create_token({"type": "super_admin", "sap_id": super_admin[0], "permissions": ADMIN_PERMISSION_KEYS})
        return {
            "status": "success",
            "role": "super_admin",
            "name": super_admin[1],
            "email": super_admin[2],
            "sap_id": super_admin[0],
            "permissions": ADMIN_PERMISSION_KEYS,
            "token": token,
        }

    # 2) تجربة الدخول كأدمن عادي (مدير) بصلاحيات محددة
    q_sub = (
        "SELECT sap_id, name, email, permissions, password FROM admins WHERE sap_id = %s AND LOWER(email) = %s"
        if is_pg
        else "SELECT sap_id, name, email, permissions, password FROM admins WHERE sap_id = ? AND LOWER(email) = ?"
    )
    c.execute(q_sub, (sap_id_clean, email_clean))
    sub_admin = c.fetchone()
    if sub_admin and verify_password(pass_clean, sub_admin[4]):
        if not is_hashed_password(sub_admin[4]):
            q_upg = (
                "UPDATE admins SET password = %s WHERE sap_id = %s"
                if is_pg
                else "UPDATE admins SET password = ? WHERE sap_id = ?"
            )
            c.execute(q_upg, (hash_password(pass_clean), sub_admin[0]))
            conn.commit()
        conn.close()
        try:
            perms = json.loads(sub_admin[3]) if sub_admin[3] else []
        except Exception:
            perms = []
        token = create_token({"type": "admin", "sap_id": sub_admin[0], "permissions": perms})
        return {
            "status": "success",
            "role": "admin",
            "name": sub_admin[1],
            "email": sub_admin[2],
            "sap_id": sub_admin[0],
            "permissions": perms,
            "token": token,
        }

    conn.close()
    raise HTTPException(
        status_code=401, detail="بيانات دخول الإدارة غير صحيحة."
    )


# --- إدارة حسابات المديرين (أدمن عادي بصلاحيات محددة) ---
@app.get("/api/admin/admins")
async def list_sub_admins(_admin: Dict[str, object] = Depends(get_current_super_admin)):
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("SELECT sap_id, name, email, permissions FROM admins ORDER BY sap_id ASC")
    rows = c.fetchall()
    conn.close()
    result = []
    for r in rows:
        try:
            perms = json.loads(r[3]) if r[3] else []
        except Exception:
            perms = []
        result.append({"sap_id": r[0], "name": r[1], "email": r[2], "permissions": perms})
    return result


@app.post("/api/admin/admins/add")
async def add_sub_admin(
    sap_id: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    permissions: str = Form("[]"),
    _admin: Dict[str, object] = Depends(get_current_super_admin),
):
    try:
        perms_list = json.loads(permissions) if permissions else []
        perms_list = [p for p in perms_list if p in ADMIN_PERMISSION_KEYS]
    except Exception:
        perms_list = []

    conn, is_pg = get_db()
    c = conn.cursor()
    if is_pg:
        q = """INSERT INTO admins (sap_id, name, email, password, permissions) VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT(sap_id) DO UPDATE SET name=EXCLUDED.name, email=EXCLUDED.email, password=EXCLUDED.password, permissions=EXCLUDED.permissions"""
    else:
        q = """INSERT INTO admins (sap_id, name, email, password, permissions) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(sap_id) DO UPDATE SET name=excluded.name, email=excluded.email, password=excluded.password, permissions=excluded.permissions"""
    c.execute(
        q,
        (
            sap_id.strip(),
            name.strip(),
            email.strip().lower(),
            hash_password(password.strip()),
            json.dumps(perms_list, ensure_ascii=False),
        ),
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم حفظ حساب المدير {name} بنجاح."}


@app.delete("/api/admin/admins/{sap_id}")
async def delete_sub_admin(
    sap_id: str, _admin: Dict[str, object] = Depends(get_current_super_admin)
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "DELETE FROM admins WHERE sap_id = %s"
        if is_pg
        else "DELETE FROM admins WHERE sap_id = ?"
    )
    c.execute(q, (sap_id.strip(),))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف حساب المدير."}


@app.post("/api/admin/self/change-password")
async def sub_admin_change_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    admin: Dict[str, object] = Depends(get_current_admin),
):
    """يسمح لحساب مدير عادي (غير الأدمن المركزي) بتغيير كلمة مروره الخاصة بنفسه فقط."""
    if admin.get("type") != "admin":
        raise HTTPException(
            status_code=400,
            detail="هذا الإجراء متاح لحسابات المديرين العاديين فقط. الأدمن المركزي يغيّر كلمة مروره من تبويب الإعدادات.",
        )
    sap_id = str(admin["sap_id"])
    conn, is_pg = get_db()
    c = conn.cursor()
    q_sel = (
        "SELECT password FROM admins WHERE sap_id = %s"
        if is_pg
        else "SELECT password FROM admins WHERE sap_id = ?"
    )
    c.execute(q_sel, (sap_id,))
    row = c.fetchone()
    if not row or not verify_password(old_password.strip(), row[0]):
        conn.close()
        raise HTTPException(status_code=400, detail="كلمة المرور الحالية غير صحيحة.")

    q_upd = (
        "UPDATE admins SET password = %s WHERE sap_id = %s"
        if is_pg
        else "UPDATE admins SET password = ? WHERE sap_id = ?"
    )
    c.execute(q_upd, (hash_password(new_password.strip()), sap_id))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تغيير كلمة المرور بنجاح."}


@app.get("/api/admin/profile")
async def get_admin_profile(_admin: Dict[str, object] = Depends(get_current_super_admin)):
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("SELECT sap_id, name, email FROM admin_settings WHERE id = 1")
    row = c.fetchone()
    conn.close()
    return {"sap_id": row[0], "name": row[1], "email": row[2]}


@app.post("/api/admin/profile/update")
async def update_admin_profile(
    sap_id: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    password: Optional[str] = Form(None),
    _admin: Dict[str, object] = Depends(get_current_super_admin),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    if password and password.strip():
        q = (
            "UPDATE admin_settings SET sap_id = %s, name = %s, email = %s, password = %s WHERE id = 1"
            if is_pg
            else "UPDATE admin_settings SET sap_id = ?, name = ?, email = ?, password = ? WHERE id = 1"
        )
        c.execute(
            q,
            (
                sap_id.strip(),
                name.strip(),
                email.strip().lower(),
                hash_password(password.strip()),
            ),
        )
    else:
        q = (
            "UPDATE admin_settings SET sap_id = %s, name = %s, email = %s WHERE id = 1"
            if is_pg
            else "UPDATE admin_settings SET sap_id = ?, name = ?, email = ? WHERE id = 1"
        )
        c.execute(q, (sap_id.strip(), name.strip(), email.strip().lower()))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث بيانات الأدمن بنجاح."}


@app.post("/api/auth/user-login")
async def user_login(sap_id: str = Form(...), password: str = Form(...)):
    sap_id_clean, pass_clean = sap_id.strip(), password.strip()
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "SELECT sap_id, name, role, department, password FROM users WHERE sap_id = %s"
        if is_pg
        else "SELECT sap_id, name, role, department, password FROM users WHERE sap_id = ?"
    )
    c.execute(q, (sap_id_clean,))
    user = c.fetchone()
    if not user or not verify_password(pass_clean, user[4]):
        conn.close()
        raise HTTPException(status_code=401, detail="بيانات الدخول غير صحيحة.")

    if not is_hashed_password(user[4]):
        q_upg = (
            "UPDATE users SET password = %s WHERE sap_id = %s"
            if is_pg
            else "UPDATE users SET password = ? WHERE sap_id = ?"
        )
        c.execute(q_upg, (hash_password(pass_clean), user[0]))
        conn.commit()

    q_teams = (
        """SELECT t.name FROM user_teams ut JOIN teams t ON ut.team_id = t.id WHERE ut.sap_id = %s"""
        if is_pg
        else """SELECT t.name FROM user_teams ut JOIN teams t ON ut.team_id = t.id WHERE ut.sap_id = ?"""
    )
    c.execute(q_teams, (user[0],))
    teams = [r[0] for r in c.fetchall()]
    conn.close()
    token = create_token({"type": "user", "sap_id": user[0]})
    return {
        "status": "success",
        "sap_id": user[0],
        "name": user[1],
        "role": user[2],
        "department": user[3],
        "teams": teams,
        "token": token,
    }


@app.post("/api/auth/request-reset")
async def request_password_reset(sap_id: str = Form(...)):
    conn, is_pg = get_db()
    c = conn.cursor()
    q_sel = (
        "SELECT name FROM users WHERE sap_id = %s"
        if is_pg
        else "SELECT name FROM users WHERE sap_id = ?"
    )
    c.execute(q_sel, (sap_id.strip(),))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(
            status_code=404, detail="رقم الساب غير مسجل في النظام."
        )

    q_ins = (
        "INSERT INTO reset_requests (sap_id, user_name, status) VALUES (%s, %s, 'pending')"
        if is_pg
        else "INSERT INTO reset_requests (sap_id, user_name, status) VALUES (?, ?, 'pending')"
    )
    c.execute(q_ins, (sap_id.strip(), user[0]))
    conn.commit()
    conn.close()
    return {
        "status": "success",
        "message": "تم إرسال طلب استعادة كلمة المرور إلى الإدارة بنجاح.",
    }


@app.post("/api/auth/change-password")
async def change_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    user: Dict[str, object] = Depends(get_current_user),
):
    sap_id = str(user["sap_id"])
    conn, is_pg = get_db()
    c = conn.cursor()
    q_sel = (
        "SELECT password FROM users WHERE sap_id = %s"
        if is_pg
        else "SELECT password FROM users WHERE sap_id = ?"
    )
    c.execute(q_sel, (sap_id,))
    row = c.fetchone()
    if not row or not verify_password(old_password.strip(), row[0]):
        conn.close()
        raise HTTPException(
            status_code=400, detail="كلمة المرور الحالية غير صحيحة."
        )

    q_upd = (
        "UPDATE users SET password = %s WHERE sap_id = %s"
        if is_pg
        else "UPDATE users SET password = ? WHERE sap_id = ?"
    )
    c.execute(q_upd, (hash_password(new_password.strip()), sap_id))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تغيير كلمة المرور بنجاح."}


# --- إدارة معرض الصور ---
@app.post("/api/admin/upload-multiple-images")
async def upload_multiple_images(
    files: List[UploadFile] = File(...),
    _admin: Dict[str, object] = Depends(require_permission("gallery")),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    uploaded_urls = []

    for file in files:
        contents = await file.read()
        public_id = None
        if CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY:
            upload_res = cloudinary.uploader.upload(
                contents, folder="exam_system"
            )
            file_url = upload_res.get("secure_url")
            public_id = upload_res.get("public_id")
        else:
            file_url = f"https://via.placeholder.com/300?text={file.filename}"

        q_ins = (
            "INSERT INTO media_gallery (filename, file_url, public_id) VALUES (%s, %s, %s)"
            if is_pg
            else "INSERT INTO media_gallery (filename, file_url, public_id) VALUES (?, ?, ?)"
        )
        c.execute(q_ins, (file.filename, file_url, public_id))
        uploaded_urls.append({"name": file.filename, "url": file_url})

    conn.commit()
    conn.close()
    return {"status": "success", "images": uploaded_urls}


@app.delete("/api/admin/gallery/{image_id}")
async def delete_gallery_image(
    image_id: int, _admin: Dict[str, object] = Depends(require_permission("gallery"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q_sel = (
        "SELECT public_id FROM media_gallery WHERE id = %s"
        if is_pg
        else "SELECT public_id FROM media_gallery WHERE id = ?"
    )
    c.execute(q_sel, (image_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="الصورة غير موجودة.")

    public_id = row[0]
    if public_id and CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY:
        try:
            cloudinary.uploader.destroy(public_id)
        except Exception:
            pass  # الصورة ممكن تكون اتمسحت من Cloudinary من قبل، نكمل نمسح السطر من قاعدة البيانات على أي حال

    q_del = (
        "DELETE FROM media_gallery WHERE id = %s"
        if is_pg
        else "DELETE FROM media_gallery WHERE id = ?"
    )
    c.execute(q_del, (image_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف الصورة بنجاح."}


@app.get("/api/admin/gallery")
async def get_gallery(_admin: Dict[str, object] = Depends(require_permission("gallery"))):
    conn, _ = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT id, filename, file_url, uploaded_at FROM media_gallery ORDER BY id DESC"
    )
    rows = c.fetchall()
    conn.close()
    return [
        {"id": r[0], "filename": r[1], "url": r[2], "date": str(r[3])}
        for r in rows
    ]


# --- إدارة المستخدمين ---
@app.get("/api/admin/departments")
async def get_registered_departments(
    _admin: Dict[str, object] = Depends(get_current_admin)
):
    """يرجّع قائمة الإدارات الفعلية المسجّلة عند المستخدمين (بدون تكرار)."""
    conn, _ = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT DISTINCT department FROM users WHERE department IS NOT NULL AND department != '' ORDER BY department ASC"
    )
    departments = [r[0] for r in c.fetchall()]
    conn.close()
    return {"departments": departments}


@app.get("/api/admin/users")
async def get_all_users(_admin: Dict[str, object] = Depends(require_permission("users"))):
    conn, _ = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT sap_id, name, role, department, password FROM users ORDER BY sap_id ASC"
    )
    users_rows = c.fetchall()

    # تجميع فرق كل مستخدم في استعلام واحد لتفادي التكرار
    c.execute("""SELECT ut.sap_id, t.id, t.name FROM user_teams ut
                 JOIN teams t ON ut.team_id = t.id""")
    teams_by_sap: Dict[str, List[Dict[str, object]]] = {}
    for sap_id, team_id, team_name in c.fetchall():
        teams_by_sap.setdefault(sap_id, []).append({"id": team_id, "name": team_name})

    conn.close()
    users = [
        {
            "sap_id": r[0],
            "name": r[1],
            "role": r[2],
            "department": r[3],
            "password": None if is_hashed_password(r[4]) else r[4],
            "password_hidden": is_hashed_password(r[4]),
            "teams": teams_by_sap.get(r[0], []),
        }
        for r in users_rows
    ]
    return users


# --- إدارة الفرق ---
@app.get("/api/admin/teams")
async def list_teams(_admin: Dict[str, object] = Depends(require_permission("teams"))):
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name FROM teams ORDER BY name ASC")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1]} for r in rows]


@app.post("/api/admin/teams/add")
async def add_team(
    name: str = Form(...), _admin: Dict[str, object] = Depends(require_permission("teams"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "INSERT INTO teams (name) VALUES (%s) ON CONFLICT(name) DO NOTHING"
        if is_pg
        else "INSERT INTO teams (name) VALUES (?) ON CONFLICT(name) DO NOTHING"
    )
    c.execute(q, (name.strip(),))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم إضافة/تأكيد فريق \"{name.strip()}\"."}


@app.delete("/api/admin/teams/{team_id}")
async def delete_team(
    team_id: int, _admin: Dict[str, object] = Depends(require_permission("teams"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q_ut = (
        "DELETE FROM user_teams WHERE team_id = %s"
        if is_pg
        else "DELETE FROM user_teams WHERE team_id = ?"
    )
    c.execute(q_ut, (team_id,))
    q_t = (
        "DELETE FROM teams WHERE id = %s" if is_pg else "DELETE FROM teams WHERE id = ?"
    )
    c.execute(q_t, (team_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف الفريق."}


@app.get("/api/admin/users/{sap_id}/teams")
async def get_user_teams(
    sap_id: str, _admin: Dict[str, object] = Depends(require_permission("users"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """SELECT t.id, t.name FROM user_teams ut JOIN teams t ON ut.team_id = t.id WHERE ut.sap_id = %s"""
        if is_pg
        else """SELECT t.id, t.name FROM user_teams ut JOIN teams t ON ut.team_id = t.id WHERE ut.sap_id = ?"""
    )
    c.execute(q, (sap_id.strip(),))
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1]} for r in rows]


@app.post("/api/admin/users/{sap_id}/set-teams")
async def set_user_teams(
    sap_id: str,
    team_ids: str = Form("[]"),
    _admin: Dict[str, object] = Depends(require_permission("users")),
):
    """يحدد فرق المستخدم (بحد أقصى فريقين)، ويستبدل أي تعيين سابق بالكامل."""
    try:
        ids = json.loads(team_ids) if team_ids else []
        ids = [int(i) for i in ids]
    except Exception:
        raise HTTPException(status_code=400, detail="صيغة الفرق غير صحيحة.")

    if len(ids) > 2:
        raise HTTPException(
            status_code=400, detail="لا يمكن أن يكون الفرد مشتركاً في أكثر من فريقين."
        )

    conn, is_pg = get_db()
    c = conn.cursor()
    q_del = (
        "DELETE FROM user_teams WHERE sap_id = %s"
        if is_pg
        else "DELETE FROM user_teams WHERE sap_id = ?"
    )
    c.execute(q_del, (sap_id.strip(),))

    q_ins = (
        "INSERT INTO user_teams (sap_id, team_id) VALUES (%s, %s)"
        if is_pg
        else "INSERT INTO user_teams (sap_id, team_id) VALUES (?, ?)"
    )
    for tid in ids:
        c.execute(q_ins, (sap_id.strip(), tid))

    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث فرق المستخدم بنجاح."}


@app.post("/api/admin/add-user")
async def add_single_user(
    sap_id: str = Form(...),
    name: str = Form(...),
    password: str = Form(...),
    role: str = Form("فني"),
    department: str = Form("عام"),
    _admin: Dict[str, object] = Depends(require_permission("users")),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    if is_pg:
        q = """INSERT INTO users (sap_id, name, password, role, department) VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT(sap_id) DO UPDATE SET name=EXCLUDED.name, password=EXCLUDED.password, role=EXCLUDED.role, department=EXCLUDED.department"""
    else:
        q = """INSERT INTO users (sap_id, name, password, role, department) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(sap_id) DO UPDATE SET name=excluded.name, password=excluded.password, role=excluded.role, department=excluded.department"""
    c.execute(
        q,
        (
            sap_id.strip(),
            name.strip(),
            hash_password(password.strip()),
            role.strip(),
            department.strip(),
        ),
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم حفظ المستخدم {name} بنجاح."}


@app.delete("/api/admin/delete-user/{sap_id}")
async def delete_user(
    sap_id: str, _admin: Dict[str, object] = Depends(require_permission("users"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "DELETE FROM users WHERE sap_id = %s"
        if is_pg
        else "DELETE FROM users WHERE sap_id = ?"
    )
    c.execute(q, (sap_id.strip(),))
    conn.commit()
    conn.close()
    return {"status": "success"}


@app.post("/api/admin/upload-users-excel")
async def upload_users_excel(
    file: UploadFile = File(...),
    _admin: Dict[str, object] = Depends(require_permission("users")),
):
    try:
        contents = await file.read()
        df = pd.read_excel(io.BytesIO(contents))
        conn, is_pg = get_db()
        c = conn.cursor()
        count = 0
        for _, row in df.iterrows():
            name = str(row["الاسم"]).strip()
            sap_id = str(row["رقم الساب"]).strip()
            password = str(row["الباسورد"]).strip()
            role = (
                str(row["الدور"]).strip()
                if pd.notna(row.get("الدور"))
                else "مشغل / فني"
            )
            dept = (
                str(row["الإدارة"]).strip()
                if pd.notna(row.get("الإدارة"))
                else "عام"
            )
            if sap_id and name:
                if is_pg:
                    q = """INSERT INTO users (sap_id, name, password, role, department) VALUES (%s, %s, %s, %s, %s)
                           ON CONFLICT(sap_id) DO UPDATE SET name=EXCLUDED.name, password=EXCLUDED.password, role=EXCLUDED.role, department=EXCLUDED.department"""
                else:
                    q = """INSERT INTO users (sap_id, name, password, role, department) VALUES (?, ?, ?, ?, ?)
                           ON CONFLICT(sap_id) DO UPDATE SET name=excluded.name, password=excluded.password, role=excluded.role, department=excluded.department"""
                c.execute(q, (sap_id, name, hash_password(password), role, dept))
                count += 1
        conn.commit()
        conn.close()
        return {
            "status": "success",
            "message": f"تم استيراد {count} مستخدم بنجاح.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/admin/download-users-template")
async def download_users_template(
    _admin: Dict[str, object] = Depends(require_permission("users"))
):
    sample_data = [
        {
            "الاسم": "محمد عادل",
            "رقم الساب": "1001",
            "الباسورد": "123456",
            "الدور": "مهندس صيانة",
            "الإدارة": "صيانة الاسطمبات",
        },
        {
            "الاسم": "أحمد محمود",
            "رقم الساب": "1002",
            "الباسورد": "654321",
            "الدور": "مشغل ماكينة",
            "الإدارة": "الإنتاج",
        },
    ]
    df = pd.DataFrame(sample_data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="المستخدمين")
    output.seek(0)
    return StreamingResponse(
        output,
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
        headers={
            "Content-Disposition": "attachment; filename=Users_Template.xlsx"
        },
    )


@app.get("/api/admin/reset-requests")
async def get_reset_requests(
    _admin: Dict[str, object] = Depends(require_permission("resets"))
):
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("""SELECT r.id, r.sap_id, r.user_name, r.created_at, u.password, u.department
                 FROM reset_requests r
                 LEFT JOIN users u ON r.sap_id = u.sap_id
                 WHERE r.status = 'pending'
                 ORDER BY r.created_at DESC""")
    rows = c.fetchall()
    conn.close()
    return [
        {
            "request_id": r[0],
            "sap_id": r[1],
            "name": r[2],
            "date": str(r[3]),
            "current_password": None if is_hashed_password(r[4]) else r[4],
            "department": r[5],
        }
        for r in rows
    ]


@app.post("/api/admin/reset-password-action")
async def reset_password_action(
    request_id: int = Form(...),
    sap_id: str = Form(...),
    new_password: Optional[str] = Form(None),
    _admin: Dict[str, object] = Depends(require_permission("resets")),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    if new_password and new_password.strip():
        q_upd = (
            "UPDATE users SET password = %s WHERE sap_id = %s"
            if is_pg
            else "UPDATE users SET password = ? WHERE sap_id = ?"
        )
        c.execute(q_upd, (hash_password(new_password.strip()), sap_id.strip()))
    q_req = (
        "UPDATE reset_requests SET status = 'resolved' WHERE id = %s"
        if is_pg
        else "UPDATE reset_requests SET status = 'resolved' WHERE id = ?"
    )
    c.execute(q_req, (request_id,))
    conn.commit()
    conn.close()
    return {
        "status": "success",
        "message": "تم تحديث كلمة المرور وإنهاء الطلب.",
    }


@app.post("/api/admin/users/{sap_id}/set-password")
async def admin_set_user_password(
    sap_id: str,
    new_password: str = Form(...),
    _admin: Dict[str, object] = Depends(require_permission("users")),
):
    """تعيين كلمة مرور جديدة لمستخدم من لوحة إدارة المشتركين مباشرة."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q_upd = (
        "UPDATE users SET password = %s WHERE sap_id = %s"
        if is_pg
        else "UPDATE users SET password = ? WHERE sap_id = ?"
    )
    c.execute(q_upd, (hash_password(new_password.strip()), sap_id.strip()))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تعيين كلمة المرور الجديدة بنجاح."}


# --- الامتحانات والأسئلة ---
@app.post("/api/admin/exams/{exam_id}/update-validity")
async def update_exam_validity(
    exam_id: int,
    is_active: int = Form(...),
    valid_until: Optional[str] = Form(None),
    hide_leaderboard: int = Form(0),
    _admin: Dict[str, object] = Depends(require_permission("manage")),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE exams SET is_active = %s, valid_until = %s, hide_leaderboard = %s WHERE id = %s"
        if is_pg
        else "UPDATE exams SET is_active = ?, valid_until = ?, hide_leaderboard = ? WHERE id = ?"
    )
    c.execute(q, (is_active, valid_until if valid_until else None, hide_leaderboard, exam_id))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث صلاحية الامتحان."}


@app.delete("/api/admin/exams/{exam_id}")
async def delete_exam(
    exam_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    """حذف امتحان بالكامل مع كل أسئلته ونتائجه وأذونات الإعادة الخاصة به."""
    conn, is_pg = get_db()
    c = conn.cursor()

    q_exam_sel = (
        "SELECT name FROM exams WHERE id = %s" if is_pg else "SELECT name FROM exams WHERE id = ?"
    )
    c.execute(q_exam_sel, (exam_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="الامتحان غير موجود.")
    exam_name = row[0]

    for table in ("questions", "submissions", "retake_permissions", "exam_sessions"):
        q_del = (
            f"DELETE FROM {table} WHERE exam_id = %s"
            if is_pg
            else f"DELETE FROM {table} WHERE exam_id = ?"
        )
        c.execute(q_del, (exam_id,))

    q_del_exam = (
        "DELETE FROM exams WHERE id = %s" if is_pg else "DELETE FROM exams WHERE id = ?"
    )
    c.execute(q_del_exam, (exam_id,))

    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم حذف امتحان \"{exam_name}\" وكل بياناته بنجاح."}


@app.post("/api/admin/exams/{exam_id}/allow-retake")
async def allow_retake(
    exam_id: int,
    sap_id: str = Form(...),
    _admin: Dict[str, object] = Depends(require_permission("manage")),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    if is_pg:
        q = (
            "INSERT INTO retake_permissions (exam_id, sap_id, allowed) VALUES (%s, %s, 1)"
            " ON CONFLICT(exam_id, sap_id) DO UPDATE SET allowed = 1"
        )
    else:
        q = (
            "INSERT INTO retake_permissions (exam_id, sap_id, allowed) VALUES (?, ?, 1)"
            " ON CONFLICT(exam_id, sap_id) DO UPDATE SET allowed = 1"
        )
    c.execute(q, (exam_id, sap_id.strip()))
    conn.commit()
    conn.close()
    return {
        "status": "success",
        "message": f"تم السماح للمتدرب {sap_id} بإعادة الامتحان.",
    }


@app.post("/api/admin/exams/{exam_id}/allow-retake-bulk")
async def allow_retake_bulk(
    exam_id: int,
    sap_ids: str = Form(...),
    _admin: Dict[str, object] = Depends(require_permission("manage")),
):
    """السماح بإعادة الامتحان لمجموعة من الأفراد دفعة واحدة."""
    try:
        ids = json.loads(sap_ids)
        if not isinstance(ids, list) or not ids:
            raise ValueError
    except Exception:
        raise HTTPException(status_code=400, detail="يجب اختيار فرد واحد على الأقل.")

    conn, is_pg = get_db()
    c = conn.cursor()
    if is_pg:
        q = (
            "INSERT INTO retake_permissions (exam_id, sap_id, allowed) VALUES (%s, %s, 1)"
            " ON CONFLICT(exam_id, sap_id) DO UPDATE SET allowed = 1"
        )
    else:
        q = (
            "INSERT INTO retake_permissions (exam_id, sap_id, allowed) VALUES (?, ?, 1)"
            " ON CONFLICT(exam_id, sap_id) DO UPDATE SET allowed = 1"
        )
    count = 0
    for sap_id in ids:
        sap_id_clean = str(sap_id).strip()
        if not sap_id_clean:
            continue
        c.execute(q, (exam_id, sap_id_clean))
        count += 1
    conn.commit()
    conn.close()
    return {
        "status": "success",
        "message": f"تم السماح لـ {count} فرد بإعادة الامتحان.",
    }


@app.post("/api/admin/upload-excel")
async def upload_excel(
    exam_name: str = Form(...),
    duration: int = Form(30),
    valid_until: Optional[str] = Form(None),
    departments: str = Form("[]"),
    teams: str = Form("[]"),
    file: UploadFile = File(...),
    _admin: Dict[str, object] = Depends(require_permission("create")),
):
    try:
        contents = await file.read()
        df = pd.read_excel(io.BytesIO(contents))
        dept_list = json.loads(departments) if departments else ["الكل"]
        if not dept_list:
            dept_list = ["الكل"]
        team_list = json.loads(teams) if teams else ["الكل"]
        if not team_list:
            team_list = ["الكل"]

        conn, is_pg = get_db()
        c = conn.cursor()
        if is_pg:
            q_exam = """INSERT INTO exams (name, duration_minutes, departments, teams, is_active, valid_until) 
                        VALUES (%s, %s, %s, %s, 1, %s)
                        ON CONFLICT(name) DO UPDATE SET 
                           duration_minutes=EXCLUDED.duration_minutes, 
                           departments=EXCLUDED.departments,
                           teams=EXCLUDED.teams,
                           is_active=1,
                           valid_until=EXCLUDED.valid_until RETURNING id"""
            c.execute(
                q_exam,
                (
                    exam_name,
                    duration,
                    json.dumps(dept_list, ensure_ascii=False),
                    json.dumps(team_list, ensure_ascii=False),
                    valid_until if valid_until else None,
                ),
            )
            exam_id = c.fetchone()[0]
        else:
            q_exam = """INSERT INTO exams (name, duration_minutes, departments, teams, is_active, valid_until) 
                        VALUES (?, ?, ?, ?, 1, ?)
                        ON CONFLICT(name) DO UPDATE SET 
                           duration_minutes=excluded.duration_minutes, 
                           departments=excluded.departments,
                           teams=excluded.teams,
                           is_active=1,
                           valid_until=excluded.valid_until"""
            c.execute(
                q_exam,
                (
                    exam_name,
                    duration,
                    json.dumps(dept_list, ensure_ascii=False),
                    json.dumps(team_list, ensure_ascii=False),
                    valid_until if valid_until else None,
                ),
            )
            c.execute("SELECT id FROM exams WHERE name = ?", (exam_name,))
            exam_id = c.fetchone()[0]

        del_q = (
            "DELETE FROM questions WHERE exam_id = %s"
            if is_pg
            else "DELETE FROM questions WHERE exam_id = ?"
        )
        c.execute(del_q, (exam_id,))

        for _, row in df.iterrows():
            branch = str(row["الفرع"]).strip()
            question = str(row["السؤال"]).strip()
            image_url = (
                str(row["رابط الصورة"]).strip()
                if "رابط الصورة" in df.columns and pd.notna(row["رابط الصورة"])
                else ""
            )
            options = [
                str(row["الاختيار 1"]).strip(),
                str(row["الاختيار 2"]).strip(),
                str(row["الاختيار 3"]).strip(),
                str(row["الاختيار 4"]).strip(),
            ]
            correct_options = parse_correct_answers_from_excel_cell(
                row["الإجابة الصحيحة"]
            )
            correct_option = json.dumps(correct_options, ensure_ascii=False)

            ins_q = (
                "INSERT INTO questions (exam_id, branch, question, image_url, options, correct_option) VALUES (%s, %s, %s, %s, %s, %s)"
                if is_pg
                else "INSERT INTO questions (exam_id, branch, question, image_url, options, correct_option) VALUES (?, ?, ?, ?, ?, ?)"
            )
            c.execute(
                ins_q,
                (
                    exam_id,
                    branch,
                    question,
                    image_url,
                    json.dumps(options, ensure_ascii=False),
                    correct_option,
                ),
            )

        conn.commit()
        conn.close()
        return {
            "status": "success",
            "message": f"تم حفظ الامتحان '{exam_name}' بـ {len(df)} سؤال ومدة {duration} دقيقة.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/exams")
async def list_exams(
    department: Optional[str] = None,
    sap_id: Optional[str] = None,
    user: Dict[str, object] = Depends(get_current_user),
):
    # نتجاهل أي sap_id قادم من الاستعلام ونستخدم هوية المستخدم من التوكن فقط لمنع انتحال شخصية فرد آخر
    sap_id = str(user["sap_id"])
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT id, name, duration_minutes, departments, teams, is_active, valid_until FROM exams"
    )
    rows = c.fetchall()

    # فرق المستخدم الحالي (لتحديد الامتحانات المتاحة له حسب الفريق)
    user_team_names = set()
    if sap_id:
        q_ut = (
            """SELECT t.name FROM user_teams ut JOIN teams t ON ut.team_id = t.id WHERE ut.sap_id = %s"""
            if is_pg
            else """SELECT t.name FROM user_teams ut JOIN teams t ON ut.team_id = t.id WHERE ut.sap_id = ?"""
        )
        c.execute(q_ut, (sap_id.strip(),))
        user_team_names = {r[0] for r in c.fetchall()}

    exams = []
    now = datetime.now().strftime("%Y-%m-%dT%H:%M")

    for r in rows:
        exam_id, name, duration, depts_json, teams_json, is_active, valid_until = r
        depts = json.loads(depts_json) if depts_json else ["الكل"]
        teams_target = json.loads(teams_json) if teams_json else ["الكل"]
        is_expired = True if valid_until and valid_until < now else False
        already_attempted, retake_allowed, in_progress = False, False, False

        if sap_id:
            # أي محاولة دخول سابقة (سواء تم التسليم أو تُركت بدون تسليم) تُحسب كمحاولة مستهلكة
            q_sess = (
                "SELECT status FROM exam_sessions WHERE exam_id = %s AND sap_id = %s"
                if is_pg
                else "SELECT status FROM exam_sessions WHERE exam_id = ? AND sap_id = ?"
            )
            c.execute(q_sess, (exam_id, sap_id.strip()))
            sess = c.fetchone()
            if sess:
                already_attempted = True
                in_progress = sess[0] == "in_progress"

            # حماية إضافية: أي نتيجة مسجلة تُعتبر محاولة مستهلكة حتى لو لم تكن هناك جلسة (بيانات قديمة)
            if not already_attempted:
                q_cnt = (
                    "SELECT COUNT(id) FROM submissions WHERE exam_id = %s AND sap_id = %s"
                    if is_pg
                    else "SELECT COUNT(id) FROM submissions WHERE exam_id = ? AND sap_id = ?"
                )
                c.execute(q_cnt, (exam_id, sap_id.strip()))
                if c.fetchone()[0] > 0:
                    already_attempted = True

            q_perm = (
                "SELECT allowed FROM retake_permissions WHERE exam_id = %s AND sap_id = %s"
                if is_pg
                else "SELECT allowed FROM retake_permissions WHERE exam_id = ? AND sap_id = ?"
            )
            c.execute(q_perm, (exam_id, sap_id.strip()))
            perm = c.fetchone()
            if perm and perm[0] == 1:
                retake_allowed = True

        dept_ok = (
            department is None
            or "الكل" in depts
            or department in depts
            or department == "عام"
        )
        team_ok = (
            not sap_id
            or "الكل" in teams_target
            or bool(user_team_names.intersection(teams_target))
        )

        if dept_ok and team_ok:
            exams.append({
                "id": exam_id,
                "name": name,
                "duration": duration,
                "departments": depts,
                "teams": teams_target,
                "is_active": bool(is_active),
                "valid_until": valid_until,
                "is_expired": is_expired,
                "already_submitted": already_attempted,
                "in_progress": in_progress,
                "retake_allowed": retake_allowed,
                "can_enter": (
                    bool(is_active)
                    and not is_expired
                    and (not already_attempted or retake_allowed)
                ),
            })
    conn.close()
    return exams


@app.get("/api/admin/exams")
async def list_admin_exams(_admin: Dict[str, object] = Depends(require_permission("manage"))):
    # قائمة كل الامتحانات لاستخدام لوحة تحكم الإدارة (مثل قائمة المعاينة)،
    # بدون منطق تصفية الطالب الموجود في /api/exams والذي يتطلب توكن نوعه "user" فقط.
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT id, name, duration_minutes, departments, teams, is_active, valid_until FROM exams ORDER BY id DESC"
    )
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "name": r[1],
            "duration": r[2],
            "departments": json.loads(r[3]) if r[3] else ["الكل"],
            "teams": json.loads(r[4]) if r[4] else ["الكل"],
            "is_active": bool(r[5]),
            "valid_until": r[6],
        }
        for r in rows
    ]


@app.get("/api/admin/exams/{exam_id}/preview")
async def preview_exam(
    exam_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q_exam = (
        "SELECT name, duration_minutes, departments, is_active, valid_until, hide_leaderboard FROM exams WHERE id = %s"
        if is_pg
        else "SELECT name, duration_minutes, departments, is_active, valid_until, hide_leaderboard FROM exams WHERE id = ?"
    )
    c.execute(q_exam, (exam_id,))
    exam = c.fetchone()

    q_qs = (
        "SELECT id, branch, question, image_url, options, correct_option FROM questions WHERE exam_id = %s"
        if is_pg
        else "SELECT id, branch, question, image_url, options, correct_option FROM questions WHERE exam_id = ?"
    )
    c.execute(q_qs, (exam_id,))
    questions = [
        {
            "id": r[0],
            "branch": r[1],
            "question": r[2],
            "image_url": r[3],
            "options": json.loads(r[4]),
            "correct_options": parse_correct_answers(r[5]),
        }
        for r in c.fetchall()
    ]
    conn.close()
    return {
        "exam_name": exam[0],
        "duration": exam[1],
        "departments": json.loads(exam[2]) if exam[2] else [],
        "is_active": bool(exam[3]),
        "valid_until": exam[4],
        "hide_leaderboard": bool(exam[5]) if exam[5] is not None else False,
        "questions": questions,
    }


@app.post("/api/admin/questions/update")
async def update_question(
    q_id: int = Form(...),
    branch: str = Form(...),
    question: str = Form(...),
    image_url: Optional[str] = Form(""),
    opt1: str = Form(...),
    opt2: str = Form(...),
    opt3: str = Form(...),
    opt4: str = Form(...),
    correct_options: str = Form(...),
    _admin: Dict[str, object] = Depends(require_permission("manage")),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    options = [opt1.strip(), opt2.strip(), opt3.strip(), opt4.strip()]
    try:
        correct_list = json.loads(correct_options)
        if not isinstance(correct_list, list):
            raise ValueError
    except Exception:
        raise HTTPException(status_code=400, detail="صيغة الإجابات الصحيحة غير سليمة.")
    if not correct_list:
        raise HTTPException(status_code=400, detail="يجب تحديد إجابة صحيحة واحدة على الأقل.")

    q = (
        "UPDATE questions SET branch = %s, question = %s, image_url = %s, options = %s, correct_option = %s WHERE id = %s"
        if is_pg
        else "UPDATE questions SET branch = ?, question = ?, image_url = ?, options = ?, correct_option = ? WHERE id = ?"
    )
    c.execute(
        q,
        (
            branch.strip(),
            question.strip(),
            image_url.strip() if image_url else "",
            json.dumps(options, ensure_ascii=False),
            json.dumps([str(x).strip() for x in correct_list], ensure_ascii=False),
            q_id,
        ),
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث السؤال بنجاح."}


@app.post("/api/admin/questions/add")
async def add_question(
    exam_id: int = Form(...),
    branch: str = Form(...),
    question: str = Form(...),
    image_url: Optional[str] = Form(""),
    opt1: str = Form(...),
    opt2: str = Form(...),
    opt3: str = Form(...),
    opt4: str = Form(...),
    correct_options: str = Form(...),
    _admin: Dict[str, object] = Depends(require_permission("manage")),
):
    options = [opt1.strip(), opt2.strip(), opt3.strip(), opt4.strip()]
    try:
        correct_list = json.loads(correct_options)
        if not isinstance(correct_list, list):
            raise ValueError
    except Exception:
        raise HTTPException(status_code=400, detail="صيغة الإجابات الصحيحة غير سليمة.")
    if not correct_list:
        raise HTTPException(status_code=400, detail="يجب تحديد إجابة صحيحة واحدة على الأقل.")

    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "INSERT INTO questions (exam_id, branch, question, image_url, options, correct_option) VALUES (%s, %s, %s, %s, %s, %s)"
        if is_pg
        else "INSERT INTO questions (exam_id, branch, question, image_url, options, correct_option) VALUES (?, ?, ?, ?, ?, ?)"
    )
    c.execute(
        q,
        (
            exam_id,
            branch.strip(),
            question.strip(),
            image_url.strip() if image_url else "",
            json.dumps(options, ensure_ascii=False),
            json.dumps([str(x).strip() for x in correct_list], ensure_ascii=False),
        ),
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم إضافة السؤال بنجاح."}


@app.delete("/api/admin/questions/{q_id}")
async def delete_question(
    q_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = "DELETE FROM questions WHERE id = %s" if is_pg else "DELETE FROM questions WHERE id = ?"
    c.execute(q, (q_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف السؤال بنجاح."}


@app.get("/api/exams/{exam_id}/questions")
async def get_exam_questions(
    exam_id: int, user: Dict[str, object] = Depends(get_current_user)
):
    sap_id = str(user["sap_id"])
    conn, is_pg = get_db()
    c = conn.cursor()
    q_exam = (
        "SELECT duration_minutes, is_active, valid_until FROM exams WHERE id = %s"
        if is_pg
        else "SELECT duration_minutes, is_active, valid_until FROM exams WHERE id = ?"
    )
    c.execute(q_exam, (exam_id,))
    exam = c.fetchone()
    if not exam or not exam[1]:
        conn.close()
        raise HTTPException(
            status_code=403, detail="هذا الامتحان معطل حالياً."
        )

    now = datetime.now().strftime("%Y-%m-%dT%H:%M")
    if exam[2] and exam[2] < now:
        conn.close()
        raise HTTPException(
            status_code=403, detail="انتهت صلاحية هذا الامتحان."
        )

    if sap_id:
        sap_id_clean = sap_id.strip()

        q_perm = (
            "SELECT allowed FROM retake_permissions WHERE exam_id = %s AND sap_id = %s"
            if is_pg
            else "SELECT allowed FROM retake_permissions WHERE exam_id = ? AND sap_id = ?"
        )
        c.execute(q_perm, (exam_id, sap_id_clean))
        perm = c.fetchone()
        retake_allowed = bool(perm and perm[0] == 1)

        q_sess = (
            "SELECT status FROM exam_sessions WHERE exam_id = %s AND sap_id = %s"
            if is_pg
            else "SELECT status FROM exam_sessions WHERE exam_id = ? AND sap_id = ?"
        )
        c.execute(q_sess, (exam_id, sap_id_clean))
        existing_session = c.fetchone()

        if not existing_session:
            # حماية إضافية لبيانات قديمة قبل إضافة جدول الجلسات: أي نتيجة مسجّلة تُعتبر محاولة مستهلكة
            q_cnt = (
                "SELECT COUNT(id) FROM submissions WHERE exam_id = %s AND sap_id = %s"
                if is_pg
                else "SELECT COUNT(id) FROM submissions WHERE exam_id = ? AND sap_id = ?"
            )
            c.execute(q_cnt, (exam_id, sap_id_clean))
            if c.fetchone()[0] > 0:
                existing_session = ("submitted",)

        if existing_session and not retake_allowed:
            conn.close()
            if existing_session[0] == "in_progress":
                raise HTTPException(
                    status_code=403,
                    detail="لقد قمت بفتح هذا الامتحان من قبل ولم تُكمل تسليمه. يجب الحصول على إذن الإدارة لإعادة المحاولة.",
                )
            raise HTTPException(
                status_code=403,
                detail="لقد قمت بخوض هذا الامتحان سابقاً. يجب الحصول على إذن الإدارة لإعادة المحاولة.",
            )

        if existing_session and retake_allowed:
            # استهلاك إذن الإعادة فورًا (بمجرد الدخول تُحسب المحاولة) وبدء جلسة جديدة نظيفة
            q_del_sess = (
                "DELETE FROM exam_sessions WHERE exam_id = %s AND sap_id = %s"
                if is_pg
                else "DELETE FROM exam_sessions WHERE exam_id = ? AND sap_id = ?"
            )
            c.execute(q_del_sess, (exam_id, sap_id_clean))
            q_reset_perm = (
                "UPDATE retake_permissions SET allowed = 0 WHERE exam_id = %s AND sap_id = %s"
                if is_pg
                else "UPDATE retake_permissions SET allowed = 0 WHERE exam_id = ? AND sap_id = ?"
            )
            c.execute(q_reset_perm, (exam_id, sap_id_clean))

        # تسجيل جلسة دخول جديدة "قيد التقدم" - بمجرد الدخول تُحسب المحاولة وتمنع أي فتح متزامن آخر
        q_ins_sess = (
            "INSERT INTO exam_sessions (exam_id, sap_id, status) VALUES (%s, %s, 'in_progress')"
            if is_pg
            else "INSERT INTO exam_sessions (exam_id, sap_id, status) VALUES (?, ?, 'in_progress')"
        )
        c.execute(q_ins_sess, (exam_id, sap_id_clean))
        conn.commit()

    q_qs = (
        "SELECT id, branch, question, image_url, options FROM questions WHERE exam_id = %s"
        if is_pg
        else "SELECT id, branch, question, image_url, options FROM questions WHERE exam_id = ?"
    )
    c.execute(q_qs, (exam_id,))
    questions = [
        {
            "id": r[0],
            "branch": r[1],
            "question": r[2],
            "image_url": r[3],
            "options": json.loads(r[4]),
        }
        for r in c.fetchall()
    ]
    conn.close()

    # ترتيب عشوائي للأسئلة ولخيارات كل سؤال لكل متحن على حدة
    random.shuffle(questions)
    for q in questions:
        random.shuffle(q["options"])

    return {"duration": exam[0], "questions": questions}


@app.post("/api/exams/{exam_id}/submit")
async def submit_exam(
    exam_id: int,
    payload: Dict[str, object],
    user: Dict[str, object] = Depends(get_current_user),
):
    sap_id = str(user["sap_id"])
    user_name = str(payload.get("user_name", "")).strip()
    answers = payload.get("answers", {})

    conn, is_pg = get_db()
    c = conn.cursor()
    q_qs = (
        "SELECT id, branch, question, correct_option FROM questions WHERE exam_id = %s"
        if is_pg
        else "SELECT id, branch, question, correct_option FROM questions WHERE exam_id = ?"
    )
    c.execute(q_qs, (exam_id,))
    questions = c.fetchall()
    if not questions:
        conn.close()
        raise HTTPException(status_code=404, detail="لا توجد أسئلة.")

    branch_stats = {}
    total_correct = 0
    answers_detail = []

    for q_id, branch, q_text, correct_opt_raw in questions:
        if branch not in branch_stats:
            branch_stats[branch] = {"total": 0, "correct": 0}
        branch_stats[branch]["total"] += 1

        correct_set = set(parse_correct_answers(correct_opt_raw))
        given_raw = answers.get(str(q_id), [])
        if isinstance(given_raw, str):
            given_raw = [given_raw] if given_raw else []
        given_set = set(str(g).strip() for g in given_raw if str(g).strip())

        is_correct = bool(correct_set) and given_set == correct_set
        if is_correct:
            total_correct += 1
            branch_stats[branch]["correct"] += 1

        answers_detail.append({
            "question_id": q_id,
            "branch": branch,
            "question": q_text,
            "given": sorted(given_set),
            "correct": sorted(correct_set),
            "is_correct": is_correct,
        })

    total_q = len(questions)
    overall_pct = (total_correct / total_q) * 100
    overall_lvl = get_level(overall_pct)

    branch_results = {}
    for branch, stats in branch_stats.items():
        b_pct = (
            (stats["correct"] / stats["total"]) * 100
            if stats["total"] > 0
            else 0
        )
        branch_results[branch] = {
            "score": stats["correct"],
            "total": stats["total"],
            "percentage": round(b_pct, 1),
            "level": get_level(b_pct),
        }

    q_sub = (
        """INSERT INTO submissions (exam_id, sap_id, user_name, total_score, total_questions, total_pct, overall_level, branch_details, answers_detail) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        if is_pg
        else """INSERT INTO submissions (exam_id, sap_id, user_name, total_score, total_questions, total_pct, overall_level, branch_details, answers_detail) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    )
    c.execute(
        q_sub,
        (
            exam_id,
            sap_id,
            user_name,
            total_correct,
            total_q,
            overall_pct,
            overall_lvl,
            json.dumps(branch_results, ensure_ascii=False),
            json.dumps(answers_detail, ensure_ascii=False),
        ),
    )

    q_ret = (
        "UPDATE retake_permissions SET allowed = 0 WHERE exam_id = %s AND sap_id = %s"
        if is_pg
        else "UPDATE retake_permissions SET allowed = 0 WHERE exam_id = ? AND sap_id = ?"
    )
    c.execute(q_ret, (exam_id, sap_id))

    # تحديث جلسة الدخول لتصبح "تم التسليم" (أو إنشاؤها لو غير موجودة لأي سبب)
    if is_pg:
        q_sess_upsert = """INSERT INTO exam_sessions (exam_id, sap_id, status, submitted_at)
                            VALUES (%s, %s, 'submitted', CURRENT_TIMESTAMP)
                            ON CONFLICT(exam_id, sap_id) DO UPDATE SET status='submitted', submitted_at=CURRENT_TIMESTAMP"""
    else:
        q_sess_upsert = """INSERT INTO exam_sessions (exam_id, sap_id, status, submitted_at)
                            VALUES (?, ?, 'submitted', CURRENT_TIMESTAMP)
                            ON CONFLICT(exam_id, sap_id) DO UPDATE SET status='submitted', submitted_at=CURRENT_TIMESTAMP"""
    c.execute(q_sess_upsert, (exam_id, sap_id))

    conn.commit()
    conn.close()

    return {
        "user_name": user_name,
        "total_score": total_correct,
        "total_questions": total_q,
        "total_pct": round(overall_pct, 1),
        "overall_level": overall_lvl,
        "branch_results": branch_results,
    }


@app.get("/api/admin/exams/{exam_id}/in-progress-users")
async def get_in_progress_users(
    exam_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    """قائمة الأفراد الذين فتحوا الامتحان ولم يقوموا بتسليمه بعد (محاولة مستهلكة تحتاج إذن الإدارة لإعادتها)."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """SELECT es.sap_id, u.name, es.started_at
           FROM exam_sessions es LEFT JOIN users u ON es.sap_id = u.sap_id
           WHERE es.exam_id = %s AND es.status = 'in_progress' ORDER BY es.started_at DESC"""
        if is_pg
        else """SELECT es.sap_id, u.name, es.started_at
           FROM exam_sessions es LEFT JOIN users u ON es.sap_id = u.sap_id
           WHERE es.exam_id = ? AND es.status = 'in_progress' ORDER BY es.started_at DESC"""
    )
    c.execute(q, (exam_id,))
    rows = c.fetchall()
    conn.close()
    return [
        {"sap_id": r[0], "name": r[1] or "-", "started_at": str(r[2])}
        for r in rows
    ]


@app.get("/api/admin/exams/{exam_id}/submissions")
async def get_exam_submissions_admin(
    exam_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    """قائمة كل نتائج المتدربين لامتحان معين، لإدارتها من لوحة الأدمن (تشمل النتائج المُعلّقة)."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """SELECT s.id, s.sap_id, s.user_name, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.submitted_at, s.hidden
           FROM submissions s WHERE s.exam_id = %s ORDER BY s.total_pct DESC, s.submitted_at ASC"""
        if is_pg
        else """SELECT s.id, s.sap_id, s.user_name, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.submitted_at, s.hidden
           FROM submissions s WHERE s.exam_id = ? ORDER BY s.total_pct DESC, s.submitted_at ASC"""
    )
    c.execute(q, (exam_id,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            "submission_id": r[0],
            "sap_id": r[1],
            "name": r[2],
            "score": f"{r[3]}/{r[4]}",
            "pct": f"{r[5]:.1f}%",
            "level": r[6],
            "date": str(r[7]),
            "hidden": bool(r[8]),
        }
        for r in rows
    ]


@app.post("/api/admin/submissions/{submission_id}/toggle-hidden")
async def toggle_submission_hidden(
    submission_id: int,
    hidden: int = Form(...),
    _admin: Dict[str, object] = Depends(require_permission("manage")),
):
    """تعليق (إخفاء) أو إظهار نتيجة فرد معين في لوحة الشرف بدون حذفها."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE submissions SET hidden = %s WHERE id = %s"
        if is_pg
        else "UPDATE submissions SET hidden = ? WHERE id = ?"
    )
    c.execute(q, (hidden, submission_id))
    conn.commit()
    conn.close()
    return {
        "status": "success",
        "message": "تم إخفاء النتيجة من لوحة الشرف." if hidden else "تم إظهار النتيجة في لوحة الشرف.",
    }


@app.delete("/api/admin/submissions/{submission_id}")
async def delete_submission(
    submission_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    """حذف نتيجة فرد معين نهائيًا."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "DELETE FROM submissions WHERE id = %s"
        if is_pg
        else "DELETE FROM submissions WHERE id = ?"
    )
    c.execute(q, (submission_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف النتيجة بنجاح."}


@app.get("/api/user/{sap_id}/history")
async def get_user_history(sap_id: str, authorization: Optional[str] = Header(None)):
    # يُسمح بالوصول لصاحب السجل نفسه أو لأي حساب إدارة (أدمن مركزي أو مدير عادي)
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="يلزم تسجيل الدخول أولاً.")
    payload = decode_token(authorization.split(" ", 1)[1])
    if payload.get("type") == "user" and str(payload.get("sap_id")) != sap_id.strip():
        raise HTTPException(status_code=403, detail="غير مصرح لك بعرض سجل فرد آخر.")
    if payload.get("type") not in ("user", "admin", "super_admin"):
        raise HTTPException(status_code=401, detail="جلسة غير صالحة.")

    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """SELECT s.id, e.name, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.branch_details, s.submitted_at 
           FROM submissions s LEFT JOIN exams e ON s.exam_id = e.id WHERE s.sap_id = %s ORDER BY s.submitted_at DESC"""
        if is_pg
        else """SELECT s.id, e.name, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.branch_details, s.submitted_at 
           FROM submissions s LEFT JOIN exams e ON s.exam_id = e.id WHERE s.sap_id = ? ORDER BY s.submitted_at DESC"""
    )
    c.execute(q, (sap_id.strip(),))
    rows = c.fetchall()
    conn.close()
    return [
        {
            "submission_id": r[0],
            "exam_name": r[1],
            "score": f"{r[2]}/{r[3]}",
            "percentage": f"{r[4]:.1f}%",
            "overall_level": r[5],
            "branches": json.loads(r[6]),
            "date": str(r[7]),
        }
        for r in rows
    ]


# --- لوحة الشرف والتصدير ---
@app.get("/api/leaderboard/exam/{exam_id}")
async def get_exam_leaderboard(exam_id: int):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """SELECT s.sap_id, s.user_name, u.role, u.department, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.submitted_at 
           FROM submissions s 
           LEFT JOIN users u ON s.sap_id = u.sap_id 
           LEFT JOIN exams e ON s.exam_id = e.id
           WHERE s.exam_id = %s AND COALESCE(s.hidden, 0) = 0 AND COALESCE(e.hide_leaderboard, 0) = 0
           ORDER BY s.total_pct DESC, s.submitted_at ASC"""
        if is_pg
        else """SELECT s.sap_id, s.user_name, u.role, u.department, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.submitted_at 
           FROM submissions s 
           LEFT JOIN users u ON s.sap_id = u.sap_id 
           LEFT JOIN exams e ON s.exam_id = e.id
           WHERE s.exam_id = ? AND COALESCE(s.hidden, 0) = 0 AND COALESCE(e.hide_leaderboard, 0) = 0
           ORDER BY s.total_pct DESC, s.submitted_at ASC"""
    )
    c.execute(q, (exam_id,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            "rank": i + 1,
            "sap_id": r[0],
            "name": r[1],
            "role": r[2] or "-",
            "department": r[3] or "-",
            "score": f"{r[4]}/{r[5]}",
            "pct": f"{r[6]:.1f}%",
            "level": r[7],
            "date": str(r[8]),
        }
        for i, r in enumerate(rows)
    ]


@app.get("/api/exams/public-list")
async def list_exams_public():
    """قائمة مبسطة بأسماء الامتحانات لتعبئة قائمة اختيار الدورة في لوحة الشرف العامة،
    وهي شاشة متاحة للجميع بدون تسجيل دخول، فهذه النقطة عامة أيضًا بلا حاجة لتوكن."""
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name FROM exams WHERE hide_leaderboard = 0 OR hide_leaderboard IS NULL ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1]} for r in rows]


@app.get("/api/leaderboard/general")
async def get_general_leaderboard():
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("""SELECT s.sap_id, s.user_name, u.role, u.department, AVG(s.total_pct) as avg_pct, COUNT(s.id) as exams_count
                 FROM submissions s 
                 LEFT JOIN users u ON s.sap_id = u.sap_id 
                 LEFT JOIN exams e ON s.exam_id = e.id
                 WHERE COALESCE(s.hidden, 0) = 0 AND COALESCE(e.hide_leaderboard, 0) = 0
                 GROUP BY s.sap_id, s.user_name, u.role, u.department ORDER BY avg_pct DESC, exams_count DESC""")
    rows = c.fetchall()
    conn.close()
    return [
        {
            "rank": i + 1,
            "sap_id": r[0],
            "name": r[1],
            "role": r[2] or "-",
            "department": r[3] or "-",
            "avg_pct": f"{r[4]:.1f}%",
            "overall_level": get_level(r[4]),
            "exams_count": r[5],
        }
        for i, r in enumerate(rows)
    ]


@app.get("/api/admin/export-results/{exam_id}")
async def export_results(
    exam_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """SELECT s.sap_id, s.user_name, u.role, u.department, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.branch_details, s.submitted_at, s.answers_detail 
           FROM submissions s LEFT JOIN users u ON s.sap_id = u.sap_id WHERE s.exam_id = %s ORDER BY s.total_pct DESC"""
        if is_pg
        else """SELECT s.sap_id, s.user_name, u.role, u.department, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.branch_details, s.submitted_at, s.answers_detail 
           FROM submissions s LEFT JOIN users u ON s.sap_id = u.sap_id WHERE s.exam_id = ? ORDER BY s.total_pct DESC"""
    )
    c.execute(q, (exam_id,))
    rows = c.fetchall()
    conn.close()

    export_data = []
    answers_rows = []
    reference_questions: Dict[int, Dict[str, object]] = {}

    for r in rows:
        record = {
            "SAP ID": r[0],
            "اسم المشترك": r[1],
            "الدور الوظيفي": r[2] or "-",
            "الإدارة": r[3] or "-",
            "الدرجة": f"{r[4]}/{r[5]}",
            "النسبة المئوية": f"{r[6]:.1f}%",
            "المستوى العام": r[7],
            "التاريخ": str(r[9]),
        }
        for branch, data in json.loads(r[8]).items():
            record[f"{branch} (%)"] = f"{data['percentage']}%"
            record[f"{branch} (المستوى)"] = data["level"]
        export_data.append(record)

        # صف تفصيلي لإجابات هذا المشارك على كل سؤال (يستخدم answers_detail المخزّنة وقت التسليم)
        answers_row = {
            "SAP ID": r[0],
            "اسم المشترك": r[1],
        }
        detail_raw = r[10]
        if detail_raw:
            try:
                details = json.loads(detail_raw)
            except Exception:
                details = []
            for i, d in enumerate(details, start=1):
                reference_questions.setdefault(i, {
                    "question": d.get("question", ""),
                    "correct": "، ".join(d.get("correct", [])),
                })
                answers_row[f"س{i} - الإجابة"] = "، ".join(d.get("given", [])) or "(لم يُجب)"
                answers_row[f"س{i} - صحيح؟"] = "✔ نعم" if d.get("is_correct") else "✘ لا"
        else:
            answers_row["ملاحظة"] = "بيانات إجابات تفصيلية غير متاحة (نتيجة مسجّلة قبل هذا التحديث)"
        answers_rows.append(answers_row)

    df = pd.DataFrame(export_data)
    df_answers = pd.DataFrame(answers_rows)
    df_ref = pd.DataFrame([
        {"رقم السؤال": f"س{i}", "نص السؤال": v["question"], "الإجابة الصحيحة": v["correct"]}
        for i, v in sorted(reference_questions.items())
    ])

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="النتائج")
        df_answers.to_excel(writer, index=False, sheet_name="إجابات كل سؤال")
        if not df_ref.empty:
            df_ref.to_excel(writer, index=False, sheet_name="مرجع الأسئلة")
    output.seek(0)
    return StreamingResponse(
        output,
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
        headers={
            "Content-Disposition": f"attachment; filename=results_exam_{exam_id}.xlsx"
        },
    )


# --- مصفوفة المهارات ---
@app.get("/api/admin/skills")
async def list_skill_requirements(
    _admin: Dict[str, object] = Depends(require_permission("skills"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT sr.id, sr.role, sr.skill_name, sr.description, sr.linked_exam_id, e.name, sr.required_level, sr.skill_group
           FROM skill_requirements sr LEFT JOIN exams e ON sr.linked_exam_id = e.id
           ORDER BY sr.role ASC, sr.skill_group ASC, sr.id ASC"""
    )
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "role": r[1],
            "skill_name": r[2],
            "description": r[3] or "",
            "linked_exam_id": r[4],
            "linked_exam_name": r[5],
            "required_level": r[6],
            "skill_group": r[7] or "عام",
        }
        for r in rows
    ]


@app.post("/api/admin/skills/add")
async def add_skill_requirement(
    role: str = Form(...),
    skill_name: str = Form(...),
    description: str = Form(""),
    linked_exam_id: Optional[str] = Form(None),
    required_level: str = Form("المستوى 2 (متوسط)"),
    skill_group: str = Form("عام"),
    _admin: Dict[str, object] = Depends(require_permission("skills")),
):
    exam_id_val = int(linked_exam_id) if linked_exam_id and linked_exam_id.strip() else None
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """INSERT INTO skill_requirements (role, skill_group, skill_name, description, linked_exam_id, required_level)
           VALUES (%s, %s, %s, %s, %s, %s)"""
        if is_pg
        else """INSERT INTO skill_requirements (role, skill_group, skill_name, description, linked_exam_id, required_level)
           VALUES (?, ?, ?, ?, ?, ?)"""
    )
    c.execute(q, (
        role.strip(),
        skill_group.strip() or "عام",
        skill_name.strip(),
        description.strip(),
        exam_id_val,
        required_level.strip(),
    ))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم إضافة متطلب المهارة بنجاح."}


@app.get("/api/admin/skills/download-template")
async def download_skills_template(
    _admin: Dict[str, object] = Depends(require_permission("skills"))
):
    df = pd.DataFrame([
        {
            "المسمى الوظيفي": "فني صيانة",
            "مجموعة المهارة": "السلامة المهنية",
            "اسم المهارة": "أساسيات السلامة والصحة المهنية",
            "الوصف": "معرفة إجراءات السلامة الأساسية في المصنع",
            "الحد الأدنى للمستوى": "المستوى 2 (متوسط)",
            "اسم الامتحان المرتبط (اختياري)": "",
        },
        {
            "المسمى الوظيفي": "فني صيانة",
            "مجموعة المهارة": "الصيانة الميكانيكية",
            "اسم المهارة": "أساسيات الهيدروليك",
            "الوصف": "",
            "الحد الأدنى للمستوى": "المستوى 3 (متقدم)",
            "اسم الامتحان المرتبط (اختياري)": "",
        },
    ])
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="مصفوفة المهارات")
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=skills_matrix_template.xlsx"},
    )


@app.post("/api/admin/skills/upload-excel")
async def upload_skills_excel(
    file: UploadFile = File(...),
    _admin: Dict[str, object] = Depends(require_permission("skills")),
):
    try:
        contents = await file.read()
        df = pd.read_excel(io.BytesIO(contents))

        conn, is_pg = get_db()
        c = conn.cursor()

        c.execute("SELECT id, name FROM exams")
        exam_name_to_id = {name: eid for eid, name in c.fetchall()}

        q = (
            """INSERT INTO skill_requirements (role, skill_group, skill_name, description, linked_exam_id, required_level)
               VALUES (%s, %s, %s, %s, %s, %s)"""
            if is_pg
            else """INSERT INTO skill_requirements (role, skill_group, skill_name, description, linked_exam_id, required_level)
               VALUES (?, ?, ?, ?, ?, ?)"""
        )

        added = 0
        skipped = 0
        for _, row in df.iterrows():
            role = str(row.get("المسمى الوظيفي", "")).strip()
            skill_name = str(row.get("اسم المهارة", "")).strip()
            if not role or not skill_name or role.lower() == "nan" or skill_name.lower() == "nan":
                skipped += 1
                continue
            skill_group = str(row.get("مجموعة المهارة", "") or "عام").strip()
            if skill_group.lower() == "nan" or not skill_group:
                skill_group = "عام"
            description = str(row.get("الوصف", "") or "").strip()
            if description.lower() == "nan":
                description = ""
            required_level = str(row.get("الحد الأدنى للمستوى", "") or "المستوى 2 (متوسط)").strip()
            if required_level not in LEVEL_ORDER:
                required_level = "المستوى 2 (متوسط)"
            exam_name = str(row.get("اسم الامتحان المرتبط (اختياري)", "") or "").strip()
            linked_exam_id = exam_name_to_id.get(exam_name) if exam_name and exam_name.lower() != "nan" else None

            c.execute(q, (role, skill_group, skill_name, description, linked_exam_id, required_level))
            added += 1

        conn.commit()
        conn.close()
        return {
            "status": "success",
            "message": f"تم استيراد {added} مهارة بنجاح" + (f" (وتخطي {skipped} صف غير مكتمل)" if skipped else "") + ".",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/admin/skills/{skill_id}")
async def delete_skill_requirement(
    skill_id: int, _admin: Dict[str, object] = Depends(require_permission("skills"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "DELETE FROM skill_requirements WHERE id = %s"
        if is_pg
        else "DELETE FROM skill_requirements WHERE id = ?"
    )
    c.execute(q, (skill_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف متطلب المهارة."}


@app.get("/api/user/{sap_id}/skill-matrix")
async def get_user_skill_matrix(sap_id: str, authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="يلزم تسجيل الدخول أولاً.")
    payload = decode_token(authorization.split(" ", 1)[1])
    if payload.get("type") == "user" and str(payload.get("sap_id")) != sap_id.strip():
        raise HTTPException(status_code=403, detail="غير مصرح لك بعرض مصفوفة مهارات فرد آخر.")
    if payload.get("type") not in ("user", "admin", "super_admin"):
        raise HTTPException(status_code=401, detail="جلسة غير صالحة.")

    conn, is_pg = get_db()
    c = conn.cursor()
    q_user = (
        "SELECT role FROM users WHERE sap_id = %s" if is_pg else "SELECT role FROM users WHERE sap_id = ?"
    )
    c.execute(q_user, (sap_id.strip(),))
    urow = c.fetchone()
    if not urow:
        conn.close()
        raise HTTPException(status_code=404, detail="المستخدم غير موجود.")
    role = urow[0]

    q_skills = (
        """SELECT sr.id, sr.skill_name, sr.description, sr.linked_exam_id, e.name, sr.required_level, sr.skill_group
           FROM skill_requirements sr LEFT JOIN exams e ON sr.linked_exam_id = e.id
           WHERE sr.role = %s ORDER BY sr.skill_group ASC, sr.id ASC"""
        if is_pg
        else """SELECT sr.id, sr.skill_name, sr.description, sr.linked_exam_id, e.name, sr.required_level, sr.skill_group
           FROM skill_requirements sr LEFT JOIN exams e ON sr.linked_exam_id = e.id
           WHERE sr.role = ? ORDER BY sr.skill_group ASC, sr.id ASC"""
    )
    c.execute(q_skills, (role,))
    skills = c.fetchall()

    result = []
    for sk_id, skill_name, description, linked_exam_id, exam_name, required_level, skill_group in skills:
        item = {
            "id": sk_id,
            "skill_name": skill_name,
            "description": description or "",
            "linked_exam_id": linked_exam_id,
            "linked_exam_name": exam_name,
            "required_level": required_level,
            "skill_group": skill_group or "عام",
            "status": "not_linked",
            "achieved_level": None,
            "achieved_pct": None,
        }
        if linked_exam_id:
            q_best = (
                """SELECT overall_level, total_pct FROM submissions
                   WHERE exam_id = %s AND sap_id = %s ORDER BY total_pct DESC LIMIT 1"""
                if is_pg
                else """SELECT overall_level, total_pct FROM submissions
                   WHERE exam_id = ? AND sap_id = ? ORDER BY total_pct DESC LIMIT 1"""
            )
            c.execute(q_best, (linked_exam_id, sap_id.strip()))
            best = c.fetchone()
            if best:
                achieved_level, achieved_pct = best
                item["achieved_level"] = achieved_level
                item["achieved_pct"] = round(achieved_pct, 1)
                achieved_idx = LEVEL_ORDER.index(achieved_level) if achieved_level in LEVEL_ORDER else -1
                required_idx = LEVEL_ORDER.index(required_level) if required_level in LEVEL_ORDER else 0
                item["status"] = "met" if achieved_idx >= required_idx else "below"
            else:
                item["status"] = "not_assessed"
        result.append(item)

    conn.close()
    return {"role": role, "skills": result}


@app.get("/api/admin/analytics/overview")
async def get_analytics_overview(
    _admin: Dict[str, object] = Depends(require_permission("analytics"))
):
    conn, is_pg = get_db()
    c = conn.cursor()

    c.execute("SELECT COUNT(id) FROM exams")
    total_exams = c.fetchone()[0]

    c.execute("SELECT COUNT(sap_id) FROM users")
    total_users = c.fetchone()[0]

    c.execute("SELECT COUNT(DISTINCT sap_id) FROM submissions")
    total_participants = c.fetchone()[0]

    c.execute("SELECT COUNT(id) FROM submissions")
    total_submissions = c.fetchone()[0]

    c.execute("SELECT AVG(total_pct) FROM submissions")
    row = c.fetchone()
    overall_avg_pct = round(row[0], 1) if row and row[0] is not None else 0

    # نسبة النجاح العامة (يُعتبر ناجحًا من حقق 60% فأكثر، وهي حدّ المستوى الثاني)
    c.execute("SELECT COUNT(id) FROM submissions WHERE total_pct >= 60")
    passing_count = c.fetchone()[0]
    overall_pass_rate = round((passing_count / total_submissions) * 100, 1) if total_submissions else 0

    # النشاط الأخير
    now = datetime.now()
    d7 = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    d30 = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    q7 = "SELECT COUNT(id) FROM submissions WHERE submitted_at >= %s" if is_pg else "SELECT COUNT(id) FROM submissions WHERE submitted_at >= ?"
    c.execute(q7, (d7,))
    submissions_last_7d = c.fetchone()[0]
    q30 = "SELECT COUNT(id) FROM submissions WHERE submitted_at >= %s" if is_pg else "SELECT COUNT(id) FROM submissions WHERE submitted_at >= ?"
    c.execute(q30, (d30,))
    submissions_last_30d = c.fetchone()[0]

    c.execute("SELECT overall_level, COUNT(id) FROM submissions GROUP BY overall_level")
    overall_level_counts = {lvl: cnt for lvl, cnt in c.fetchall()}
    overall_level_distribution = [
        {
            "level": lvl,
            "count": overall_level_counts.get(lvl, 0),
            "pct": round((overall_level_counts.get(lvl, 0) / total_submissions) * 100, 1)
            if total_submissions
            else 0,
        }
        for lvl in LEVEL_ORDER
    ]

    c.execute(
        """SELECT e.id, e.name, COUNT(s.id) as participants, AVG(s.total_pct) as avg_pct,
                  SUM(CASE WHEN s.total_pct >= 60 THEN 1 ELSE 0 END) as passing
           FROM exams e LEFT JOIN submissions s ON e.id = s.exam_id
           GROUP BY e.id, e.name ORDER BY e.id DESC"""
    )
    exam_rows = c.fetchall()

    per_exam = []
    for exam_id, exam_name, participants, avg_pct, passing in exam_rows:
        q_lvl = (
            "SELECT overall_level, COUNT(id) FROM submissions WHERE exam_id = %s GROUP BY overall_level"
            if is_pg
            else "SELECT overall_level, COUNT(id) FROM submissions WHERE exam_id = ? GROUP BY overall_level"
        )
        c.execute(q_lvl, (exam_id,))
        lvl_counts = {lvl: cnt for lvl, cnt in c.fetchall()}
        p = participants or 0
        level_dist = [
            {
                "level": lvl,
                "count": lvl_counts.get(lvl, 0),
                "pct": round((lvl_counts.get(lvl, 0) / p) * 100, 1) if p else 0,
            }
            for lvl in LEVEL_ORDER
        ]
        per_exam.append({
            "exam_id": exam_id,
            "exam_name": exam_name,
            "participants": p,
            "avg_pct": round(avg_pct, 1) if avg_pct is not None else 0,
            "pass_rate": round(((passing or 0) / p) * 100, 1) if p else 0,
            "level_distribution": level_dist,
        })

    # أكثر 5 امتحانات مشاركة
    top_participation = sorted(per_exam, key=lambda x: x["participants"], reverse=True)[:5]

    # أضعف وأقوى 3 دورات من حيث متوسط الأداء (من بين الدورات التي لها مشاركات فعلية)
    exams_with_participants = [e for e in per_exam if e["participants"] > 0]
    weakest_exams = sorted(exams_with_participants, key=lambda x: x["avg_pct"])[:3]
    strongest_exams = sorted(exams_with_participants, key=lambda x: x["avg_pct"], reverse=True)[:3]

    # التوزيع حسب الإدارة (متوسط الأداء وعدد المشاركين لكل إدارة)
    c.execute(
        """SELECT u.department, COUNT(s.id) as participants, AVG(s.total_pct) as avg_pct
           FROM submissions s LEFT JOIN users u ON s.sap_id = u.sap_id
           GROUP BY u.department ORDER BY participants DESC"""
    )
    dept_breakdown = [
        {
            "department": d or "غير محدد",
            "participants": p,
            "avg_pct": round(a, 1) if a is not None else 0,
        }
        for d, p, a in c.fetchall()
    ]

    # أفضل 5 أفراد أداءً (متوسط النسبة عبر كل امتحاناتهم)
    c.execute(
        """SELECT s.sap_id, s.user_name, u.department, AVG(s.total_pct) as avg_pct, COUNT(s.id) as exams_taken
           FROM submissions s LEFT JOIN users u ON s.sap_id = u.sap_id
           GROUP BY s.sap_id, s.user_name, u.department
           ORDER BY avg_pct DESC LIMIT 5"""
    )
    top_performers = [
        {
            "sap_id": sap_id,
            "name": name,
            "department": dept or "-",
            "avg_pct": round(avg_pct, 1) if avg_pct is not None else 0,
            "exams_taken": exams_taken,
        }
        for sap_id, name, dept, avg_pct, exams_taken in c.fetchall()
    ]

    # تحليل أضعف الأسئلة (الأقل نسبة إجابة صحيحة) عبر كل الامتحانات، بالاعتماد على تفاصيل الإجابات
    # المخزّنة وقت التسليم (متاحة فقط للنتائج المسجّلة بعد تفعيل هذه الميزة)
    c.execute("SELECT answers_detail FROM submissions WHERE answers_detail IS NOT NULL")
    q_stats: Dict[str, Dict[str, object]] = {}
    for (detail_raw,) in c.fetchall():
        try:
            details = json.loads(detail_raw)
        except Exception:
            continue
        for d in details:
            key = f"{d.get('question_id')}"
            if key not in q_stats:
                q_stats[key] = {"question": d.get("question", ""), "branch": d.get("branch", ""), "total": 0, "correct": 0}
            q_stats[key]["total"] += 1
            if d.get("is_correct"):
                q_stats[key]["correct"] += 1

    weakest_questions = []
    for stats in q_stats.values():
        if stats["total"] >= 2:  # نتجاهل الأسئلة قليلة المحاولات لتفادي نتائج غير دالة إحصائيًا
            correct_rate = round((stats["correct"] / stats["total"]) * 100, 1)
            weakest_questions.append({
                "question": stats["question"],
                "branch": stats["branch"],
                "attempts": stats["total"],
                "correct_rate": correct_rate,
            })
    weakest_questions = sorted(weakest_questions, key=lambda x: x["correct_rate"])[:8]

    conn.close()
    return {
        "total_exams": total_exams,
        "total_users": total_users,
        "total_participants": total_participants,
        "participation_rate": round((total_participants / total_users) * 100, 1) if total_users else 0,
        "total_submissions": total_submissions,
        "overall_avg_pct": overall_avg_pct,
        "overall_pass_rate": overall_pass_rate,
        "submissions_last_7d": submissions_last_7d,
        "submissions_last_30d": submissions_last_30d,
        "overall_level_distribution": overall_level_distribution,
        "per_exam": per_exam,
        "top_participation": [
            {"exam_name": e["exam_name"], "participants": e["participants"]}
            for e in top_participation
        ],
        "weakest_exams": weakest_exams,
        "strongest_exams": strongest_exams,
        "department_breakdown": dept_breakdown,
        "top_performers": top_performers,
        "weakest_questions": weakest_questions,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
