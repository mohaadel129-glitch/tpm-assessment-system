import base64
import hashlib
import hmac
import io
import json
import math
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
import arabic_reshaper
from bidi.algorithm import get_display
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="Enterprise Skill Matrix & Assessment System")

# مفاتيح الصلاحيات المتاحة لحسابات الأدمن الفرعية (المديرين العاديين)
# الأدمن المركزي (admin_settings) يملك كل الصلاحيات دائمًا تلقائيًا
ADMIN_PERMISSION_KEYS = [
    "resets", "gallery", "create", "manage", "users", "teams", "analytics", "skills",
    "suggestions", "appreciation", "backup", "content", "full_access",
]

# مهام أعضاء الفريق المتاحة (تُستخدم عند تعيين الأفراد في الفرق)
TEAM_MEMBER_ROLES = [
    "قائد الفريق", "ميسر الفريق", "اداري الفريق", "عضو الفريق",
    "عضو الحلقة A", "عضو الحلقة B", "عضو الحلقة C",
    "قائد الحلقة A", "قائد الحلقة B", "قائد الحلقة C",
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
    if admin.get("type") == "super_admin":
        return admin
    # صلاحية "كل الصلاحيات" تمنح نفس إمكانيات الأدمن المركزي بالكامل، لو الأدمن المركزي منحها لشخص بعينه
    if "full_access" in (admin.get("permissions") or []):
        return admin
    raise HTTPException(
        status_code=403, detail="هذا الإجراء متاح للأدمن المركزي فقط."
    )


def require_permission(perm_key: str):
    async def _dep(admin: Dict[str, object] = Depends(get_current_admin)):
        if admin.get("type") == "super_admin":
            return admin
        perms = admin.get("permissions") or []
        if "full_access" in perms or perm_key in perms:
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

        # ترحيل: إضافة عمود allow_answer_review لجدول الامتحانات (السماح للمتحن بمراجعة
        # تفاصيل إجاباته: إجابته الصحيحة والخاطئة والإجابة الصحيحة المفترضة لكل سؤال)
        try:
            if is_pg:
                c.execute("ALTER TABLE exams ADD COLUMN IF NOT EXISTS allow_answer_review INTEGER DEFAULT 0")
            else:
                c.execute("PRAGMA table_info(exams)")
                cols = [r[1] for r in c.fetchall()]
                if "allow_answer_review" not in cols:
                    c.execute("ALTER TABLE exams ADD COLUMN allow_answer_review INTEGER DEFAULT 0")
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
            name TEXT UNIQUE NOT NULL,
            visibility TEXT DEFAULT 'public'
        )""")
        # ترحيل: إضافة عمود رؤية الفريق (public = يظهر للجميع، team_only = لأعضاء الفريق فقط) لو الجدول قديم
        try:
            if is_pg:
                c.execute("ALTER TABLE teams ADD COLUMN IF NOT EXISTS visibility TEXT DEFAULT 'public'")
            else:
                c.execute("PRAGMA table_info(teams)")
                cols = [r[1] for r in c.fetchall()]
                if "visibility" not in cols:
                    c.execute("ALTER TABLE teams ADD COLUMN visibility TEXT DEFAULT 'public'")
        except Exception:
            pass

        # 11. جدول ربط المستخدمين بالفرق (فرد يمكن أن يكون في فريقين كحد أقصى)
        c.execute(f"""CREATE TABLE IF NOT EXISTS user_teams (
            id {id_type},
            sap_id TEXT NOT NULL,
            team_id INTEGER NOT NULL,
            role_in_team TEXT,
            task_description TEXT,
            UNIQUE(sap_id, team_id)
        )""")
        # ترحيل: إضافة عمود مهمة العضو ووصف المهام المطلوبة منه، لو الجدول قديم
        for col, coldef in [("role_in_team", "TEXT"), ("task_description", "TEXT")]:
            try:
                if is_pg:
                    c.execute(f"ALTER TABLE user_teams ADD COLUMN IF NOT EXISTS {col} {coldef}")
                else:
                    c.execute("PRAGMA table_info(user_teams)")
                    cols = [r[1] for r in c.fetchall()]
                    if col not in cols:
                        c.execute(f"ALTER TABLE user_teams ADD COLUMN {col} {coldef}")
            except Exception:
                pass

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

        # 12-ب. جدول طلبات إعادة الامتحان المقدَّمة من الأفراد أنفسهم
        c.execute(f"""CREATE TABLE IF NOT EXISTS retake_requests (
            id {id_type},
            exam_id INTEGER NOT NULL,
            sap_id TEXT NOT NULL,
            user_name TEXT,
            status TEXT DEFAULT 'pending',
            requested_at TIMESTAMP DEFAULT {ts_default}
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

        # 14. جدول التقييم اليدوي لمهارات فرد (تجاوز/تحديد مستوى مهارة يدويًا بدون ربطها بامتحان)
        c.execute(f"""CREATE TABLE IF NOT EXISTS skill_overrides (
            id {id_type},
            sap_id TEXT NOT NULL,
            skill_requirement_id INTEGER NOT NULL,
            achieved_level TEXT,
            note TEXT,
            updated_at TIMESTAMP DEFAULT {ts_default},
            UNIQUE(sap_id, skill_requirement_id)
        )""")

        # ترحيل: أعمدة مصدر التدريب المقترح ومدة صلاحية المهارة (لتنبيهات التجديد الدورية)
        for col, coldef in [
            ("training_resource_url", "TEXT"),
            ("training_resource_note", "TEXT"),
            ("validity_months", "INTEGER"),
        ]:
            try:
                if is_pg:
                    c.execute(f"ALTER TABLE skill_requirements ADD COLUMN IF NOT EXISTS {col} {coldef}")
                else:
                    c.execute("PRAGMA table_info(skill_requirements)")
                    cols = [r[1] for r in c.fetchall()]
                    if col not in cols:
                        c.execute(f"ALTER TABLE skill_requirements ADD COLUMN {col} {coldef}")
            except Exception:
                pass

        # 16. نتائج الصيانة الإنتاجية الشاملة (TPM) نصف السنوية — تُرفع بواسطة الأدمن المركزي
        c.execute(f"""CREATE TABLE IF NOT EXISTS tpm_results (
            id {id_type},
            half_period TEXT NOT NULL,
            factory TEXT,
            department TEXT NOT NULL,
            team TEXT NOT NULL,
            activity TEXT NOT NULL,
            planned_point REAL,
            actual_point REAL,
            achievement_pct REAL NOT NULL,
            rating_ar TEXT,
            uploaded_at TIMESTAMP DEFAULT {ts_default}
        )""")

        # 17. مقترحات وملاحظات الزوار (من زر "اقتراح بتعديل" في الصفحة الرئيسية)
        c.execute(f"""CREATE TABLE IF NOT EXISTS suggestions (
            id {id_type},
            name TEXT,
            phone TEXT,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            admin_reply TEXT,
            created_at TIMESTAMP DEFAULT {ts_default}
        )""")
        # ترحيل: أعمدة حالة المقترح (مقبول/مرفوض) ورد الأدمن، لو الجدول قديم
        for col, coldef in [("status", "TEXT DEFAULT 'pending'"), ("admin_reply", "TEXT")]:
            try:
                if is_pg:
                    c.execute(f"ALTER TABLE suggestions ADD COLUMN IF NOT EXISTS {col} {coldef}")
                else:
                    c.execute("PRAGMA table_info(suggestions)")
                    cols = [r[1] for r in c.fetchall()]
                    if col not in cols:
                        c.execute(f"ALTER TABLE suggestions ADD COLUMN {col} {coldef}")
            except Exception:
                pass

        # 18. شهادات التقدير (تُمنح لأفراد يحددهم الأدمن، وتُنزَّل من خلال الإدارة فقط)
        c.execute(f"""CREATE TABLE IF NOT EXISTS appreciation_certificates (
            id {id_type},
            sap_id TEXT NOT NULL,
            user_name TEXT NOT NULL,
            reason_text TEXT NOT NULL,
            granted_by TEXT,
            rank_type TEXT DEFAULT 'none',
            exam_id INTEGER,
            exam_name TEXT,
            rank_value INTEGER,
            created_at TIMESTAMP DEFAULT {ts_default}
        )""")
        # ترحيل: أعمدة الترتيب (في دورة معينة أو الترتيب العام) لو الجدول قديم
        for col, coldef in [
            ("rank_type", "TEXT DEFAULT 'none'"), ("exam_id", "INTEGER"),
            ("exam_name", "TEXT"), ("rank_value", "INTEGER"),
        ]:
            try:
                if is_pg:
                    c.execute(f"ALTER TABLE appreciation_certificates ADD COLUMN IF NOT EXISTS {col} {coldef}")
                else:
                    c.execute("PRAGMA table_info(appreciation_certificates)")
                    cols = [r[1] for r in c.fetchall()]
                    if col not in cols:
                        c.execute(f"ALTER TABLE appreciation_certificates ADD COLUMN {col} {coldef}")
            except Exception:
                pass

        # 19. مفاتيح تحكم الأدمن المركزي في ظهور الأجزاء/الفيتشرز، ووضع الصيانة (تعليق الدخول بالكامل)
        c.execute(f"""CREATE TABLE IF NOT EXISTS feature_flags (
            flag_key TEXT PRIMARY KEY,
            enabled INTEGER DEFAULT 1,
            label TEXT
        )""")
        default_flags = [
            ("maintenance_mode", 0, "وضع الصيانة (تعليق الدخول بالكامل عن الأفراد والمديرين)"),
            ("leaderboard", 1, "لوحة الشرف"),
            ("skill_matrix", 1, "مصفوفة المهارات"),
            ("teams_view", 1, "عرض الفرق للأفراد"),
            ("suggestions_button", 1, "زر الاقتراحات في الصفحة الرئيسية"),
            ("certificates_download", 1, "تحميل شهادات الاجتياز"),
            ("answer_review", 1, "مراجعة الإجابات بعد الامتحان"),
            ("public_gallery", 1, "معرض الصور في الصفحة الرئيسية"),
            ("tpm_charts", 1, "شارتات نتائج TPM في الصفحة الرئيسية"),
            ("training_tab", 1, "تبويب التدريب (فيديو/صوت/PDF)"),
            ("instructions_tab", 1, "تبويب التعليمات والخرائط"),
        ]
        for key, enabled, label in default_flags:
            q_seed = (
                "INSERT INTO feature_flags (flag_key, enabled, label) VALUES (%s, %s, %s) ON CONFLICT(flag_key) DO NOTHING"
                if is_pg
                else "INSERT OR IGNORE INTO feature_flags (flag_key, enabled, label) VALUES (?, ?, ?)"
            )
            try:
                c.execute(q_seed, (key, enabled, label))
            except Exception:
                pass

        # 20. المحتوى التدريبي: فولدرات هرمية (تدريب / تعليمات وخرائط) وموادها (فيديو يوتيوب / صوت / PDF)
        c.execute(f"""CREATE TABLE IF NOT EXISTS content_folders (
            id {id_type},
            tab TEXT NOT NULL,
            parent_id INTEGER,
            name TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT {ts_default}
        )""")
        c.execute(f"""CREATE TABLE IF NOT EXISTS content_materials (
            id {id_type},
            tab TEXT NOT NULL,
            folder_id INTEGER,
            name TEXT NOT NULL,
            description TEXT,
            content_type TEXT NOT NULL,
            video_url TEXT,
            file_url TEXT,
            file_public_id TEXT,
            created_at TIMESTAMP DEFAULT {ts_default}
        )""")

        # 21. تتبع مشاهدة المواد التدريبية لكل فرد (فتح + إنهاء)
        c.execute(f"""CREATE TABLE IF NOT EXISTS content_progress (
            id {id_type},
            sap_id TEXT NOT NULL,
            material_id INTEGER NOT NULL,
            first_viewed_at TIMESTAMP DEFAULT {ts_default},
            completed INTEGER DEFAULT 0,
            completed_at TIMESTAMP,
            UNIQUE(sap_id, material_id)
        )""")

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


def normalize_arabic(text: str) -> str:
    """يوحّد الأشكال المختلفة للحروف العربية شائعة الخلط بها (مثل ي/ى، ة/ه، أ/إ/آ)
    ويزيل التشكيل والمسافات الزائدة، لمقارنة النصوص (مثل المسمى الوظيفي) بدون حساسية
    للفروق الإملائية الشائعة (فني صيانة / فنى صيانه / إلخ)."""
    if not text:
        return ""
    t = str(text).strip()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"[\u064B-\u0652]", "", t)  # إزالة التشكيل
    t = t.replace("أ", "ا").replace("إ", "ا").replace("آ", "ا")
    t = t.replace("ى", "ي")
    t = t.replace("ة", "ه")
    return t.lower()


# ==================== شهادات الاجتياز (PDF بدعم اللغة العربية) ====================
CERTIFICATE_ELIGIBLE_LEVELS = {"المستوى 3 (متقدم)", "المستوى 4 (خبير)"}
_ARABIC_FONT_REGISTERED = False

# مجلد الصور (اللوجوهات وصور الأفراد) المرفوع بجوار ملف الكود مباشرة
ASSETS_DIR = BASE_DIR / "assets"
IMAGE_EXTENSIONS = [".png", ".jpg", ".jpeg", ".webp", ".PNG", ".JPG", ".JPEG"]


def _find_asset_image(*possible_names: str) -> Optional[Path]:
    """يبحث عن ملف صورة داخل مجلد assets بأي من الأسماء المحتملة وأي امتداد شائع.
    يُستخدم للوجوهات (logo 1 / logo 2) ولصور الأفراد (باسم رقم الساب)."""
    if not ASSETS_DIR.exists():
        return None
    for name in possible_names:
        for ext in IMAGE_EXTENSIONS:
            candidate = ASSETS_DIR / f"{name}{ext}"
            if candidate.exists():
                return candidate
    return None


@app.get("/api/public/logo/{which}")
def get_public_logo(which: int):
    """يعرض اللوجو (1 أو 2) للواجهة الأمامية — مثلًا في صفحة تسجيل الدخول،
    من غير ما نفتح مجلد assets بالكامل للعامة (لأنه فيه صور شخصية للأفراد)."""
    if which not in (1, 2):
        raise HTTPException(status_code=404, detail="Not found")
    path = _find_asset_image(f"logo {which}", f"logo{which}", f"Logo {which}", f"Logo{which}")
    if not path:
        raise HTTPException(status_code=404, detail="Logo not found")
    return FileResponse(str(path))


@app.get("/api/public/name-font")
def get_public_name_font():
    """يعرض ملف الخط المميز (نفس خط اسم الزميل في الشهادات) عشان نستخدمه في تصميم
    الموقع أيضًا (زي توقيع المصمم) — مجرد ملف خط، لا يحتوي على أي بيانات خاصة."""
    font_path = Path(__file__).parent / "fonts" / "al-mujahed-free-yr.ttf"
    if not font_path.exists():
        raise HTTPException(status_code=404, detail="Font not found")
    return FileResponse(str(font_path), media_type="font/ttf")


# أسماء صور الصفحة التعريفية المسموح عرضها للعامة (قائمة مغلقة أمانًا — عشان منفتحش مجلد
# assets بالكامل، لأنه فيه صور شخصية للأفراد وصورة اعتماد المدير لازم تفضل خاصة)
PUBLIC_SITE_IMAGE_NAMES = {
    "site-hero", "site-about-1", "site-about-2", "site-designer-avatar",
    "site-training-1", "site-training-2", "site-training-3", "site-training-4",
    "site-training-5", "site-training-6", "site-training-7", "site-training-8",
    "site-training-9", "site-training-10",
    "site-icon-192", "site-icon-512",
}
PUBLIC_SITE_VIDEO_NAMES = {"site-video-1", "site-video-2"}
VIDEO_EXTENSIONS = [".mp4", ".webm", ".mov", ".MP4"]


@app.get("/api/public/site-image/{name}")
def get_public_site_image(name: str):
    """يعرض صور الصفحة التعريفية (Hero / نبذة / معرض التدريبات) — بقائمة أسماء مغلقة فقط."""
    if name not in PUBLIC_SITE_IMAGE_NAMES:
        raise HTTPException(status_code=404, detail="Not found")
    path = _find_asset_image(name)
    if not path:
        raise HTTPException(status_code=404, detail="Image not found")
    return FileResponse(str(path))


@app.get("/api/public/site-video/{name}")
def get_public_site_video(name: str):
    """يعرض الفيديوهات التعريفية القصيرة في الصفحة الرئيسية — بقائمة أسماء مغلقة فقط."""
    if name not in PUBLIC_SITE_VIDEO_NAMES:
        raise HTTPException(status_code=404, detail="Not found")
    if not ASSETS_DIR.exists():
        raise HTTPException(status_code=404, detail="Video not found")
    for ext in VIDEO_EXTENSIONS:
        candidate = ASSETS_DIR / f"{name}{ext}"
        if candidate.exists():
            return FileResponse(str(candidate), media_type="video/mp4")
    raise HTTPException(status_code=404, detail="Video not found")


# ==================== مقترحات الزوار (زر "اقتراح بتعديل" في الصفحة الرئيسية) ====================
@app.post("/api/public/suggestions")
async def submit_suggestion(payload: Dict[str, object]):
    name = str(payload.get("name") or "").strip()
    phone = str(payload.get("phone") or "").strip()
    message = str(payload.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="من فضلك اكتب نص الاقتراح أو المشكلة.")
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "INSERT INTO suggestions (name, phone, message) VALUES (%s, %s, %s)"
        if is_pg
        else "INSERT INTO suggestions (name, phone, message) VALUES (?, ?, ?)"
    )
    c.execute(q, (name, phone, message))
    conn.commit()
    conn.close()
    return {"status": "success"}


@app.get("/api/admin/suggestions")
async def list_suggestions(
    status: str = "all",
    q: str = "",
    _admin: Dict[str, object] = Depends(require_permission("suggestions")),
):
    """يرجّع المقترحات مع دعم الفلترة بالحالة والبحث بالاسم/التليفون/نص الرسالة،
    بالإضافة لعدد كل حالة (لعرض الكروت الإحصائية فوق القائمة)."""
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, phone, message, is_read, status, admin_reply, created_at FROM suggestions ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    all_items = [
        {
            "id": r[0], "name": r[1], "phone": r[2], "message": r[3],
            "is_read": bool(r[4]), "status": r[5] or "pending", "admin_reply": r[6],
            "created_at": str(r[7]),
        }
        for r in rows
    ]

    counts = {
        "all": len(all_items),
        "pending": sum(1 for s in all_items if s["status"] == "pending"),
        "approved": sum(1 for s in all_items if s["status"] == "approved"),
        "rejected": sum(1 for s in all_items if s["status"] == "rejected"),
        "unread": sum(1 for s in all_items if not s["is_read"]),
    }

    filtered = all_items
    if status and status != "all":
        filtered = [s for s in filtered if s["status"] == status]
    if q:
        ql = q.strip().lower()
        filtered = [
            s for s in filtered
            if ql in (s["name"] or "").lower() or ql in (s["phone"] or "").lower() or ql in (s["message"] or "").lower()
        ]

    return {"items": filtered, "counts": counts}


@app.post("/api/admin/suggestions/{suggestion_id}/mark-read")
async def mark_suggestion_read(
    suggestion_id: int, _admin: Dict[str, object] = Depends(require_permission("suggestions"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE suggestions SET is_read = 1 WHERE id = %s" if is_pg
        else "UPDATE suggestions SET is_read = 1 WHERE id = ?"
    )
    c.execute(q, (suggestion_id,))
    conn.commit()
    conn.close()
    return {"status": "success"}


@app.post("/api/admin/suggestions/{suggestion_id}/respond")
async def respond_to_suggestion(
    suggestion_id: int,
    status: str = Form(...),
    admin_reply: str = Form(""),
    _admin: Dict[str, object] = Depends(require_permission("suggestions")),
):
    """يحدد الأدمن حالة المقترح: approved (✓ مقبول) أو rejected (✗ مرفوض)، مع رد اختياري."""
    if status not in ("approved", "rejected", "pending"):
        raise HTTPException(status_code=400, detail="حالة غير صحيحة.")
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE suggestions SET status = %s, admin_reply = %s, is_read = 1 WHERE id = %s" if is_pg
        else "UPDATE suggestions SET status = ?, admin_reply = ?, is_read = 1 WHERE id = ?"
    )
    c.execute(q, (status, admin_reply.strip() or None, suggestion_id))
    conn.commit()
    conn.close()
    return {"status": "success"}


@app.get("/api/admin/suggestions/export")
async def export_suggestions(_admin: Dict[str, object] = Depends(require_permission("suggestions"))):
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, phone, message, status, admin_reply, is_read, created_at FROM suggestions ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    status_ar = {"pending": "قيد المراجعة", "approved": "مقبول", "rejected": "مرفوض"}
    df = pd.DataFrame(
        [
            {
                "رقم": r[0], "الاسم": r[1], "رقم الموبايل": r[2], "الرسالة": r[3],
                "الحالة": status_ar.get(r[4] or "pending", r[4]), "رد الإدارة": r[5] or "",
                "تمت المراجعة": "نعم" if r[6] else "لا", "التاريخ": str(r[7]),
            }
            for r in rows
        ]
    )
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="المقترحات")
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=suggestions_export.xlsx"},
    )


# ==================== نتائج الصيانة الإنتاجية الشاملة (TPM) — الصفحة الرئيسية ====================
TPM_STEP_PILLARS = {"JH", "PM"}  # الركائز اللي ليها خطوات متتالية (Jishu Hozen / Planned Maintenance)


@app.post("/api/admin/tpm-results/upload")
async def upload_tpm_results(
    half_period: str = Form(...),
    file: UploadFile = File(...),
    _admin: Dict[str, object] = Depends(get_current_super_admin),
):
    """رفع ملف إكسل نتائج TPM (بنفس أعمدة الملف: Factory, Team, Activity, Department,
    Planned_Point, Actual_Point, Achievement_Pct, Rating_AR) — للنصف الأول أو الثاني من السنة."""
    half_period = half_period.strip().upper()
    if half_period not in ("H1", "H2"):
        raise HTTPException(status_code=400, detail="النصف يجب أن يكون H1 أو H2.")
    try:
        contents = await file.read()
        df = pd.read_excel(io.BytesIO(contents))
        required_cols = {"Team", "Activity", "Department", "Achievement_Pct"}
        if not required_cols.issubset(set(df.columns)):
            raise HTTPException(
                status_code=400,
                detail=f"الملف لازم يحتوي على الأعمدة: {', '.join(sorted(required_cols))}",
            )
        conn, is_pg = get_db()
        c = conn.cursor()
        q_del = (
            "DELETE FROM tpm_results WHERE half_period = %s" if is_pg
            else "DELETE FROM tpm_results WHERE half_period = ?"
        )
        c.execute(q_del, (half_period,))
        q_ins = (
            """INSERT INTO tpm_results
               (half_period, factory, department, team, activity, planned_point, actual_point, achievement_pct, rating_ar)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            if is_pg
            else """INSERT INTO tpm_results
               (half_period, factory, department, team, activity, planned_point, actual_point, achievement_pct, rating_ar)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""
        )
        count = 0
        for _, row in df.iterrows():
            if pd.isna(row.get("Team")) or pd.isna(row.get("Department")):
                continue
            c.execute(q_ins, (
                half_period,
                str(row.get("Factory") or "").strip() or None,
                str(row["Department"]).strip(),
                str(row["Team"]).strip(),
                str(row.get("Activity") or "").strip(),
                float(row["Planned_Point"]) if pd.notna(row.get("Planned_Point")) else None,
                float(row["Actual_Point"]) if pd.notna(row.get("Actual_Point")) else None,
                float(row["Achievement_Pct"]),
                str(row.get("Rating_AR") or "").strip() or None,
            ))
            count += 1
        conn.commit()
        conn.close()
        return {"status": "success", "rows_imported": count, "half_period": half_period}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"تعذّرت قراءة الملف: {e}")


def _fetch_tpm_rows(half: str):
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT department, team, activity, achievement_pct
           FROM tpm_results WHERE half_period = %s""" if is_pg
        else """SELECT department, team, activity, achievement_pct
           FROM tpm_results WHERE half_period = ?""",
        (half,),
    )
    rows = c.fetchall()
    conn.close()
    return rows


def _aggregate_tpm(rows):
    """يحسب متوسط الإنجاز لكل إدارة ولكل ركيزة داخل كل إدارة، من صفوف نتائج TPM خام."""
    departments = sorted(set(r[0] for r in rows if r[0] != "TPM Teams"))
    pillars = sorted(set(r[1] for r in rows))

    dept_avg = []
    for dept in departments:
        vals = [r[3] for r in rows if r[0] == dept]
        dept_avg.append(round(sum(vals) / len(vals), 1) if vals else 0)

    pillar_by_dept = {}
    for dept in departments:
        vals = []
        for pillar in pillars:
            matched = [r[3] for r in rows if r[0] == dept and r[1] == pillar]
            vals.append(round(sum(matched) / len(matched), 1) if matched else None)
        pillar_by_dept[dept] = vals

    overall_avg = round(sum(r[3] for r in rows) / len(rows), 1) if rows else 0

    return {
        "departments": departments,
        "pillars": pillars,
        "department_avg": dept_avg,
        "pillar_by_department": pillar_by_dept,
        "overall_avg": overall_avg,
    }


@app.get("/api/public/tpm-results")
def get_public_tpm_results(half: str = "H1"):
    """يرجّع نتائج TPM جاهزة للرسم البياني في الصفحة الرئيسية: متوسط الإنجاز لكل إدارة،
    متوسط الإنجاز لكل ركيزة، وتفصيل الخطوات للركائز اللي ليها خطوات (JH و PM)."""
    half = half.strip().upper() if half else "H1"
    rows = _fetch_tpm_rows(half)

    if not rows:
        return {"half_period": half, "has_data": False}

    agg = _aggregate_tpm(rows)
    departments, pillars = agg["departments"], agg["pillars"]

    # شارتات خاصة للركائز اللي ليها خطوات (JH, PM) — تطور الأداء عبر الخطوات لكل إدارة
    step_charts = {}
    for pillar in TPM_STEP_PILLARS:
        step_rows = [r for r in rows if r[1] == pillar and r[0] != "TPM Teams" and "-" in (r[2] or "")]
        if not step_rows:
            continue
        steps = sorted(set(r[2] for r in step_rows), key=lambda s: (len(s), s))
        series = {}
        for dept in departments:
            series[dept] = [
                next((r[3] for r in step_rows if r[0] == dept and r[2] == step), None)
                for step in steps
            ]
        step_charts[pillar] = {"steps": steps, "series": series}

    return {
        "half_period": half,
        "has_data": True,
        "departments": departments,
        "pillars": pillars,
        "department_avg": agg["department_avg"],
        "pillar_by_department": agg["pillar_by_department"],
        "step_charts": step_charts,
    }


@app.get("/api/public/tpm-results/comparison")
def get_public_tpm_comparison():
    """يقارن نتائج النصف الأول بالنصف الثاني (لو النصفين متاحين) — لكل إدارة ولكل ركيزة."""
    h1_rows = _fetch_tpm_rows("H1")
    h2_rows = _fetch_tpm_rows("H2")

    if not h1_rows or not h2_rows:
        return {"has_both": False}

    h1 = _aggregate_tpm(h1_rows)
    h2 = _aggregate_tpm(h2_rows)

    # نوحّد قائمة الإدارات والركائز بين النصفين (اتحاد الاثنين) عشان المقارنة تبقى كاملة
    departments = sorted(set(h1["departments"]) | set(h2["departments"]))
    pillars = sorted(set(h1["pillars"]) | set(h2["pillars"]))

    def dept_avg_aligned(agg):
        m = dict(zip(agg["departments"], agg["department_avg"]))
        return [m.get(d) for d in departments]

    def pillar_aligned(agg):
        out = {}
        for dept in departments:
            row = agg["pillar_by_department"].get(dept)
            if row is None:
                out[dept] = [None] * len(pillars)
                continue
            m = dict(zip(agg["pillars"], row))
            out[dept] = [m.get(p) for p in pillars]
        return out

    return {
        "has_both": True,
        "departments": departments,
        "pillars": pillars,
        "h1_department_avg": dept_avg_aligned(h1),
        "h2_department_avg": dept_avg_aligned(h2),
        "h1_overall_avg": h1["overall_avg"],
        "h2_overall_avg": h2["overall_avg"],
        "h1_pillar_by_department": pillar_aligned(h1),
        "h2_pillar_by_department": pillar_aligned(h2),
    }


@app.get("/api/public/platform-stats")
def get_public_platform_stats():
    """إحصائيات عامة عن المنصة تُعرض كشارات في الصفحة الرئيسية."""
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM exams")
    courses_count = c.fetchone()[0]
    c.execute("SELECT COUNT(DISTINCT sap_id) FROM submissions")
    examinees_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM submissions")
    submissions_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users")
    users_count = c.fetchone()[0]
    try:
        c.execute("SELECT COUNT(*) FROM teams")
        teams_count = c.fetchone()[0]
    except Exception:
        teams_count = 0
    conn.close()
    return {
        "courses_count": courses_count,
        "examinees_count": examinees_count,
        "submissions_count": submissions_count,
        "users_count": users_count,
        "teams_count": teams_count,
    }


# ==================== تحكم الأدمن المركزي في ظهور الأجزاء ووضع الصيانة ====================
def is_maintenance_mode() -> bool:
    """يفحص هل وضع الصيانة مفعّل حاليًا (يُستخدم في نقاط تسجيل الدخول لمنع دخول
    الأفراد والمديرين العاديين، مع إبقاء الأدمن المركزي قادرًا على الدخول دائمًا لإيقافه)."""
    try:
        conn, is_pg = get_db()
        c = conn.cursor()
        q = (
            "SELECT enabled FROM feature_flags WHERE flag_key = %s" if is_pg
            else "SELECT enabled FROM feature_flags WHERE flag_key = ?"
        )
        c.execute(q, ("maintenance_mode",))
        row = c.fetchone()
        conn.close()
        return bool(row and row[0])
    except Exception:
        return False


@app.get("/api/public/feature-flags")
def get_public_feature_flags():
    """يرجّع كل مفاتيح التحكم (ظاهر/مخفي) — عام ومتاح حتى قبل تسجيل الدخول،
    عشان الواجهة تعرف تخفي/تظهر الأجزاء المناسبة فورًا."""
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("SELECT flag_key, enabled FROM feature_flags")
    rows = c.fetchall()
    conn.close()
    return {r[0]: bool(r[1]) for r in rows}


@app.get("/api/admin/feature-flags/list")
async def list_feature_flags_admin(_admin: Dict[str, object] = Depends(get_current_super_admin)):
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("SELECT flag_key, enabled, label FROM feature_flags ORDER BY (flag_key = 'maintenance_mode') DESC, label ASC")
    rows = c.fetchall()
    conn.close()
    return [{"key": r[0], "enabled": bool(r[1]), "label": r[2]} for r in rows]


@app.post("/api/admin/feature-flags/{flag_key}/toggle")
async def toggle_feature_flag(
    flag_key: str,
    enabled: bool = Form(...),
    _admin: Dict[str, object] = Depends(get_current_super_admin),
):
    """تفعيل/تعطيل أي فيتشر أو جزء من المنصة — مقصور على الأدمن المركزي فقط
    (بما في ذلك وضع الصيانة نفسه، عشان محدش تاني يقدر يعلّق الدخول كله غيره)."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE feature_flags SET enabled = %s WHERE flag_key = %s" if is_pg
        else "UPDATE feature_flags SET enabled = ? WHERE flag_key = ?"
    )
    c.execute(q, (1 if enabled else 0, flag_key))
    conn.commit()
    conn.close()
    return {"status": "success"}


BACKUP_TABLES = [
    "users", "admins", "admin_settings", "exams", "questions", "submissions",
    "teams", "user_teams", "retake_permissions", "retake_requests",
    "reset_requests", "skill_requirements", "skill_overrides",
    "tpm_results", "suggestions", "appreciation_certificates", "media_gallery",
]


@app.get("/api/admin/backup/download")
async def download_backup(_admin: Dict[str, object] = Depends(require_permission("backup"))):
    """نسخة احتياطية يدوية فورية: ملف إكسل بكل جداول النظام، كل جدول في ورقة مستقلة."""
    conn, is_pg = get_db()
    c = conn.cursor()
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        for table in BACKUP_TABLES:
            try:
                c.execute(f"SELECT * FROM {table}")
                rows = c.fetchall()
                col_names = [desc[0] for desc in c.description]
                df = pd.DataFrame(rows, columns=col_names) if rows else pd.DataFrame(columns=col_names)
                # اسم الورقة في إكسل محدود بـ 31 حرف
                df.to_excel(writer, index=False, sheet_name=table[:31])
            except Exception:
                continue
    conn.close()
    output.seek(0)
    filename = f"tpm_backup_{datetime.now().strftime('%Y-%m-%d_%H%M')}.xlsx"
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def ensure_arabic_font():
    """يسجّل خط Amiri العربي (الأساسي) وخط Al-Mujahed (لاسم الزميل تحديدًا) مرة واحدة فقط."""
    global _ARABIC_FONT_REGISTERED
    if _ARABIC_FONT_REGISTERED:
        return
    font_path = Path(__file__).parent / "fonts" / "Amiri-Regular.ttf"
    if not font_path.exists():
        raise HTTPException(
            status_code=500,
            detail="خط الشهادات العربي غير موجود على السيرفر (ملف fonts/Amiri-Regular.ttf مفقود من مجلد المشروع).",
        )
    pdfmetrics.registerFont(TTFont("Amiri", str(font_path)))

    # خط مميز لاسم الزميل في الشهادة (اختياري: لو مش موجود، بيرجع تلقائيًا لخط Amiri)
    name_font_path = Path(__file__).parent / "fonts" / "al-mujahed-free-yr.ttf"
    if name_font_path.exists():
        try:
            pdfmetrics.registerFont(TTFont("NameFont", str(name_font_path)))
        except Exception:
            pass

    _ARABIC_FONT_REGISTERED = True


def _name_font_available() -> bool:
    return "NameFont" in pdfmetrics.getRegisteredFontNames()


def shape_arabic(text: str) -> str:
    """يهيّئ نصًا عربيًا (بما فيه أرقام/إنجليزي مختلط) للعرض الصحيح داخل PDF."""
    reshaped = arabic_reshaper.reshape(str(text))
    return get_display(reshaped)


def _to_arabic_numerals(s: str) -> str:
    return s.translate(str.maketrans("0123456789.", "٠١٢٣٤٥٦٧٨٩٫"))


def _wrap_arabic_lines(text: str, font_name: str, size: int, max_width: float) -> List[str]:
    """يقسّم نصًا عربيًا طويلًا إلى أسطر متعددة بحيث لا يتجاوز عرض أي سطر max_width،
    مع إعادة تهيئة (reshape) كل سطر على حدة بشكل صحيح."""
    words = text.split(" ")
    lines: List[str] = []
    current = ""
    for w in words:
        candidate = (current + " " + w).strip()
        shaped = shape_arabic(candidate)
        width = pdfmetrics.stringWidth(shaped, font_name, size)
        if width <= max_width or not current:
            current = candidate
        else:
            lines.append(current)
            current = w
    if current:
        lines.append(current)
    return lines


def generate_certificate_pdf(
    user_name: str, exam_name: str, level: str, pct: float, cert_id: int, date_str: str,
    sap_id: str = "",
) -> bytes:
    ensure_arabic_font()
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=landscape(A4))
    W, H = landscape(A4)

    # ==================== باليتة ألوان فاخرة (كحلي / ذهبي / رمادي أنيق) ====================
    NAVY = "#0F2A5C"
    NAVY_SOFT = "#1E3A6B"
    GOLD = "#B8860B"
    GOLD_LIGHT = "#D4A937"
    SLATE = "#374151"
    MUTED = "#8B95A8"

    c.setFillColor(colors.HexColor("#FAF9F5"))
    c.rect(0, 0, W, H, fill=1, stroke=0)

    # إطار مزدوج أنيق: كحلي خارجي سميك + ذهبي داخلي رفيع
    c.setStrokeColor(colors.HexColor(NAVY))
    c.setLineWidth(3.2)
    c.rect(0.9 * cm, 0.9 * cm, W - 1.8 * cm, H - 1.8 * cm, fill=0, stroke=1)
    c.setStrokeColor(colors.HexColor(GOLD))
    c.setLineWidth(1)
    c.rect(1.25 * cm, 1.25 * cm, W - 2.5 * cm, H - 2.5 * cm, fill=0, stroke=1)

    # زخارف الزوايا الذهبية (لمسة فاخرة مميزة)
    def draw_corner(x: float, y: float, hx: int, hy: int, length: float = 1.5 * cm):
        c.setStrokeColor(colors.HexColor(GOLD))
        c.setLineWidth(2.4)
        c.line(x, y, x + hx * length, y)
        c.line(x, y, x, y + hy * length)

    draw_corner(1.7 * cm, H - 1.7 * cm, 1, -1)
    draw_corner(W - 1.7 * cm, H - 1.7 * cm, -1, -1)
    draw_corner(1.7 * cm, 1.7 * cm, 1, 1)
    draw_corner(W - 1.7 * cm, 1.7 * cm, -1, 1)

    # --- اللوجوهات: أعلى اليسار وأعلى اليمين (مساحة أكبر) ---
    logo_size = 4.2 * cm
    logo_y = H - 1.7 * cm - logo_size
    logo1_path = _find_asset_image("logo 1", "logo1", "Logo 1", "Logo1")
    logo2_path = _find_asset_image("logo 2", "logo2", "Logo 2", "Logo2")
    if logo1_path:
        try:
            c.drawImage(
                ImageReader(str(logo1_path)), 2 * cm, logo_y,
                width=logo_size, height=logo_size,
                preserveAspectRatio=True, anchor="c", mask="auto",
            )
        except Exception:
            pass
    if logo2_path:
        try:
            c.drawImage(
                ImageReader(str(logo2_path)), W - 2 * cm - logo_size, logo_y,
                width=logo_size, height=logo_size,
                preserveAspectRatio=True, anchor="c", mask="auto",
            )
        except Exception:
            pass

    # --- صورة صاحب الشهادة: مستطيلة على الجانب الأيسر بإطار ذهبي فاخر ---
    photo_path = _find_asset_image(sap_id) if sap_id else None
    photo_w, photo_h = 4.8 * cm, 6.4 * cm
    photo_x = 2.2 * cm
    photo_y = 6.4 * cm
    if photo_path:
        try:
            c.saveState()
            c.setFillColor(colors.white)
            c.roundRect(
                photo_x - 0.18 * cm, photo_y - 0.18 * cm,
                photo_w + 0.36 * cm, photo_h + 0.36 * cm,
                0.25 * cm, fill=1, stroke=0,
            )
            c.drawImage(
                ImageReader(str(photo_path)), photo_x, photo_y,
                width=photo_w, height=photo_h,
                preserveAspectRatio=True, anchor="c", mask="auto",
            )
            c.setStrokeColor(colors.HexColor(GOLD))
            c.setLineWidth(2)
            c.roundRect(photo_x, photo_y, photo_w, photo_h, 0.15 * cm, fill=0, stroke=1)
            c.setStrokeColor(colors.HexColor(NAVY))
            c.setLineWidth(0.7)
            c.roundRect(
                photo_x - 0.18 * cm, photo_y - 0.18 * cm,
                photo_w + 0.36 * cm, photo_h + 0.36 * cm,
                0.28 * cm, fill=0, stroke=1,
            )
            c.restoreState()
        except Exception:
            photo_path = None

    # لو فيه صورة شخصية على اليسار، بننقل مركز النص لليمين شوية عشان مايتقابلش معاها
    text_center_x = ((photo_x + photo_w + 2.3 * cm) + (W - 2 * cm)) / 2 if photo_path else W / 2
    text_max_width = (W - 2.2 * cm) - (photo_x + photo_w + 2.3 * cm) if photo_path else (W - 5 * cm)

    def draw_center(text: str, size: int, y: float, color: str = SLATE, cx: float = None):
        c.setFont("Amiri", size)
        c.setFillColor(colors.HexColor(color))
        shaped = shape_arabic(text)
        tw = c.stringWidth(shaped, "Amiri", size)
        center = cx if cx is not None else text_center_x
        x = center - tw / 2
        c.drawString(x, y, shaped)

    def draw_center_thick(text: str, size: int, y: float, color: str = NAVY, cx: float = None, font: str = "Amiri"):
        """نص عريض وسميك. لو الخط المُمرَّر أصلًا Bold/مميز (زي NameFont) بيترسم مرة واحدة بس؛
        ولو خط عادي (Amiri) بيتحاكى السُّمك برسمه عدة مرات بإزاحات دقيقة."""
        c.setFont(font, size)
        c.setFillColor(colors.HexColor(color))
        shaped = shape_arabic(text)
        tw = c.stringWidth(shaped, font, size)
        center = cx if cx is not None else text_center_x
        x = center - tw / 2
        if font == "Amiri":
            for dx, dy in [(0, 0), (0.65, 0), (-0.65, 0), (0, 0.5), (0, -0.5), (0.45, 0.35), (-0.45, -0.35), (0.45, -0.35), (-0.45, 0.35)]:
                c.drawString(x + dx, y + dy, shaped)
        else:
            c.drawString(x, y, shaped)
            c.drawString(x + 0.4, y, shaped)  # لمسة سُمك بسيطة حتى مع الخط المميز

    def draw_diamond(cx: float, cy: float, r: float, color: str):
        c.setFillColor(colors.HexColor(color))
        p = c.beginPath()
        p.moveTo(cx, cy + r)
        p.lineTo(cx + r, cy)
        p.lineTo(cx, cy - r)
        p.lineTo(cx - r, cy)
        p.close()
        c.drawPath(p, fill=1, stroke=0)

    def _measure(text: str, size: float, font: str = "Amiri") -> tuple:
        shaped = shape_arabic(text)
        return shaped, c.stringWidth(shaped, font, size)

    def draw_rtl_segments(segments, y: float, max_width: float, cx: float = None):
        """يرسم سطرًا من عدة أجزاء بألوان/أوزان/خطوط مختلفة، مرتبة من اليمين لليسار
        (الجزء الأول في القراءة يكون أقصى اليمين)، مع تصغير تلقائي للخط لو النص طويل
        عشان يفضل في سطر واحد زي ما هو مطلوب بالظبط.
        كل جزء (segment) عبارة عن: (نص, حجم, لون, سميك؟, اسم_الخط)."""
        center = cx if cx is not None else text_center_x
        scale = 1.0
        rendered = []
        while True:
            rendered = []
            total_w = 0.0
            for text, size, color, thick, font in segments:
                sz = size * scale
                shaped, w = _measure(text, sz, font)
                rendered.append((shaped, sz, color, thick, font, w))
                total_w += w
            if total_w <= max_width or scale <= 0.55:
                break
            scale -= 0.05
        x_right = center + total_w / 2
        for shaped, sz, color, thick, font, w in rendered:
            x_left = x_right - w
            c.setFont(font, sz)
            c.setFillColor(colors.HexColor(color))
            if thick and font == "Amiri":
                for dx, dy in [(0, 0), (0.55, 0), (-0.55, 0), (0, 0.4), (0, -0.4), (0.4, 0.3), (-0.4, -0.3)]:
                    c.drawString(x_left + dx, y + dy, shaped)
            elif thick:
                c.drawString(x_left, y, shaped)
                c.drawString(x_left + 0.35, y, shaped)
            else:
                c.drawString(x_left, y, shaped)
            x_right -= w
        return scale

    # ==================== محتوى الشهادة: 6 أسطر ثابتة بألوان مميزة لكل عنصر ====================
    NAME_COLOR = "#9F1239"      # اسم الزميل واسم الدورة: لون مميز (خمري) وخط مميز
    LEVEL_COLOR = "#047857"     # المستوى والنسبة: أخضر زمردي (بدون سماكة)

    _name_font = "NameFont" if _name_font_available() else "Amiri"
    _name_size = 31 if _name_font == "NameFont" else 29

    y = H - 5.5 * cm  # بداية الكلام مرفوعة لأعلى قليلًا

    draw_center_thick("شهادة اجتياز", 38, y, NAVY)
    y -= 1.85 * cm

    # فاصل مزخرف: خط ذهبي مزدوج + معين صغير في المنتصف
    c.setStrokeColor(colors.HexColor(GOLD))
    c.setLineWidth(1.4)
    c.line(text_center_x - 3.4 * cm, y, text_center_x - 0.28 * cm, y)
    c.line(text_center_x + 0.28 * cm, y, text_center_x + 3.4 * cm, y)
    draw_diamond(text_center_x, y, 0.16 * cm, GOLD)
    y -= 1.1 * cm

    # السطر الأول: يسر شركة العربي المتحدة...
    draw_rtl_segments(
        [("يسر شركة العربي المتحدة للاستثمار الصناعي والتجاري - مصنع فوم بنها", 14.5, SLATE, False, "Amiri")],
        y, text_max_width,
    )
    y -= 0.78 * cm

    # السطر الثاني: منح هذه الشهادة إلى الزميل الفاضل /
    draw_rtl_segments(
        [("منح هذه الشهادة إلى الزميل الفاضل /", 15.5, SLATE, False, "Amiri")],
        y, text_max_width,
    )
    y -= 1.4 * cm  # مسافة أكبر شوية قبل الاسم عشان ميبقاش ملتصق بالسطر اللي قبله

    # السطر الثالث: اسم الزميل (لون مميز وخط مميز)
    for line in _wrap_arabic_lines(user_name, _name_font, _name_size, text_max_width):
        draw_center_thick(line, _name_size, y, NAME_COLOR, font=_name_font)
        y -= 1.42 * cm

    y -= 0.15 * cm

    # السطر الرابع: وذلك لاجتيازه دورة / اسم الدورة (بنفس خط ولون الاسم)
    draw_rtl_segments(
        [
            ("وذلك لاجتيازه دورة / ", 15, SLATE, False, "Amiri"),
            (exam_name, _name_size - 10 if _name_font == "NameFont" else 16, NAME_COLOR, True, _name_font),
        ],
        y, text_max_width,
    )
    y -= 0.95 * cm

    # السطر الخامس: والحصول على مستوى / ... ونسبة / ... (مميز باللون فقط، من غير سماكة، والنسبة بأرقام عربية)
    draw_rtl_segments(
        [
            ("والحصول على مستوى / ", 15, SLATE, False, "Amiri"),
            (level, 15.5, LEVEL_COLOR, False, "Amiri"),
            ("  ونسبة / ", 15, SLATE, False, "Amiri"),
            (_to_arabic_numerals(f"{pct:.1f}") + "٪", 15.5, LEVEL_COLOR, False, "Amiri"),
        ],
        y, text_max_width,
    )
    y -= 0.95 * cm

    # السطر السادس: متمنين له دوام التوفيق والنجاح (بنفس لون النص الطبيعي)
    draw_rtl_segments(
        [("متمنين له دوام التوفيق والنجاح", 14.5, SLATE, False, "Amiri")],
        y, text_max_width,
    )
    y -= 0.85 * cm

    draw_center(f"بتاريخ: {date_str[:10]}", 12.5, y, MUTED)

    draw_center(f"رقم الشهادة: {cert_id}", 11, 1.8 * cm, MUTED, cx=W / 2)

    # --- اعتماد المدير: صورة توقيع/ختم أسفل يسار الشهادة (اختيارية) ---
    manager_sig_path = _find_asset_image(
        "manager signature", "director signature", "signature",
        "توقيع المدير", "اعتماد المدير", "Manager Signature",
    )
    if manager_sig_path:
        try:
            sig_w, sig_h = 4.0 * cm, 2.2 * cm
            sig_x = 2.3 * cm
            sig_y = 2.6 * cm
            c.drawImage(
                ImageReader(str(manager_sig_path)), sig_x, sig_y,
                width=sig_w, height=sig_h,
                preserveAspectRatio=True, anchor="c", mask="auto",
            )
            c.setStrokeColor(colors.HexColor(GOLD))
            c.setLineWidth(1.2)
            c.line(sig_x, sig_y - 0.15 * cm, sig_x + sig_w, sig_y - 0.15 * cm)
            draw_center("اعتماد المدير", 10.5, sig_y - 0.62 * cm, MUTED, cx=sig_x + sig_w / 2)
        except Exception:
            pass

    c.showPage()
    c.save()
    return buf.getvalue()


def _arabic_ordinal(n: int) -> str:
    """يحوّل رقم ترتيب إلى صيغة عربية (المركز الأول، الثاني...) لعرضها في شهادة التقدير."""
    words = {
        1: "المركز الأول", 2: "المركز الثاني", 3: "المركز الثالث", 4: "المركز الرابع",
        5: "المركز الخامس", 6: "المركز السادس", 7: "المركز السابع", 8: "المركز الثامن",
        9: "المركز التاسع", 10: "المركز العاشر",
    }
    return words.get(n, f"المركز رقم {_to_arabic_numerals(str(n))}")


def generate_appreciation_certificate_pdf(
    user_name: str, reason_text: str, cert_id: int, date_str: str, sap_id: str = "",
    rank_type: str = "none", exam_name: str = None, rank_value: int = None,
) -> bytes:
    """شهادة تقدير (مختلفة عن شهادة الاجتياز) — تُمنح لأفراد يحددهم الأدمن مع نص تقدير حر،
    بنفس الإطار والتصميم الفاخر لشهادة الاجتياز، مع إمكانية إظهار ترتيب الفرد
    في دورة معينة أو ترتيبه العام."""
    ensure_arabic_font()
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=landscape(A4))
    W, H = landscape(A4)

    NAVY = "#0F2A5C"
    GOLD = "#B8860B"
    SLATE = "#374151"
    MUTED = "#8B95A8"

    c.setFillColor(colors.HexColor("#FAF9F5"))
    c.rect(0, 0, W, H, fill=1, stroke=0)

    c.setStrokeColor(colors.HexColor(NAVY))
    c.setLineWidth(3.2)
    c.rect(0.9 * cm, 0.9 * cm, W - 1.8 * cm, H - 1.8 * cm, fill=0, stroke=1)
    c.setStrokeColor(colors.HexColor(GOLD))
    c.setLineWidth(1)
    c.rect(1.25 * cm, 1.25 * cm, W - 2.5 * cm, H - 2.5 * cm, fill=0, stroke=1)

    def draw_corner(x: float, y: float, hx: int, hy: int, length: float = 1.5 * cm):
        c.setStrokeColor(colors.HexColor(GOLD))
        c.setLineWidth(2.4)
        c.line(x, y, x + hx * length, y)
        c.line(x, y, x, y + hy * length)

    draw_corner(1.7 * cm, H - 1.7 * cm, 1, -1)
    draw_corner(W - 1.7 * cm, H - 1.7 * cm, -1, -1)
    draw_corner(1.7 * cm, 1.7 * cm, 1, 1)
    draw_corner(W - 1.7 * cm, 1.7 * cm, -1, 1)

    logo_size = 4.2 * cm
    logo_y = H - 1.7 * cm - logo_size
    logo1_path = _find_asset_image("logo 1", "logo1", "Logo 1", "Logo1")
    logo2_path = _find_asset_image("logo 2", "logo2", "Logo 2", "Logo2")
    if logo1_path:
        try:
            c.drawImage(ImageReader(str(logo1_path)), 2 * cm, logo_y, width=logo_size, height=logo_size,
                        preserveAspectRatio=True, anchor="c", mask="auto")
        except Exception:
            pass
    if logo2_path:
        try:
            c.drawImage(ImageReader(str(logo2_path)), W - 2 * cm - logo_size, logo_y, width=logo_size, height=logo_size,
                        preserveAspectRatio=True, anchor="c", mask="auto")
        except Exception:
            pass

    photo_path = _find_asset_image(sap_id) if sap_id else None
    photo_w, photo_h = 4.8 * cm, 6.4 * cm
    photo_x = 2.2 * cm
    photo_y = 6.4 * cm
    if photo_path:
        try:
            c.saveState()
            c.setFillColor(colors.white)
            c.roundRect(photo_x - 0.18 * cm, photo_y - 0.18 * cm, photo_w + 0.36 * cm, photo_h + 0.36 * cm,
                        0.25 * cm, fill=1, stroke=0)
            c.drawImage(ImageReader(str(photo_path)), photo_x, photo_y, width=photo_w, height=photo_h,
                        preserveAspectRatio=True, anchor="c", mask="auto")
            c.setStrokeColor(colors.HexColor(GOLD))
            c.setLineWidth(2)
            c.roundRect(photo_x, photo_y, photo_w, photo_h, 0.15 * cm, fill=0, stroke=1)
            c.setStrokeColor(colors.HexColor(NAVY))
            c.setLineWidth(0.7)
            c.roundRect(photo_x - 0.18 * cm, photo_y - 0.18 * cm, photo_w + 0.36 * cm, photo_h + 0.36 * cm,
                        0.28 * cm, fill=0, stroke=1)
            c.restoreState()
        except Exception:
            photo_path = None

    text_center_x = ((photo_x + photo_w + 2.3 * cm) + (W - 2 * cm)) / 2 if photo_path else W / 2
    text_max_width = (W - 2.2 * cm) - (photo_x + photo_w + 2.3 * cm) if photo_path else (W - 5 * cm)

    def draw_center(text: str, size: int, y: float, color: str = SLATE, cx: float = None):
        c.setFont("Amiri", size)
        c.setFillColor(colors.HexColor(color))
        shaped = shape_arabic(text)
        tw = c.stringWidth(shaped, "Amiri", size)
        center = cx if cx is not None else text_center_x
        c.drawString(center - tw / 2, y, shaped)

    def draw_center_thick(text: str, size: int, y: float, color: str = NAVY, cx: float = None, font: str = "Amiri"):
        c.setFont(font, size)
        c.setFillColor(colors.HexColor(color))
        shaped = shape_arabic(text)
        tw = c.stringWidth(shaped, font, size)
        center = cx if cx is not None else text_center_x
        x = center - tw / 2
        if font == "Amiri":
            for dx, dy in [(0, 0), (0.65, 0), (-0.65, 0), (0, 0.5), (0, -0.5), (0.45, 0.35), (-0.45, -0.35), (0.45, -0.35), (-0.45, 0.35)]:
                c.drawString(x + dx, y + dy, shaped)
        else:
            c.drawString(x, y, shaped)
            c.drawString(x + 0.4, y, shaped)

    def draw_diamond(cx: float, cy: float, r: float, color: str):
        c.setFillColor(colors.HexColor(color))
        p = c.beginPath()
        p.moveTo(cx, cy + r); p.lineTo(cx + r, cy); p.lineTo(cx, cy - r); p.lineTo(cx - r, cy); p.close()
        c.drawPath(p, fill=1, stroke=0)

    NAME_COLOR = "#9F1239"
    _name_font = "NameFont" if _name_font_available() else "Amiri"
    _name_size = 31 if _name_font == "NameFont" else 29

    y = H - 5.5 * cm
    draw_center_thick("شهادة تقدير", 38, y, NAVY)
    y -= 1.85 * cm

    c.setStrokeColor(colors.HexColor(GOLD))
    c.setLineWidth(1.4)
    c.line(text_center_x - 3.4 * cm, y, text_center_x - 0.28 * cm, y)
    c.line(text_center_x + 0.28 * cm, y, text_center_x + 3.4 * cm, y)
    draw_diamond(text_center_x, y, 0.16 * cm, GOLD)
    y -= 1.1 * cm

    for line in _wrap_arabic_lines(
        "تتقدم شركة العربي المتحدة للاستثمار الصناعي والتجاري - مصنع فوم بنها بخالص الشكر والتقدير إلى الزميل الفاضل /",
        "Amiri", 14.5, text_max_width,
    ):
        draw_center(line, 14.5, y, SLATE)
        y -= 0.7 * cm
    y -= 0.5 * cm

    for line in _wrap_arabic_lines(user_name, _name_font, _name_size, text_max_width):
        draw_center_thick(line, _name_size, y, NAME_COLOR, font=_name_font)
        y -= 1.42 * cm
    y -= 0.25 * cm

    for line in _wrap_arabic_lines(reason_text, "Amiri", 15, text_max_width):
        draw_center(line, 15, y, SLATE)
        y -= 0.75 * cm
    y -= 0.15 * cm

    # سطر الترتيب (لو محدد) — في دورة معينة أو الترتيب العام عبر كل الدورات
    if rank_type in ("exam", "general") and rank_value:
        ordinal = _arabic_ordinal(rank_value)
        if rank_type == "exam" and exam_name:
            rank_line = f"حاصل على {ordinal} على دورة / {exam_name}"
        else:
            rank_line = f"حاصل على {ordinal} على الترتيب العام لكل الدورات"
        for line in _wrap_arabic_lines(rank_line, "Amiri", 15, text_max_width):
            draw_center_thick(line, 15, y, "#047857")
            y -= 0.78 * cm
        y -= 0.2 * cm

    draw_center("مع خالص الشكر والتقدير", 14, y, "#92400E")
    y -= 0.85 * cm

    draw_center(f"بتاريخ: {date_str[:10]}", 12.5, y, MUTED)
    draw_center(f"رقم الشهادة: {cert_id}", 11, 1.8 * cm, MUTED, cx=W / 2)

    manager_sig_path = _find_asset_image(
        "manager signature", "director signature", "signature", "توقيع المدير", "اعتماد المدير", "Manager Signature",
    )
    if manager_sig_path:
        try:
            sig_w, sig_h = 4.0 * cm, 2.2 * cm
            sig_x, sig_y = 2.3 * cm, 2.6 * cm
            c.drawImage(ImageReader(str(manager_sig_path)), sig_x, sig_y, width=sig_w, height=sig_h,
                        preserveAspectRatio=True, anchor="c", mask="auto")
            c.setStrokeColor(colors.HexColor(GOLD))
            c.setLineWidth(1.2)
            c.line(sig_x, sig_y - 0.15 * cm, sig_x + sig_w, sig_y - 0.15 * cm)
            draw_center("اعتماد المدير", 10.5, sig_y - 0.62 * cm, MUTED, cx=sig_x + sig_w / 2)
        except Exception:
            pass

    c.showPage()
    c.save()
    return buf.getvalue()


def _compute_exam_rank(sap_id: str, exam_id: int) -> Optional[int]:
    """يحسب ترتيب فرد داخل امتحان معيّن (بأعلى محاولة له)، بنفس منطق لوحة شرف الامتحان."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "SELECT s.sap_id, s.total_pct, s.submitted_at FROM submissions s WHERE s.exam_id = %s AND COALESCE(s.hidden, 0) = 0"
        if is_pg
        else "SELECT s.sap_id, s.total_pct, s.submitted_at FROM submissions s WHERE s.exam_id = ? AND COALESCE(s.hidden, 0) = 0"
    )
    c.execute(q, (exam_id,))
    rows = c.fetchall()
    conn.close()

    best_by_sap: Dict[str, tuple] = {}
    for r_sap, pct, submitted_at in rows:
        if r_sap not in best_by_sap or pct > best_by_sap[r_sap][0] or (
            pct == best_by_sap[r_sap][0] and str(submitted_at) < str(best_by_sap[r_sap][1])
        ):
            best_by_sap[r_sap] = (pct, submitted_at)

    ranked = sorted(best_by_sap.items(), key=lambda kv: (-kv[1][0], str(kv[1][1])))
    for i, (r_sap, _) in enumerate(ranked):
        if r_sap == sap_id:
            return i + 1
    return None


def _compute_general_rank(sap_id: str) -> Optional[int]:
    """يحسب الترتيب العام لفرد عبر كل الدورات، بنفس منطق لوحة الشرف العامة."""
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("""SELECT s.sap_id, s.exam_id, s.total_pct
                 FROM submissions s
                 LEFT JOIN exams e ON s.exam_id = e.id
                 WHERE COALESCE(s.hidden, 0) = 0 AND COALESCE(e.hide_leaderboard, 0) = 0""")
    rows = c.fetchall()
    conn.close()

    best_per_person_exam: Dict[tuple, float] = {}
    for r_sap, exam_id, pct in rows:
        key = (r_sap, exam_id)
        if key not in best_per_person_exam or pct > best_per_person_exam[key]:
            best_per_person_exam[key] = pct

    person_bests: Dict[str, List[float]] = {}
    for (r_sap, exam_id), pct in best_per_person_exam.items():
        person_bests.setdefault(r_sap, []).append(pct)

    results = [(r_sap, sum(pcts) / len(pcts), len(pcts)) for r_sap, pcts in person_bests.items()]
    results.sort(key=lambda x: (-x[1], -x[2]))

    for i, (r_sap, _, _) in enumerate(results):
        if r_sap == sap_id:
            return i + 1
    return None


@app.get("/api/admin/appreciation/list")
async def list_appreciation_certificates(_admin: Dict[str, object] = Depends(require_permission("appreciation"))):
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute("""SELECT id, sap_id, user_name, reason_text, granted_by, rank_type, exam_name, rank_value, created_at
                 FROM appreciation_certificates ORDER BY id DESC""")
    rows = c.fetchall()
    conn.close()
    return [
        {
            "id": r[0], "sap_id": r[1], "user_name": r[2], "reason_text": r[3], "granted_by": r[4],
            "rank_type": r[5] or "none", "exam_name": r[6], "rank_value": r[7], "created_at": str(r[8]),
        }
        for r in rows
    ]


@app.get("/api/admin/appreciation/exams-list")
async def list_exams_for_appreciation(_admin: Dict[str, object] = Depends(require_permission("appreciation"))):
    """قائمة مبسطة بأسماء الدورات لتعبئة قائمة الاختيار عند منح شهادة تقدير مرتبطة بترتيب في دورة معينة."""
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name FROM exams ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1]} for r in rows]


@app.get("/api/admin/appreciation/preview-rank")
async def preview_appreciation_rank(
    sap_id: str, rank_type: str, exam_id: Optional[int] = None,
    _admin: Dict[str, object] = Depends(require_permission("appreciation")),
):
    """يعرض للأدمن ترتيب الفرد قبل ما يمنح الشهادة، عشان يتأكد من الرقم قبل التوليد."""
    sap_id = sap_id.strip()
    if rank_type == "exam":
        if not exam_id:
            raise HTTPException(status_code=400, detail="من فضلك اختر الدورة.")
        rank = _compute_exam_rank(sap_id, exam_id)
    elif rank_type == "general":
        rank = _compute_general_rank(sap_id)
    else:
        rank = None
    return {"rank": rank}


@app.post("/api/admin/appreciation/grant")
async def grant_appreciation_certificate(
    sap_id: str = Form(...),
    reason_text: str = Form(...),
    rank_type: str = Form("none"),
    exam_id: Optional[int] = Form(None),
    admin: Dict[str, object] = Depends(require_permission("appreciation")),
):
    """يمنح شهادة تقدير لفرد يحدده الأدمن، بنص تقدير حر، مع إمكانية إظهار ترتيبه
    في دورة معينة أو ترتيبه العام عبر كل الدورات (يُحسب ويُثبَّت وقت المنح)."""
    sap_id = sap_id.strip()
    reason_text = reason_text.strip()
    if not reason_text:
        raise HTTPException(status_code=400, detail="من فضلك اكتب نص التقدير.")
    if rank_type not in ("none", "exam", "general"):
        raise HTTPException(status_code=400, detail="نوع الترتيب غير صحيح.")

    conn, is_pg = get_db()
    c = conn.cursor()
    q_user = "SELECT name FROM users WHERE sap_id = %s" if is_pg else "SELECT name FROM users WHERE sap_id = ?"
    c.execute(q_user, (sap_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="رقم الساب غير موجود بين المستخدمين.")
    user_name = row[0]

    exam_name = None
    rank_value = None
    if rank_type == "exam":
        if not exam_id:
            conn.close()
            raise HTTPException(status_code=400, detail="من فضلك اختر الدورة لعرض ترتيب الفرد فيها.")
        q_exam = "SELECT name FROM exams WHERE id = %s" if is_pg else "SELECT name FROM exams WHERE id = ?"
        c.execute(q_exam, (exam_id,))
        exam_row = c.fetchone()
        if not exam_row:
            conn.close()
            raise HTTPException(status_code=404, detail="الدورة غير موجودة.")
        exam_name = exam_row[0]
        rank_value = _compute_exam_rank(sap_id, exam_id)
        if rank_value is None:
            conn.close()
            raise HTTPException(status_code=400, detail="هذا الفرد ليس له نتيجة مسجّلة في هذه الدورة.")
    elif rank_type == "general":
        rank_value = _compute_general_rank(sap_id)
        if rank_value is None:
            conn.close()
            raise HTTPException(status_code=400, detail="هذا الفرد ليس له أي نتائج مسجّلة بعد لحساب ترتيبه العام.")

    q_ins = (
        """INSERT INTO appreciation_certificates
           (sap_id, user_name, reason_text, granted_by, rank_type, exam_id, exam_name, rank_value)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
        if is_pg
        else """INSERT INTO appreciation_certificates
           (sap_id, user_name, reason_text, granted_by, rank_type, exam_id, exam_name, rank_value)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
    )
    c.execute(q_ins, (sap_id, user_name, reason_text, admin.get("sap_id"), rank_type, exam_id, exam_name, rank_value))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم منح شهادة تقدير لـ {user_name}.", "rank_value": rank_value}


@app.delete("/api/admin/appreciation/{cert_id}")
async def delete_appreciation_certificate(
    cert_id: int, _admin: Dict[str, object] = Depends(require_permission("appreciation"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = "DELETE FROM appreciation_certificates WHERE id = %s" if is_pg else "DELETE FROM appreciation_certificates WHERE id = ?"
    c.execute(q, (cert_id,))
    conn.commit()
    conn.close()
    return {"status": "success"}


@app.get("/api/admin/appreciation/{cert_id}/download")
async def download_appreciation_certificate(
    cert_id: int, _admin: Dict[str, object] = Depends(require_permission("appreciation"))
):
    """تنزيل شهادة التقدير كملف PDF — متاح للأدمن المركزي فقط أو لمن يمنحه صلاحية 'appreciation'."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """SELECT sap_id, user_name, reason_text, created_at, rank_type, exam_name, rank_value
           FROM appreciation_certificates WHERE id = %s""" if is_pg
        else """SELECT sap_id, user_name, reason_text, created_at, rank_type, exam_name, rank_value
           FROM appreciation_certificates WHERE id = ?"""
    )
    c.execute(q, (cert_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="شهادة التقدير غير موجودة.")
    sap_id, user_name, reason_text, created_at, rank_type, exam_name, rank_value = row
    try:
        pdf_bytes = generate_appreciation_certificate_pdf(
            user_name, reason_text, cert_id, str(created_at), sap_id.strip(),
            rank_type=rank_type or "none", exam_name=exam_name, rank_value=rank_value,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"تعذّر توليد ملف الشهادة: {e}")
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=appreciation_certificate_{cert_id}.pdf"},
    )


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


@app.get("/manifest.json")
def serve_manifest():
    """ملف PWA — بيسمح بتثبيت المنصة كتطبيق على الشاشة الرئيسية للموبايل."""
    manifest = {
        "name": "منصة التدريب والتقييم الفني - فوم بنها",
        "short_name": "فوم بنها TPM",
        "description": "منصة موحّدة لتنمية وتقييم مهارات فرق العمل في الصيانة الإنتاجية الشاملة",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "orientation": "portrait-primary",
        "background_color": "#f4f5fb",
        "theme_color": "#4f46e5",
        "dir": "rtl",
        "lang": "ar",
        "icons": [
            {"src": "/api/public/site-image/site-icon-192", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
            {"src": "/api/public/site-image/site-icon-512", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
        ],
    }
    return Response(content=json.dumps(manifest, ensure_ascii=False), media_type="application/manifest+json")


@app.get("/sw.js")
def serve_service_worker():
    """Service Worker بسيط — شرط أساسي عند أندرويد/كروم لإظهار اقتراح التثبيت التلقائي."""
    sw_code = """
const CACHE_NAME = 'tpm-platform-v1';
self.addEventListener('install', (event) => { self.skipWaiting(); });
self.addEventListener('activate', (event) => { self.clients.claim(); });
self.addEventListener('fetch', (event) => {
    // استراتيجية شبكة أولاً (Network First) — يضمن دايمًا آخر نسخة من المنصة،
    // مع رجوع بسيط للكاش لو الاتصال انقطع مؤقتًا
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});
"""
    return Response(content=sw_code, media_type="application/javascript")


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
    if is_maintenance_mode():
        conn.close()
        raise HTTPException(
            status_code=503,
            detail="النظام تحت الصيانة حاليًا لتحديث البرنامج، برجاء المحاولة لاحقًا.",
        )
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


@app.post("/api/admin/admins/{sap_id}/update")
async def update_sub_admin(
    sap_id: str,
    name: str = Form(...),
    email: str = Form(...),
    permissions: str = Form("[]"),
    password: Optional[str] = Form(None),
    _admin: Dict[str, object] = Depends(get_current_super_admin),
):
    """يسمح للأدمن المركزي بتعديل بيانات وصلاحيات حساب مدير عادي موجود.
    كلمة المرور اختيارية: تُترك فارغة للإبقاء على كلمة المرور الحالية."""
    try:
        perms_list = json.loads(permissions) if permissions else []
        perms_list = [p for p in perms_list if p in ADMIN_PERMISSION_KEYS]
    except Exception:
        perms_list = []

    conn, is_pg = get_db()
    c = conn.cursor()

    if password and password.strip():
        q = (
            "UPDATE admins SET name = %s, email = %s, permissions = %s, password = %s WHERE sap_id = %s"
            if is_pg
            else "UPDATE admins SET name = ?, email = ?, permissions = ?, password = ? WHERE sap_id = ?"
        )
        c.execute(q, (
            name.strip(), email.strip().lower(), json.dumps(perms_list, ensure_ascii=False),
            hash_password(password.strip()), sap_id.strip(),
        ))
    else:
        q = (
            "UPDATE admins SET name = %s, email = %s, permissions = %s WHERE sap_id = %s"
            if is_pg
            else "UPDATE admins SET name = ?, email = ?, permissions = ? WHERE sap_id = ?"
        )
        c.execute(q, (
            name.strip(), email.strip().lower(), json.dumps(perms_list, ensure_ascii=False), sap_id.strip(),
        ))

    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث بيانات وصلاحيات المدير بنجاح."}


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
    if is_maintenance_mode():
        raise HTTPException(
            status_code=503,
            detail="النظام تحت الصيانة حاليًا لتحديث البرنامج، برجاء المحاولة لاحقًا.",
        )
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


# ==================== المحتوى التدريبي (تدريب / تعليمات وخرائط) ====================
CONTENT_TABS = ("training", "instructions")
CONTENT_TYPES = ("video", "audio", "pdf")


def _browse_content(tab: str, folder_id: Optional[int], sap_id: Optional[str] = None) -> Dict[str, object]:
    """يرجّع الفولدرات الفرعية والمواد الموجودة داخل مستوى معيّن، مع مسار التنقل (breadcrumb).
    لو اتبعت sap_id (تصفح فرد)، بيضيف حالة المشاهدة/الإنهاء لكل مادة بالنسبة لهذا الفرد.
    لو من غير sap_id (تصفح أدمن)، بيضيف عدد الأفراد اللي أنهوا كل مادة."""
    conn, is_pg = get_db()
    c = conn.cursor()

    if folder_id:
        q_cur = "SELECT id, name FROM content_folders WHERE id = %s" if is_pg else "SELECT id, name FROM content_folders WHERE id = ?"
        c.execute(q_cur, (folder_id,))
        cur = c.fetchone()
        if not cur:
            conn.close()
            raise HTTPException(status_code=404, detail="الفولدر غير موجود.")

    # بناء مسار التنقل (breadcrumb) بالصعود لأعلى حتى الجذر
    breadcrumb = []
    walk_id = folder_id
    while walk_id:
        q_walk = "SELECT id, name, parent_id FROM content_folders WHERE id = %s" if is_pg else "SELECT id, name, parent_id FROM content_folders WHERE id = ?"
        c.execute(q_walk, (walk_id,))
        wr = c.fetchone()
        if not wr:
            break
        breadcrumb.insert(0, {"id": wr[0], "name": wr[1]})
        walk_id = wr[2]

    if folder_id:
        q_folders = "SELECT id, name, description FROM content_folders WHERE tab = %s AND parent_id = %s ORDER BY name ASC" if is_pg else "SELECT id, name, description FROM content_folders WHERE tab = ? AND parent_id = ? ORDER BY name ASC"
        c.execute(q_folders, (tab, folder_id))
    else:
        q_folders = "SELECT id, name, description FROM content_folders WHERE tab = %s AND parent_id IS NULL ORDER BY name ASC" if is_pg else "SELECT id, name, description FROM content_folders WHERE tab = ? AND parent_id IS NULL ORDER BY name ASC"
        c.execute(q_folders, (tab,))
    folders = [{"id": r[0], "name": r[1], "description": r[2]} for r in c.fetchall()]

    if folder_id:
        q_mat = "SELECT id, name, description, content_type, video_url, file_url FROM content_materials WHERE tab = %s AND folder_id = %s ORDER BY name ASC" if is_pg else "SELECT id, name, description, content_type, video_url, file_url FROM content_materials WHERE tab = ? AND folder_id = ? ORDER BY name ASC"
        c.execute(q_mat, (tab, folder_id))
    else:
        q_mat = "SELECT id, name, description, content_type, video_url, file_url FROM content_materials WHERE tab = %s AND folder_id IS NULL ORDER BY name ASC" if is_pg else "SELECT id, name, description, content_type, video_url, file_url FROM content_materials WHERE tab = ? AND folder_id IS NULL ORDER BY name ASC"
        c.execute(q_mat, (tab,))
    materials = [
        {"id": r[0], "name": r[1], "description": r[2], "content_type": r[3], "video_url": r[4], "file_url": r[5]}
        for r in c.fetchall()
    ]

    if materials:
        mat_ids = [m["id"] for m in materials]
        if sap_id:
            placeholders = ",".join(["%s" if is_pg else "?"] * len(mat_ids))
            q_prog = f"SELECT material_id, completed FROM content_progress WHERE sap_id = {'%s' if is_pg else '?'} AND material_id IN ({placeholders})"
            c.execute(q_prog, (sap_id, *mat_ids))
            progress_map = {r[0]: bool(r[1]) for r in c.fetchall()}
            for m in materials:
                m["completed"] = progress_map.get(m["id"], False)
        else:
            placeholders = ",".join(["%s" if is_pg else "?"] * len(mat_ids))
            q_counts = f"SELECT material_id, COUNT(*) FROM content_progress WHERE completed = 1 AND material_id IN ({placeholders}) GROUP BY material_id"
            c.execute(q_counts, tuple(mat_ids))
            counts_map = {r[0]: r[1] for r in c.fetchall()}
            for m in materials:
                m["completed_count"] = counts_map.get(m["id"], 0)

    conn.close()
    return {"breadcrumb": breadcrumb, "folders": folders, "materials": materials}


@app.get("/api/admin/content/browse")
async def admin_browse_content(
    tab: str, folder_id: Optional[int] = None,
    _admin: Dict[str, object] = Depends(require_permission("content")),
):
    if tab not in CONTENT_TABS:
        raise HTTPException(status_code=400, detail="تبويب غير صحيح.")
    return _browse_content(tab, folder_id)


@app.get("/api/admin/content/materials/{material_id}/progress")
async def get_material_progress(
    material_id: int, _admin: Dict[str, object] = Depends(require_permission("content"))
):
    """يرجّع قائمة الأفراد اللي فتحوا/أنهوا مادة تدريبية معيّنة — لتتبع المشاهدة من جهة الأدمن."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """SELECT u.sap_id, u.name, u.department, cp.completed, cp.first_viewed_at, cp.completed_at
           FROM content_progress cp JOIN users u ON cp.sap_id = u.sap_id
           WHERE cp.material_id = %s ORDER BY cp.first_viewed_at DESC"""
        if is_pg
        else """SELECT u.sap_id, u.name, u.department, cp.completed, cp.first_viewed_at, cp.completed_at
           FROM content_progress cp JOIN users u ON cp.sap_id = u.sap_id
           WHERE cp.material_id = ? ORDER BY cp.first_viewed_at DESC"""
    )
    c.execute(q, (material_id,))
    rows = c.fetchall()
    conn.close()
    return [
        {
            "sap_id": r[0], "name": r[1], "department": r[2], "completed": bool(r[3]),
            "first_viewed_at": str(r[4]), "completed_at": str(r[5]) if r[5] else None,
        }
        for r in rows
    ]


@app.post("/api/admin/content/folders")
async def create_content_folder(
    tab: str = Form(...), parent_id: Optional[int] = Form(None),
    name: str = Form(...), description: str = Form(""),
    _admin: Dict[str, object] = Depends(require_permission("content")),
):
    if tab not in CONTENT_TABS:
        raise HTTPException(status_code=400, detail="تبويب غير صحيح.")
    if not name.strip():
        raise HTTPException(status_code=400, detail="اسم الفولدر مطلوب.")
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "INSERT INTO content_folders (tab, parent_id, name, description) VALUES (%s, %s, %s, %s)"
        if is_pg
        else "INSERT INTO content_folders (tab, parent_id, name, description) VALUES (?, ?, ?, ?)"
    )
    c.execute(q, (tab, parent_id, name.strip(), description.strip() or None))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم إنشاء فولدر \"{name.strip()}\"."}


@app.post("/api/admin/content/folders/{folder_id}/rename")
async def rename_content_folder(
    folder_id: int, name: str = Form(...), description: str = Form(""),
    _admin: Dict[str, object] = Depends(require_permission("content")),
):
    if not name.strip():
        raise HTTPException(status_code=400, detail="اسم الفولدر مطلوب.")
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE content_folders SET name = %s, description = %s WHERE id = %s" if is_pg
        else "UPDATE content_folders SET name = ?, description = ? WHERE id = ?"
    )
    c.execute(q, (name.strip(), description.strip() or None, folder_id))
    conn.commit()
    conn.close()
    return {"status": "success"}


def _delete_folder_recursive(c, is_pg: bool, folder_id: int):
    """يمسح الفولدر وكل محتوياته (فولدرات فرعية ومواد) بشكل تكراري، بما فيها ملفات Cloudinary."""
    q_sub = "SELECT id FROM content_folders WHERE parent_id = %s" if is_pg else "SELECT id FROM content_folders WHERE parent_id = ?"
    c.execute(q_sub, (folder_id,))
    for (sub_id,) in c.fetchall():
        _delete_folder_recursive(c, is_pg, sub_id)

    q_mat = "SELECT id, file_public_id FROM content_materials WHERE folder_id = %s" if is_pg else "SELECT id, file_public_id FROM content_materials WHERE folder_id = ?"
    c.execute(q_mat, (folder_id,))
    for mat_id, public_id in c.fetchall():
        if public_id and CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY:
            try:
                cloudinary.uploader.destroy(public_id, resource_type="raw")
            except Exception:
                try:
                    cloudinary.uploader.destroy(public_id, resource_type="video")
                except Exception:
                    pass
    q_del_mat = "DELETE FROM content_materials WHERE folder_id = %s" if is_pg else "DELETE FROM content_materials WHERE folder_id = ?"
    c.execute(q_del_mat, (folder_id,))
    q_del_folder = "DELETE FROM content_folders WHERE id = %s" if is_pg else "DELETE FROM content_folders WHERE id = ?"
    c.execute(q_del_folder, (folder_id,))


@app.delete("/api/admin/content/folders/{folder_id}")
async def delete_content_folder(
    folder_id: int, _admin: Dict[str, object] = Depends(require_permission("content"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    _delete_folder_recursive(c, is_pg, folder_id)
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف الفولدر وكل محتوياته."}


@app.post("/api/admin/content/materials")
async def create_content_material(
    tab: str = Form(...), folder_id: Optional[int] = Form(None),
    name: str = Form(...), description: str = Form(""),
    content_type: str = Form(...), video_url: str = Form(""),
    file: Optional[UploadFile] = File(None),
    _admin: Dict[str, object] = Depends(require_permission("content")),
):
    if tab not in CONTENT_TABS:
        raise HTTPException(status_code=400, detail="تبويب غير صحيح.")
    if content_type not in CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="نوع المحتوى غير صحيح.")
    if not name.strip():
        raise HTTPException(status_code=400, detail="اسم المادة مطلوب.")

    final_video_url = None
    file_url = None
    file_public_id = None

    if content_type == "video":
        if not video_url.strip():
            raise HTTPException(status_code=400, detail="من فضلك أدخل رابط فيديو اليوتيوب.")
        final_video_url = video_url.strip()
    else:
        if not file:
            raise HTTPException(status_code=400, detail="من فضلك ارفع الملف.")
        if not (CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY):
            raise HTTPException(status_code=500, detail="خدمة تخزين الملفات (Cloudinary) غير مُفعّلة على السيرفر.")
        contents = await file.read()
        resource_type = "video" if content_type == "audio" else "raw"  # كلاوديناري بيتعامل مع الصوت كـ video
        try:
            upload_res = cloudinary.uploader.upload(
                contents, folder="tpm_training_content", resource_type=resource_type,
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"فشل رفع الملف: {e}")
        file_url = upload_res.get("secure_url")
        file_public_id = upload_res.get("public_id")

    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """INSERT INTO content_materials (tab, folder_id, name, description, content_type, video_url, file_url, file_public_id)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
        if is_pg
        else """INSERT INTO content_materials (tab, folder_id, name, description, content_type, video_url, file_url, file_public_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
    )
    c.execute(q, (tab, folder_id, name.strip(), description.strip() or None, content_type, final_video_url, file_url, file_public_id))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم إضافة \"{name.strip()}\"."}


@app.delete("/api/admin/content/materials/{material_id}")
async def delete_content_material(
    material_id: int, _admin: Dict[str, object] = Depends(require_permission("content"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q_sel = "SELECT file_public_id, content_type FROM content_materials WHERE id = %s" if is_pg else "SELECT file_public_id, content_type FROM content_materials WHERE id = ?"
    c.execute(q_sel, (material_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="المادة غير موجودة.")
    public_id, content_type = row
    if public_id and CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY:
        try:
            resource_type = "video" if content_type == "audio" else "raw"
            cloudinary.uploader.destroy(public_id, resource_type=resource_type)
        except Exception:
            pass
    q_del = "DELETE FROM content_materials WHERE id = %s" if is_pg else "DELETE FROM content_materials WHERE id = ?"
    c.execute(q_del, (material_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم حذف المادة."}


@app.get("/api/user/content/browse")
async def user_browse_content(
    tab: str, folder_id: Optional[int] = None,
    user: Dict[str, object] = Depends(get_current_user),
):
    """تصفح المحتوى التدريبي المتاح للفرد (بعد تسجيل الدخول) — نفس منطق تصفح الأدمن،
    من غير أي أدوات إدارة (إضافة/حذف)، مع حالة المشاهدة/الإنهاء الخاصة بيه."""
    if tab not in CONTENT_TABS:
        raise HTTPException(status_code=400, detail="تبويب غير صحيح.")
    return _browse_content(tab, folder_id, sap_id=user.get("sap_id"))


@app.post("/api/user/content/materials/{material_id}/view")
async def record_material_view(
    material_id: int, user: Dict[str, object] = Depends(get_current_user)
):
    """يسجّل إن الفرد فتح المادة دي (تتبع المشاهدة) — بيُستدعى أول ما تُفتح نافذة العرض."""
    sap_id = user.get("sap_id")
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "INSERT INTO content_progress (sap_id, material_id) VALUES (%s, %s) ON CONFLICT(sap_id, material_id) DO NOTHING"
        if is_pg
        else "INSERT OR IGNORE INTO content_progress (sap_id, material_id) VALUES (?, ?)"
    )
    c.execute(q, (sap_id, material_id))
    conn.commit()
    conn.close()
    return {"status": "success"}


@app.post("/api/user/content/materials/{material_id}/complete")
async def mark_material_complete(
    material_id: int, user: Dict[str, object] = Depends(get_current_user)
):
    """يعلّم إن الفرد أنهى مشاهدة/استماع/قراءة المادة دي بالكامل."""
    sap_id = user.get("sap_id")
    conn, is_pg = get_db()
    c = conn.cursor()
    if is_pg:
        c.execute(
            """INSERT INTO content_progress (sap_id, material_id, completed, completed_at)
               VALUES (%s, %s, 1, CURRENT_TIMESTAMP)
               ON CONFLICT(sap_id, material_id) DO UPDATE SET completed = 1, completed_at = CURRENT_TIMESTAMP""",
            (sap_id, material_id),
        )
    else:
        c.execute(
            "INSERT OR IGNORE INTO content_progress (sap_id, material_id) VALUES (?, ?)",
            (sap_id, material_id),
        )
        c.execute(
            "UPDATE content_progress SET completed = 1, completed_at = CURRENT_TIMESTAMP WHERE sap_id = ? AND material_id = ?",
            (sap_id, material_id),
        )
    conn.commit()
    conn.close()
    return {"status": "success"}


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
    c.execute("SELECT id, name, visibility FROM teams ORDER BY name ASC")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1], "visibility": r[2] or "public"} for r in rows]


@app.get("/api/admin/team-roles")
async def get_team_roles(_admin: Dict[str, object] = Depends(require_permission("teams"))):
    """قائمة مهام أعضاء الفريق المتاحة (لملء القوائم المنسدلة عند التعيين)."""
    return TEAM_MEMBER_ROLES


@app.post("/api/admin/teams/{team_id}/visibility")
async def set_team_visibility(
    team_id: int,
    visibility: str = Form(...),
    _admin: Dict[str, object] = Depends(require_permission("teams")),
):
    """يحدد الأدمن المركزي (أو من له صلاحية الفرق) هل عرض أعضاء الفريق ده متاح لكل الناس
    (public) ولا لأعضاء الفريق نفسه بس (team_only)."""
    if visibility not in ("public", "team_only"):
        raise HTTPException(status_code=400, detail="قيمة الرؤية غير صحيحة.")
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE teams SET visibility = %s WHERE id = %s" if is_pg
        else "UPDATE teams SET visibility = ? WHERE id = ?"
    )
    c.execute(q, (visibility, team_id))
    conn.commit()
    conn.close()
    return {"status": "success"}


@app.get("/api/admin/teams/roster")
async def get_teams_roster(_admin: Dict[str, object] = Depends(require_permission("teams"))):
    """يرجّع كل الفرق مع أعضائها ومهمة كل عضو ووصف مهامه، بالإضافة لقائمة الأفراد اللي مش في أي فريق —
    للأدمن عشان يشوف الصورة الكاملة لتوزيع الفرق."""
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, visibility FROM teams ORDER BY name ASC")
    teams_rows = c.fetchall()

    c.execute("""SELECT ut.team_id, ut.sap_id, u.name, u.department, ut.role_in_team, ut.task_description
                 FROM user_teams ut JOIN users u ON ut.sap_id = u.sap_id
                 ORDER BY u.name ASC""")
    members_rows = c.fetchall()

    c.execute("""SELECT sap_id, name, department FROM users
                 WHERE sap_id NOT IN (SELECT DISTINCT sap_id FROM user_teams)
                 ORDER BY name ASC""")
    no_team_rows = c.fetchall()
    conn.close()

    members_by_team: Dict[int, List[Dict[str, object]]] = {}
    for team_id, sap_id, name, dept, role, task_desc in members_rows:
        members_by_team.setdefault(team_id, []).append(
            {"sap_id": sap_id, "name": name, "department": dept, "role_in_team": role, "task_description": task_desc}
        )

    teams = [
        {
            "id": t[0], "name": t[1], "visibility": t[2] or "public",
            "members": members_by_team.get(t[0], []),
        }
        for t in teams_rows
    ]
    users_without_team = [{"sap_id": r[0], "name": r[1], "department": r[2]} for r in no_team_rows]

    return {"teams": teams, "users_without_team": users_without_team}


@app.get("/api/admin/teams/{team_id}/org-chart")
async def get_team_org_chart(
    team_id: int, _admin: Dict[str, object] = Depends(require_permission("teams"))
):
    """يبني هيكل الفريق الهرمي: قائد الفريق أعلى الهرم، وتحته الميسر والإداري،
    وفي نفس المستوى الأعضاء وقادة الحلقات، وتحت كل قائد حلقة أعضاء حلقته."""
    conn, is_pg = get_db()
    c = conn.cursor()
    q_team = "SELECT id, name FROM teams WHERE id = %s" if is_pg else "SELECT id, name FROM teams WHERE id = ?"
    c.execute(q_team, (team_id,))
    team_row = c.fetchone()
    if not team_row:
        conn.close()
        raise HTTPException(status_code=404, detail="الفريق غير موجود.")

    q_members = (
        """SELECT u.sap_id, u.name, u.department, ut.role_in_team, ut.task_description
           FROM user_teams ut JOIN users u ON ut.sap_id = u.sap_id
           WHERE ut.team_id = %s""" if is_pg
        else """SELECT u.sap_id, u.name, u.department, ut.role_in_team, ut.task_description
           FROM user_teams ut JOIN users u ON ut.sap_id = u.sap_id
           WHERE ut.team_id = ?"""
    )
    c.execute(q_members, (team_id,))
    rows = c.fetchall()
    conn.close()

    def person(r):
        return {"sap_id": r[0], "name": r[1], "department": r[2], "role_in_team": r[3], "task_description": r[4]}

    leader = [person(r) for r in rows if r[3] == "قائد الفريق"]
    facilitator = [person(r) for r in rows if r[3] == "ميسر الفريق"]
    team_admin = [person(r) for r in rows if r[3] == "اداري الفريق"]
    members = [person(r) for r in rows if r[3] == "عضو الفريق"]
    other = [person(r) for r in rows if r[3] in (None, "") or r[3] not in TEAM_MEMBER_ROLES]

    circles = {}
    for letter in ("A", "B", "C"):
        circle_leader = [person(r) for r in rows if r[3] == f"قائد الحلقة {letter}"]
        circle_members = [person(r) for r in rows if r[3] == f"عضو الحلقة {letter}"]
        if circle_leader or circle_members:
            circles[letter] = {"leader": circle_leader[0] if circle_leader else None, "members": circle_members}

    return {
        "team_id": team_row[0], "team_name": team_row[1],
        "leader": leader[0] if leader else None,
        "facilitator": facilitator[0] if facilitator else None,
        "team_admin": team_admin[0] if team_admin else None,
        "members": members,
        "circles": circles,
        "unclassified": other,  # أعضاء بدون مهمة محددة، أو انضموا قبل نظام المهام
    }


@app.get("/api/admin/person-photo/{sap_id}")
async def get_admin_person_photo(
    sap_id: str, _admin: Dict[str, object] = Depends(require_permission("teams"))
):
    """يعرض صورة فرد لعرضها في هيكل الفريق للأدمن فقط (وليست عامة، حفاظًا على خصوصية الأفراد)."""
    path = _find_asset_image(sap_id.strip())
    if not path:
        raise HTTPException(status_code=404, detail="لا توجد صورة لهذا الفرد.")
    return FileResponse(str(path))


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
        """SELECT t.id, t.name, ut.role_in_team, ut.task_description FROM user_teams ut JOIN teams t ON ut.team_id = t.id WHERE ut.sap_id = %s"""
        if is_pg
        else """SELECT t.id, t.name, ut.role_in_team, ut.task_description FROM user_teams ut JOIN teams t ON ut.team_id = t.id WHERE ut.sap_id = ?"""
    )
    c.execute(q, (sap_id.strip(),))
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1], "role_in_team": r[2], "task_description": r[3]} for r in rows]


@app.post("/api/admin/users/{sap_id}/set-teams")
async def set_user_teams(
    sap_id: str,
    team_assignments: str = Form("[]"),
    _admin: Dict[str, object] = Depends(require_permission("users")),
):
    """يحدد فرق المستخدم مع مهمته ووصف مهامه في كل فريق (بحد أقصى فريقين)، ويستبدل أي تعيين سابق بالكامل.
    الصيغة: [{"team_id": 1, "role_in_team": "قائد الفريق", "task_description": "..."}, ...]"""
    try:
        assignments = json.loads(team_assignments) if team_assignments else []
        parsed = [
            (
                int(a["team_id"]),
                (a.get("role_in_team") or "").strip() or None,
                (a.get("task_description") or "").strip() or None,
            )
            for a in assignments
        ]
    except Exception:
        raise HTTPException(status_code=400, detail="صيغة الفرق غير صحيحة.")

    if len(parsed) > 2:
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
        "INSERT INTO user_teams (sap_id, team_id, role_in_team, task_description) VALUES (%s, %s, %s, %s)"
        if is_pg
        else "INSERT INTO user_teams (sap_id, team_id, role_in_team, task_description) VALUES (?, ?, ?, ?)"
    )
    for tid, role, task_desc in parsed:
        c.execute(q_ins, (sap_id.strip(), tid, role, task_desc))

    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث فرق المستخدم بنجاح."}


@app.get("/api/user/teams")
async def get_visible_teams_for_user(current_user: Dict[str, object] = Depends(get_current_user)):
    """يرجّع للمستخدم الحالي الفرق المسموح له يشوف أعضاءها: كل الفرق العامة (public)،
    بالإضافة لفرقه الخاصة (team_only) لو هو عضو فيها."""
    sap_id = current_user.get("sap_id")
    conn, is_pg = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, visibility FROM teams ORDER BY name ASC")
    all_teams = c.fetchall()

    q_my = (
        "SELECT team_id FROM user_teams WHERE sap_id = %s" if is_pg
        else "SELECT team_id FROM user_teams WHERE sap_id = ?"
    )
    c.execute(q_my, (sap_id,))
    my_team_ids = {r[0] for r in c.fetchall()}

    visible_team_ids = [t[0] for t in all_teams if (t[2] or "public") == "public" or t[0] in my_team_ids]

    result = []
    for tid, name, visibility in all_teams:
        if tid not in visible_team_ids:
            continue
        c.execute("""SELECT u.sap_id, u.name, u.department, ut.role_in_team
                     FROM user_teams ut JOIN users u ON ut.sap_id = u.sap_id
                     WHERE ut.team_id = %s""" if is_pg else
                   """SELECT u.sap_id, u.name, u.department, ut.role_in_team
                     FROM user_teams ut JOIN users u ON ut.sap_id = u.sap_id
                     WHERE ut.team_id = ?""", (tid,))
        members = [{"sap_id": r[0], "name": r[1], "department": r[2], "role_in_team": r[3]} for r in c.fetchall()]
        result.append({"id": tid, "name": name, "visibility": visibility or "public", "members": members})

    conn.close()
    return result


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


@app.post("/api/admin/users/{sap_id}/update")
async def update_user(
    sap_id: str,
    new_sap_id: str = Form(...),
    name: str = Form(...),
    role: str = Form(...),
    department: str = Form(...),
    _admin: Dict[str, object] = Depends(require_permission("users")),
):
    """تعديل بيانات مستخدم موجود (الاسم/رقم SAP/الدور/الإدارة)، مع تحديث كل الجداول
    المرتبطة برقم SAP تلقائيًا في حال تغييره، حتى لا تنقطع الروابط مع نتائجه وفرقه السابقة."""
    old_sap = sap_id.strip()
    new_sap = new_sap_id.strip()
    if not new_sap:
        raise HTTPException(status_code=400, detail="رقم SAP لا يمكن أن يكون فارغًا.")

    conn, is_pg = get_db()
    c = conn.cursor()

    if new_sap != old_sap:
        q_check = (
            "SELECT sap_id FROM users WHERE sap_id = %s"
            if is_pg
            else "SELECT sap_id FROM users WHERE sap_id = ?"
        )
        c.execute(q_check, (new_sap,))
        if c.fetchone():
            conn.close()
            raise HTTPException(
                status_code=400,
                detail=f"رقم SAP الجديد ({new_sap}) مستخدم بالفعل لفرد آخر.",
            )

    q_upd = (
        "UPDATE users SET sap_id = %s, name = %s, role = %s, department = %s WHERE sap_id = %s"
        if is_pg
        else "UPDATE users SET sap_id = ?, name = ?, role = ?, department = ? WHERE sap_id = ?"
    )
    c.execute(q_upd, (new_sap, name.strip(), role.strip(), department.strip(), old_sap))

    if new_sap != old_sap:
        # تحديث كل الجداول المرتبطة برقم SAP القديم للحفاظ على الروابط التاريخية
        for table in ("submissions", "user_teams", "retake_permissions", "exam_sessions", "reset_requests", "retake_requests"):
            try:
                q_cascade = (
                    f"UPDATE {table} SET sap_id = %s WHERE sap_id = %s"
                    if is_pg
                    else f"UPDATE {table} SET sap_id = ? WHERE sap_id = ?"
                )
                c.execute(q_cascade, (new_sap, old_sap))
            except Exception:
                pass  # الجدول قد لا يكون موجودًا بعد في نسخ قديمة من قاعدة البيانات

    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث بيانات المستخدم بنجاح."}


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
    allow_answer_review: int = Form(0),
    _admin: Dict[str, object] = Depends(require_permission("manage")),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE exams SET is_active = %s, valid_until = %s, hide_leaderboard = %s, allow_answer_review = %s WHERE id = %s"
        if is_pg
        else "UPDATE exams SET is_active = ?, valid_until = ?, hide_leaderboard = ?, allow_answer_review = ? WHERE id = ?"
    )
    c.execute(q, (is_active, valid_until if valid_until else None, hide_leaderboard, allow_answer_review, exam_id))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث صلاحية الامتحان."}


@app.post("/api/admin/exams/{exam_id}/update-targeting")
async def update_exam_targeting(
    exam_id: int,
    departments: str = Form(...),
    teams: str = Form(...),
    _admin: Dict[str, object] = Depends(require_permission("manage")),
):
    """يسمح بتعديل تخصيص الامتحان (الإدارات/الفرق المتاحة له) في أي وقت بعد النشر."""
    try:
        dept_list = json.loads(departments) if departments else ["الكل"]
        if not dept_list:
            dept_list = ["الكل"]
    except Exception:
        raise HTTPException(status_code=400, detail="صيغة الإدارات غير صحيحة.")
    try:
        team_list = json.loads(teams) if teams else ["الكل"]
        if not team_list:
            team_list = ["الكل"]
    except Exception:
        raise HTTPException(status_code=400, detail="صيغة الفرق غير صحيحة.")

    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE exams SET departments = %s, teams = %s WHERE id = %s"
        if is_pg
        else "UPDATE exams SET departments = ?, teams = ? WHERE id = ?"
    )
    c.execute(q, (
        json.dumps(dept_list, ensure_ascii=False),
        json.dumps(team_list, ensure_ascii=False),
        exam_id,
    ))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث تخصيص الامتحان بنجاح."}


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

    for table in ("questions", "submissions", "retake_permissions", "exam_sessions", "retake_requests"):
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
    # نتجاهل أي sap_id/department قادمين من الاستعلام ونستخدم هوية المستخدم من التوكن فقط
    # (ونجلب إدارته الحقيقية من قاعدة البيانات)، لمنع انتحال شخصية فرد آخر أو إدارة أخرى
    sap_id = str(user["sap_id"])
    conn, is_pg = get_db()
    c = conn.cursor()

    q_dept = (
        "SELECT department FROM users WHERE sap_id = %s" if is_pg else "SELECT department FROM users WHERE sap_id = ?"
    )
    c.execute(q_dept, (sap_id,))
    urow = c.fetchone()
    department = urow[0] if urow else None

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
        "SELECT name, duration_minutes, departments, is_active, valid_until, hide_leaderboard, teams, allow_answer_review FROM exams WHERE id = %s"
        if is_pg
        else "SELECT name, duration_minutes, departments, is_active, valid_until, hide_leaderboard, teams, allow_answer_review FROM exams WHERE id = ?"
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
        "departments": json.loads(exam[2]) if exam[2] else ["الكل"],
        "is_active": bool(exam[3]),
        "valid_until": exam[4],
        "hide_leaderboard": bool(exam[5]) if exam[5] is not None else False,
        "teams": json.loads(exam[6]) if exam[6] else ["الكل"],
        "allow_answer_review": bool(exam[7]) if exam[7] is not None else False,
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


@app.post("/api/admin/exams/{exam_id}/regrade")
async def regrade_exam_submissions(
    exam_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    """يعيد تصحيح كل النتائج المسجّلة لهذا الامتحان بناءً على الإجابات الصحيحة الحالية للأسئلة
    (مفيد بعد تعديل إجابة سؤال بالخطأ). يستخدم إجابة كل متدرب كما سجّلها وقت التسليم، ويعيد
    مقارنتها بالمفتاح الصحيح الحالي. أي سؤال حُذف منذ التسليم يُستبعد بالكامل من إعادة التصحيح
    (لا يُحتسب ضمن عدد الأسئلة أو الدرجة)، فتُحسب النتيجة الجديدة على أساس الأسئلة الحالية فقط."""
    conn, is_pg = get_db()
    c = conn.cursor()

    q_qs = (
        "SELECT id, branch, question, correct_option FROM questions WHERE exam_id = %s"
        if is_pg
        else "SELECT id, branch, question, correct_option FROM questions WHERE exam_id = ?"
    )
    c.execute(q_qs, (exam_id,))
    current_questions = {
        r[0]: {"branch": r[1], "question": r[2], "correct": set(parse_correct_answers(r[3]))}
        for r in c.fetchall()
    }

    q_subs = (
        "SELECT id, answers_detail FROM submissions WHERE exam_id = %s AND answers_detail IS NOT NULL"
        if is_pg
        else "SELECT id, answers_detail FROM submissions WHERE exam_id = ? AND answers_detail IS NOT NULL"
    )
    c.execute(q_subs, (exam_id,))
    submissions = c.fetchall()

    if not submissions:
        conn.close()
        return {
            "status": "success",
            "message": "لا توجد نتائج لها تفاصيل إجابات قابلة لإعادة التصحيح (النتائج القديمة قبل هذه الميزة لا يمكن إعادة تصحيحها تلقائيًا).",
            "updated_count": 0,
        }

    updated_count = 0
    for sub_id, detail_raw in submissions:
        try:
            details = json.loads(detail_raw)
        except Exception:
            continue

        branch_stats: Dict[str, Dict[str, int]] = {}
        total_correct = 0
        refreshed_details = []
        excluded_deleted = 0

        for d in details:
            q_id = d.get("question_id")
            given_set = set(d.get("given", []))
            cur = current_questions.get(q_id)

            if cur is None:
                # السؤال حُذف منذ ذلك الحين: يُستبعد تمامًا من إعادة التصحيح ولا يُحتسب
                # ضمن عدد الأسئلة أو الدرجة، حتى تعكس النتيجة الأسئلة الحالية فقط
                excluded_deleted += 1
                continue

            # السؤال ما زال موجودًا: نعيد التصحيح بمقارنة إجابة المتدرب بالمفتاح الحالي
            correct_set = cur["correct"]
            is_correct = bool(correct_set) and given_set == correct_set
            branch = cur["branch"]
            refreshed_details.append({
                "question_id": q_id,
                "branch": branch,
                "question": cur["question"],
                "given": sorted(given_set),
                "correct": sorted(correct_set),
                "is_correct": is_correct,
            })

            branch_stats.setdefault(branch, {"total": 0, "correct": 0})
            branch_stats[branch]["total"] += 1
            if is_correct:
                branch_stats[branch]["correct"] += 1
                total_correct += 1

        total_q = len(refreshed_details)
        if total_q == 0:
            # كل أسئلة هذه المحاولة اتحذفت، لا يوجد أساس لإعادة تصحيحها
            continue
        overall_pct = (total_correct / total_q) * 100
        overall_lvl = get_level(overall_pct)
        branch_results = {
            branch: {
                "score": stats["correct"],
                "total": stats["total"],
                "percentage": round((stats["correct"] / stats["total"]) * 100, 1) if stats["total"] else 0,
                "level": get_level((stats["correct"] / stats["total"]) * 100 if stats["total"] else 0),
            }
            for branch, stats in branch_stats.items()
        }

        q_upd = (
            """UPDATE submissions SET total_score = %s, total_questions = %s, total_pct = %s,
               overall_level = %s, branch_details = %s, answers_detail = %s WHERE id = %s"""
            if is_pg
            else """UPDATE submissions SET total_score = ?, total_questions = ?, total_pct = ?,
               overall_level = ?, branch_details = ?, answers_detail = ? WHERE id = ?"""
        )
        c.execute(q_upd, (
            total_correct, total_q, overall_pct, overall_lvl,
            json.dumps(branch_results, ensure_ascii=False),
            json.dumps(refreshed_details, ensure_ascii=False),
            sub_id,
        ))
        updated_count += 1

    conn.commit()
    conn.close()
    return {
        "status": "success",
        "message": f"تمت إعادة تصحيح {updated_count} نتيجة بناءً على المفتاح الحالي للإجابات.",
        "updated_count": updated_count,
    }


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

    # لو الشخص ده قدّم الامتحان ده قبل كده (إعادة امتحان)، نمسح نتيجته السابقة في هذا الامتحان
    # قبل حفظ النتيجة الجديدة، عشان يفضل ليه نتيجة واحدة بس (الأحدث) لكل امتحان
    q_del_prev = (
        "DELETE FROM submissions WHERE exam_id = %s AND sap_id = %s"
        if is_pg
        else "DELETE FROM submissions WHERE exam_id = ? AND sap_id = ?"
    )
    c.execute(q_del_prev, (exam_id, sap_id))

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


@app.get("/api/exams/{exam_id}/my-review")
async def get_my_exam_review(
    exam_id: int, user: Dict[str, object] = Depends(get_current_user)
):
    """يعرض للمتحن تفصيل إجاباته على امتحان أدّاه: إجابته الصحيحة والخاطئة، والإجابة الصحيحة
    المفترضة لكل سؤال، بشرط أن يكون الأدمن قد فعّل خاصية مراجعة الإجابات لهذا الامتحان تحديدًا."""
    sap_id = str(user["sap_id"])
    conn, is_pg = get_db()
    c = conn.cursor()

    q_exam = (
        "SELECT name, allow_answer_review FROM exams WHERE id = %s"
        if is_pg
        else "SELECT name, allow_answer_review FROM exams WHERE id = ?"
    )
    c.execute(q_exam, (exam_id,))
    exam = c.fetchone()
    if not exam:
        conn.close()
        raise HTTPException(status_code=404, detail="الامتحان غير موجود.")
    if not exam[1]:
        conn.close()
        raise HTTPException(
            status_code=403, detail="مراجعة تفاصيل الإجابات غير متاحة لهذا الامتحان حاليًا."
        )

    q_sub = (
        """SELECT answers_detail, total_score, total_questions, total_pct, overall_level, submitted_at
           FROM submissions WHERE exam_id = %s AND sap_id = %s ORDER BY submitted_at DESC LIMIT 1"""
        if is_pg
        else """SELECT answers_detail, total_score, total_questions, total_pct, overall_level, submitted_at
           FROM submissions WHERE exam_id = ? AND sap_id = ? ORDER BY submitted_at DESC LIMIT 1"""
    )
    c.execute(q_sub, (exam_id, sap_id))
    sub = c.fetchone()
    conn.close()

    if not sub:
        raise HTTPException(status_code=404, detail="لا توجد نتيجة مسجّلة لك في هذا الامتحان.")
    if not sub[0]:
        raise HTTPException(
            status_code=404,
            detail="تفاصيل الإجابات غير متاحة لهذه النتيجة (نتيجة قديمة قبل تفعيل هذه الميزة).",
        )

    try:
        answers = json.loads(sub[0])
    except Exception:
        answers = []

    return {
        "exam_name": exam[0],
        "total_score": sub[1],
        "total_questions": sub[2],
        "total_pct": round(sub[3], 1),
        "overall_level": sub[4],
        "submitted_at": str(sub[5]),
        "answers": answers,
    }


def _fetch_best_submission_for_certificate(c, is_pg, exam_id: int, sap_id: str):
    q_best = (
        """SELECT id, total_pct, overall_level, submitted_at FROM submissions
           WHERE exam_id = %s AND sap_id = %s ORDER BY total_pct DESC LIMIT 1"""
        if is_pg
        else """SELECT id, total_pct, overall_level, submitted_at FROM submissions
           WHERE exam_id = ? AND sap_id = ? ORDER BY total_pct DESC LIMIT 1"""
    )
    c.execute(q_best, (exam_id, sap_id))
    return c.fetchone()


@app.get("/api/exams/{exam_id}/certificate")
async def get_my_certificate(
    exam_id: int, user: Dict[str, object] = Depends(get_current_user)
):
    """يصدر شهادة PDF قابلة للتنزيل للفرد نفسه، بشرط تحقيقه المستوى 3 (متقدم) أو المستوى 4 (خبير)
    على الأقل في أفضل محاولة له بهذا الامتحان."""
    sap_id = str(user["sap_id"])
    conn, is_pg = get_db()
    c = conn.cursor()

    q_exam = "SELECT name FROM exams WHERE id = %s" if is_pg else "SELECT name FROM exams WHERE id = ?"
    c.execute(q_exam, (exam_id,))
    exam = c.fetchone()
    if not exam:
        conn.close()
        raise HTTPException(status_code=404, detail="الامتحان غير موجود.")

    q_user = "SELECT name FROM users WHERE sap_id = %s" if is_pg else "SELECT name FROM users WHERE sap_id = ?"
    c.execute(q_user, (sap_id,))
    urow = c.fetchone()
    user_name = urow[0] if urow else sap_id

    best = _fetch_best_submission_for_certificate(c, is_pg, exam_id, sap_id)
    conn.close()

    if not best:
        raise HTTPException(status_code=404, detail="لا توجد نتيجة مسجّلة لك في هذا الامتحان.")
    sub_id, pct, level, submitted_at = best
    if level not in CERTIFICATE_ELIGIBLE_LEVELS:
        raise HTTPException(
            status_code=403,
            detail="الشهادة متاحة فقط لمن حقق المستوى 3 (متقدم) أو المستوى 4 (خبير) على الأقل.",
        )

    pdf_bytes = generate_certificate_pdf(user_name, exam[0], level, pct, sub_id, str(submitted_at), sap_id)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=certificate_{sub_id}.pdf"},
    )


@app.get("/api/admin/exams/{exam_id}/certificate/{sap_id}")
async def get_certificate_for_user_admin(
    exam_id: int, sap_id: str, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    """يسمح للأدمن باستخراج شهادة أي فرد مستحق مباشرة من شاشة إدارة نتائج الامتحان."""
    conn, is_pg = get_db()
    c = conn.cursor()

    q_exam = "SELECT name FROM exams WHERE id = %s" if is_pg else "SELECT name FROM exams WHERE id = ?"
    c.execute(q_exam, (exam_id,))
    exam = c.fetchone()
    if not exam:
        conn.close()
        raise HTTPException(status_code=404, detail="الامتحان غير موجود.")

    q_user = "SELECT name FROM users WHERE sap_id = %s" if is_pg else "SELECT name FROM users WHERE sap_id = ?"
    c.execute(q_user, (sap_id.strip(),))
    urow = c.fetchone()
    user_name = urow[0] if urow else sap_id

    best = _fetch_best_submission_for_certificate(c, is_pg, exam_id, sap_id.strip())
    conn.close()

    if not best:
        raise HTTPException(status_code=404, detail="لا توجد نتيجة مسجّلة لهذا الفرد في هذا الامتحان.")
    sub_id, pct, level, submitted_at = best
    if level not in CERTIFICATE_ELIGIBLE_LEVELS:
        raise HTTPException(
            status_code=403,
            detail="الشهادة متاحة فقط لمن حقق المستوى 3 (متقدم) أو المستوى 4 (خبير) على الأقل.",
        )

    pdf_bytes = generate_certificate_pdf(user_name, exam[0], level, pct, sub_id, str(submitted_at), sap_id.strip())
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=certificate_{sub_id}.pdf"},
    )


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


# --- صفحة موحّدة لإدارة كل المحاولات المعلّقة عبر جميع الامتحانات ---
@app.get("/api/admin/pending-attempts")
async def get_all_pending_attempts(
    _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    """قائمة موحّدة عبر كل الامتحانات: من دخل ولم يُكمل، ومن طلب إعادة الامتحان صراحة."""
    conn, is_pg = get_db()
    c = conn.cursor()

    c.execute(
        """SELECT es.exam_id, e.name, es.sap_id, u.name, es.started_at
           FROM exam_sessions es
           LEFT JOIN users u ON es.sap_id = u.sap_id
           LEFT JOIN exams e ON es.exam_id = e.id
           WHERE es.status = 'in_progress'
           ORDER BY es.started_at DESC"""
    )
    in_progress = [
        {
            "exam_id": r[0], "exam_name": r[1] or "-", "sap_id": r[2],
            "name": r[3] or "-", "started_at": str(r[4]),
        }
        for r in c.fetchall()
    ]

    c.execute(
        """SELECT rr.id, rr.exam_id, e.name, rr.sap_id, COALESCE(u.name, rr.user_name), rr.requested_at
           FROM retake_requests rr
           LEFT JOIN users u ON rr.sap_id = u.sap_id
           LEFT JOIN exams e ON rr.exam_id = e.id
           WHERE rr.status = 'pending'
           ORDER BY rr.requested_at DESC"""
    )
    retake_requests = [
        {
            "request_id": r[0], "exam_id": r[1], "exam_name": r[2] or "-",
            "sap_id": r[3], "name": r[4] or "-", "requested_at": str(r[5]),
        }
        for r in c.fetchall()
    ]

    conn.close()
    return {"in_progress": in_progress, "retake_requests": retake_requests}


@app.post("/api/exams/{exam_id}/request-retake")
async def request_exam_retake(
    exam_id: int, user: Dict[str, object] = Depends(get_current_user)
):
    """يسمح للفرد بتقديم طلب صريح لإعادة الامتحان عندما يكون محظورًا من الدخول، ليراه الأدمن في قائمة موحّدة."""
    sap_id = str(user["sap_id"])
    conn, is_pg = get_db()
    c = conn.cursor()

    # تفادي تكرار طلبات معلّقة لنفس الامتحان لنفس الفرد
    q_check = (
        "SELECT id FROM retake_requests WHERE exam_id = %s AND sap_id = %s AND status = 'pending'"
        if is_pg
        else "SELECT id FROM retake_requests WHERE exam_id = ? AND sap_id = ? AND status = 'pending'"
    )
    c.execute(q_check, (exam_id, sap_id))
    if c.fetchone():
        conn.close()
        return {"status": "success", "message": "لديك بالفعل طلب إعادة معلّق لهذا الامتحان، سيتم مراجعته من الإدارة."}

    q_name = (
        "SELECT name FROM users WHERE sap_id = %s" if is_pg else "SELECT name FROM users WHERE sap_id = ?"
    )
    c.execute(q_name, (sap_id,))
    row = c.fetchone()
    user_name = row[0] if row else ""

    q_ins = (
        "INSERT INTO retake_requests (exam_id, sap_id, user_name) VALUES (%s, %s, %s)"
        if is_pg
        else "INSERT INTO retake_requests (exam_id, sap_id, user_name) VALUES (?, ?, ?)"
    )
    c.execute(q_ins, (exam_id, sap_id, user_name))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم إرسال طلب إعادة الامتحان إلى الإدارة بنجاح."}


@app.post("/api/admin/retake-requests/{request_id}/approve")
async def approve_retake_request(
    request_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q_sel = (
        "SELECT exam_id, sap_id FROM retake_requests WHERE id = %s"
        if is_pg
        else "SELECT exam_id, sap_id FROM retake_requests WHERE id = ?"
    )
    c.execute(q_sel, (request_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="الطلب غير موجود.")
    exam_id, sap_id = row

    if is_pg:
        q_perm = (
            "INSERT INTO retake_permissions (exam_id, sap_id, allowed) VALUES (%s, %s, 1)"
            " ON CONFLICT(exam_id, sap_id) DO UPDATE SET allowed = 1"
        )
    else:
        q_perm = (
            "INSERT INTO retake_permissions (exam_id, sap_id, allowed) VALUES (?, ?, 1)"
            " ON CONFLICT(exam_id, sap_id) DO UPDATE SET allowed = 1"
        )
    c.execute(q_perm, (exam_id, sap_id))

    q_resolve = (
        "UPDATE retake_requests SET status = 'approved' WHERE id = %s"
        if is_pg
        else "UPDATE retake_requests SET status = 'approved' WHERE id = ?"
    )
    c.execute(q_resolve, (request_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم الموافقة على طلب الإعادة والسماح للفرد {sap_id} بإعادة الامتحان."}


@app.post("/api/admin/retake-requests/{request_id}/reject")
async def reject_retake_request(
    request_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE retake_requests SET status = 'rejected' WHERE id = %s"
        if is_pg
        else "UPDATE retake_requests SET status = 'rejected' WHERE id = ?"
    )
    c.execute(q, (request_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم رفض طلب الإعادة."}


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
        """SELECT s.id, e.name, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.branch_details, s.submitted_at, s.exam_id, e.allow_answer_review
           FROM submissions s LEFT JOIN exams e ON s.exam_id = e.id WHERE s.sap_id = %s ORDER BY s.submitted_at DESC"""
        if is_pg
        else """SELECT s.id, e.name, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.branch_details, s.submitted_at, s.exam_id, e.allow_answer_review
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
            "exam_id": r[8],
            "allow_answer_review": bool(r[9]) if r[9] is not None else False,
        }
        for r in rows
    ]


# --- لوحة الشرف والتصدير ---
@app.get("/api/leaderboard/exam/{exam_id}")
async def get_exam_leaderboard(exam_id: int, department: Optional[str] = None):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """SELECT s.sap_id, s.user_name, u.role, u.department, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.submitted_at 
           FROM submissions s 
           LEFT JOIN users u ON s.sap_id = u.sap_id 
           LEFT JOIN exams e ON s.exam_id = e.id
           WHERE s.exam_id = %s AND COALESCE(s.hidden, 0) = 0 AND COALESCE(e.hide_leaderboard, 0) = 0"""
        if is_pg
        else """SELECT s.sap_id, s.user_name, u.role, u.department, s.total_score, s.total_questions, s.total_pct, s.overall_level, s.submitted_at 
           FROM submissions s 
           LEFT JOIN users u ON s.sap_id = u.sap_id 
           LEFT JOIN exams e ON s.exam_id = e.id
           WHERE s.exam_id = ? AND COALESCE(s.hidden, 0) = 0 AND COALESCE(e.hide_leaderboard, 0) = 0"""
    )
    c.execute(q, (exam_id,))
    rows = c.fetchall()
    conn.close()

    # في حال إعادة الامتحان أكثر من مرة لنفس الفرد، نأخذ أعلى محاولة له فقط (وليس متوسطها أو تكرارها)
    best_by_sap: Dict[str, tuple] = {}
    for r in rows:
        sap_id = r[0]
        if department and (r[3] or "") != department:
            continue
        if sap_id not in best_by_sap or r[6] > best_by_sap[sap_id][6] or (
            r[6] == best_by_sap[sap_id][6] and str(r[8]) < str(best_by_sap[sap_id][8])
        ):
            best_by_sap[sap_id] = r

    best_rows = sorted(best_by_sap.values(), key=lambda r: (-r[6], str(r[8])))
    return [
        {
            "rank": i + 1,
            "name": r[1],
            "role": r[2] or "-",
            "department": r[3] or "-",
            "score": f"{r[4]}/{r[5]}",
            "pct": f"{r[6]:.1f}%",
            "level": r[7],
            "date": str(r[8]),
        }
        for i, r in enumerate(best_rows)
    ]


@app.get("/api/departments/public-list")
async def list_departments_public():
    """قائمة الإدارات المسجّلة، متاحة للجميع بدون تسجيل دخول لاستخدامها في تصفية لوحة الشرف حسب الإدارة."""
    conn, _ = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT DISTINCT department FROM users WHERE department IS NOT NULL AND department != '' ORDER BY department ASC"
    )
    depts = [r[0] for r in c.fetchall()]
    conn.close()
    return {"departments": depts}


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
async def get_general_leaderboard(department: Optional[str] = None):
    conn, _ = get_db()
    c = conn.cursor()
    c.execute("""SELECT s.sap_id, s.user_name, u.role, u.department, s.exam_id, s.total_pct
                 FROM submissions s 
                 LEFT JOIN users u ON s.sap_id = u.sap_id 
                 LEFT JOIN exams e ON s.exam_id = e.id
                 WHERE COALESCE(s.hidden, 0) = 0 AND COALESCE(e.hide_leaderboard, 0) = 0""")
    rows = c.fetchall()
    conn.close()

    # نأخذ أعلى محاولة للفرد في كل امتحان على حدة (بدلاً من متوسط كل المحاولات، حتى لا يُعاقَب
    # على محاولة أضعف سابقة بعد ما حسّن نتيجته بإذن إعادة من الإدارة)
    best_per_person_exam: Dict[tuple, float] = {}
    meta: Dict[str, tuple] = {}
    for sap_id, name, role, dept, exam_id, pct in rows:
        if department and (dept or "") != department:
            continue
        key = (sap_id, exam_id)
        if key not in best_per_person_exam or pct > best_per_person_exam[key]:
            best_per_person_exam[key] = pct
        meta[sap_id] = (name, role, dept)

    person_bests: Dict[str, List[float]] = {}
    for (sap_id, exam_id), pct in best_per_person_exam.items():
        person_bests.setdefault(sap_id, []).append(pct)

    results = []
    for sap_id, pcts in person_bests.items():
        name, role, dept = meta[sap_id]
        avg_pct = sum(pcts) / len(pcts)
        results.append((sap_id, name, role, dept, avg_pct, len(pcts)))
    results.sort(key=lambda x: (-x[4], -x[5]))

    return [
        {
            "rank": i + 1,
            "name": r[1],
            "role": r[2] or "-",
            "department": r[3] or "-",
            "avg_pct": f"{r[4]:.1f}%",
            "overall_level": get_level(r[4]),
            "exams_count": r[5],
        }
        for i, r in enumerate(results)
    ]


@app.get("/api/admin/exams/{exam_id}/export-non-attendees")
async def export_non_attendees(
    exam_id: int, _admin: Dict[str, object] = Depends(require_permission("manage"))
):
    """يصدّر ملف إكسل بأسماء وأرقام SAP وإدارات الأفراد المستحقين لهذا الامتحان (حسب تخصيصه
    الحالي للإدارات/الفرق) والذين لم يؤدّوه بعد إطلاقًا."""
    conn, is_pg = get_db()
    c = conn.cursor()

    q_exam = (
        "SELECT name, departments, teams FROM exams WHERE id = %s"
        if is_pg
        else "SELECT name, departments, teams FROM exams WHERE id = ?"
    )
    c.execute(q_exam, (exam_id,))
    exam = c.fetchone()
    if not exam:
        conn.close()
        raise HTTPException(status_code=404, detail="الامتحان غير موجود.")
    exam_name, depts_json, teams_json = exam
    target_depts = json.loads(depts_json) if depts_json else ["الكل"]
    target_teams = json.loads(teams_json) if teams_json else ["الكل"]

    c.execute("SELECT sap_id, name, department, role FROM users ORDER BY department ASC, name ASC")
    all_users = c.fetchall()

    c.execute("""SELECT ut.sap_id, t.name FROM user_teams ut JOIN teams t ON ut.team_id = t.id""")
    user_teams_map: Dict[str, set] = {}
    for sap_id, team_name in c.fetchall():
        user_teams_map.setdefault(sap_id, set()).add(team_name)

    q_sub = (
        "SELECT DISTINCT sap_id FROM submissions WHERE exam_id = %s"
        if is_pg
        else "SELECT DISTINCT sap_id FROM submissions WHERE exam_id = ?"
    )
    c.execute(q_sub, (exam_id,))
    attendees = set(r[0] for r in c.fetchall())
    conn.close()

    non_attendees = []
    for sap_id, name, dept, role in all_users:
        if sap_id in attendees:
            continue
        dept_ok = "الكل" in target_depts or (dept in target_depts) or dept == "عام"
        user_team_names = user_teams_map.get(sap_id, set())
        team_ok = "الكل" in target_teams or bool(user_team_names.intersection(target_teams))
        if dept_ok and team_ok:
            non_attendees.append({
                "رقم SAP": sap_id,
                "الاسم": name,
                "الإدارة": dept,
                "الدور الوظيفي": role,
            })

    df = pd.DataFrame(non_attendees) if non_attendees else pd.DataFrame(
        columns=["رقم SAP", "الاسم", "الإدارة", "الدور الوظيفي"]
    )
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="لم يؤدوا الامتحان")
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename=non_attendees_exam_{exam_id}.xlsx"
        },
    )


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
        """SELECT sr.id, sr.role, sr.skill_name, sr.description, sr.linked_exam_id, e.name, sr.required_level,
                  sr.skill_group, sr.training_resource_url, sr.training_resource_note, sr.validity_months
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
            "training_resource_url": r[8] or "",
            "training_resource_note": r[9] or "",
            "validity_months": r[10],
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
    training_resource_url: str = Form(""),
    training_resource_note: str = Form(""),
    validity_months: Optional[str] = Form(None),
    _admin: Dict[str, object] = Depends(require_permission("skills")),
):
    exam_id_val = int(linked_exam_id) if linked_exam_id and linked_exam_id.strip() else None
    validity_val = int(validity_months) if validity_months and validity_months.strip() else None
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """INSERT INTO skill_requirements (role, skill_group, skill_name, description, linked_exam_id,
           required_level, training_resource_url, training_resource_note, validity_months)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        if is_pg
        else """INSERT INTO skill_requirements (role, skill_group, skill_name, description, linked_exam_id,
           required_level, training_resource_url, training_resource_note, validity_months)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    )
    c.execute(q, (
        role.strip(),
        skill_group.strip() or "عام",
        skill_name.strip(),
        description.strip(),
        exam_id_val,
        required_level.strip(),
        training_resource_url.strip(),
        training_resource_note.strip(),
        validity_val,
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
            "رابط مصدر تدريب مقترح (اختياري)": "https://example.com/safety-course",
            "اسم المدرّب/ملاحظة (اختياري)": "المهندس أحمد - قسم السلامة",
            "مدة الصلاحية بالشهور (اختياري)": 12,
        },
        {
            "المسمى الوظيفي": "فني صيانة",
            "مجموعة المهارة": "الصيانة الميكانيكية",
            "اسم المهارة": "أساسيات الهيدروليك",
            "الوصف": "",
            "الحد الأدنى للمستوى": "المستوى 3 (متقدم)",
            "اسم الامتحان المرتبط (اختياري)": "",
            "رابط مصدر تدريب مقترح (اختياري)": "",
            "اسم المدرّب/ملاحظة (اختياري)": "",
            "مدة الصلاحية بالشهور (اختياري)": "",
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
            """INSERT INTO skill_requirements (role, skill_group, skill_name, description, linked_exam_id,
               required_level, training_resource_url, training_resource_note, validity_months)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            if is_pg
            else """INSERT INTO skill_requirements (role, skill_group, skill_name, description, linked_exam_id,
               required_level, training_resource_url, training_resource_note, validity_months)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""
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

            resource_url = str(row.get("رابط مصدر تدريب مقترح (اختياري)", "") or "").strip()
            if resource_url.lower() == "nan":
                resource_url = ""
            resource_note = str(row.get("اسم المدرّب/ملاحظة (اختياري)", "") or "").strip()
            if resource_note.lower() == "nan":
                resource_note = ""
            validity_raw = row.get("مدة الصلاحية بالشهور (اختياري)", None)
            try:
                validity_val = int(validity_raw) if validity_raw and str(validity_raw).lower() != "nan" else None
            except Exception:
                validity_val = None

            c.execute(q, (
                role, skill_group, skill_name, description, linked_exam_id, required_level,
                resource_url, resource_note, validity_val,
            ))
            added += 1

        conn.commit()
        conn.close()
        return {
            "status": "success",
            "message": f"تم استيراد {added} مهارة بنجاح" + (f" (وتخطي {skipped} صف غير مكتمل)" if skipped else "") + ".",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/admin/skills/{skill_id}/update")
async def update_skill_requirement(
    skill_id: int,
    role: str = Form(...),
    skill_group: str = Form("عام"),
    skill_name: str = Form(...),
    description: str = Form(""),
    linked_exam_id: Optional[str] = Form(None),
    required_level: str = Form("المستوى 2 (متوسط)"),
    training_resource_url: str = Form(""),
    training_resource_note: str = Form(""),
    validity_months: Optional[str] = Form(None),
    _admin: Dict[str, object] = Depends(require_permission("skills")),
):
    exam_id_val = int(linked_exam_id) if linked_exam_id and linked_exam_id.strip() else None
    validity_val = int(validity_months) if validity_months and validity_months.strip() else None
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        """UPDATE skill_requirements SET role = %s, skill_group = %s, skill_name = %s,
           description = %s, linked_exam_id = %s, required_level = %s,
           training_resource_url = %s, training_resource_note = %s, validity_months = %s WHERE id = %s"""
        if is_pg
        else """UPDATE skill_requirements SET role = ?, skill_group = ?, skill_name = ?,
           description = ?, linked_exam_id = ?, required_level = ?,
           training_resource_url = ?, training_resource_note = ?, validity_months = ? WHERE id = ?"""
    )
    c.execute(q, (
        role.strip(),
        skill_group.strip() or "عام",
        skill_name.strip(),
        description.strip(),
        exam_id_val,
        required_level.strip(),
        training_resource_url.strip(),
        training_resource_note.strip(),
        validity_val,
        skill_id,
    ))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث متطلب المهارة بنجاح."}


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
        """SELECT sr.id, sr.role, sr.skill_name, sr.description, sr.linked_exam_id, e.name, sr.required_level,
                  sr.skill_group, sr.training_resource_url, sr.training_resource_note, sr.validity_months
           FROM skill_requirements sr LEFT JOIN exams e ON sr.linked_exam_id = e.id
           ORDER BY sr.skill_group ASC, sr.id ASC"""
        if is_pg
        else """SELECT sr.id, sr.role, sr.skill_name, sr.description, sr.linked_exam_id, e.name, sr.required_level,
                  sr.skill_group, sr.training_resource_url, sr.training_resource_note, sr.validity_months
           FROM skill_requirements sr LEFT JOIN exams e ON sr.linked_exam_id = e.id
           ORDER BY sr.skill_group ASC, sr.id ASC"""
    )
    # نجلب كل متطلبات المهارات ونفلترها في بايثون بمطابقة غير حسّاسة للفروق الإملائية
    # الشائعة في العربية (فني صيانة / فنى صيانه / إلخ)، بدل مطابقة SQL الحرفية
    c.execute(q_skills)
    normalized_role = normalize_arabic(role)
    skills = [r for r in c.fetchall() if normalize_arabic(r[1]) == normalized_role]

    # نجلب أي تقييمات يدوية مسجّلة لهذا الفرد (تجاوز نتيجة الامتحان أو تقييم مهارة غير مرتبطة بامتحان أصلًا)
    q_overrides = (
        "SELECT skill_requirement_id, achieved_level, note, updated_at FROM skill_overrides WHERE sap_id = %s"
        if is_pg
        else "SELECT skill_requirement_id, achieved_level, note, updated_at FROM skill_overrides WHERE sap_id = ?"
    )
    c.execute(q_overrides, (sap_id.strip(),))
    overrides = {row[0]: {"achieved_level": row[1], "note": row[2], "updated_at": row[3]} for row in c.fetchall()}

    now = datetime.now()
    result = []
    for (sk_id, sk_role, skill_name, description, linked_exam_id, exam_name, required_level,
         skill_group, training_url, training_note, validity_months) in skills:
        item = {
            "id": sk_id,
            "skill_name": skill_name,
            "description": description or "",
            "linked_exam_id": linked_exam_id,
            "linked_exam_name": exam_name,
            "required_level": required_level,
            "skill_group": skill_group or "عام",
            "training_resource_url": training_url or "",
            "training_resource_note": training_note or "",
            "validity_months": validity_months,
            "status": "not_linked",
            "achieved_level": None,
            "achieved_pct": None,
            "achieved_at": None,
            "expires_at": None,
            "renewal_status": None,
            "source": None,
            "note": None,
        }

        override = overrides.get(sk_id)
        achieved_at_raw = None
        if override and override["achieved_level"]:
            # التقييم اليدوي له الأولوية دائمًا على نتيجة الامتحان التلقائية
            achieved_level = override["achieved_level"]
            item["achieved_level"] = achieved_level
            item["source"] = "manual"
            item["note"] = override.get("note") or ""
            achieved_at_raw = override.get("updated_at")
            achieved_idx = LEVEL_ORDER.index(achieved_level) if achieved_level in LEVEL_ORDER else -1
            required_idx = LEVEL_ORDER.index(required_level) if required_level in LEVEL_ORDER else 0
            item["status"] = "met" if achieved_idx >= required_idx else "below"
        elif linked_exam_id:
            q_best = (
                """SELECT overall_level, total_pct, submitted_at FROM submissions
                   WHERE exam_id = %s AND sap_id = %s ORDER BY total_pct DESC LIMIT 1"""
                if is_pg
                else """SELECT overall_level, total_pct, submitted_at FROM submissions
                   WHERE exam_id = ? AND sap_id = ? ORDER BY total_pct DESC LIMIT 1"""
            )
            c.execute(q_best, (linked_exam_id, sap_id.strip()))
            best = c.fetchone()
            if best:
                achieved_level, achieved_pct, submitted_at = best
                item["achieved_level"] = achieved_level
                item["achieved_pct"] = round(achieved_pct, 1)
                item["source"] = "exam"
                achieved_at_raw = submitted_at
                achieved_idx = LEVEL_ORDER.index(achieved_level) if achieved_level in LEVEL_ORDER else -1
                required_idx = LEVEL_ORDER.index(required_level) if required_level in LEVEL_ORDER else 0
                item["status"] = "met" if achieved_idx >= required_idx else "below"
            else:
                item["status"] = "not_assessed"

        # حساب تاريخ انتهاء صلاحية المهارة (لو مُحدَّدة مدة صلاحية ولها تاريخ إنجاز فعلي)
        if achieved_at_raw and validity_months:
            try:
                achieved_dt = datetime.fromisoformat(str(achieved_at_raw)[:19])
                expires_dt = achieved_dt + timedelta(days=validity_months * 30)
                item["achieved_at"] = achieved_dt.strftime("%Y-%m-%d")
                item["expires_at"] = expires_dt.strftime("%Y-%m-%d")
                days_left = (expires_dt - now).days
                if days_left < 0:
                    item["renewal_status"] = "expired"
                elif days_left <= 30:
                    item["renewal_status"] = "expiring_soon"
                else:
                    item["renewal_status"] = "valid"
            except Exception:
                pass
        result.append(item)

    conn.close()
    return {"role": role, "skills": result}


@app.get("/api/admin/skills/expiring")
async def get_expiring_skills(
    _admin: Dict[str, object] = Depends(require_permission("skills"))
):
    """يرصد كل المهارات المحقَّقة (يدويًا أو عبر امتحان) لكل الأفراد، والتي انتهت صلاحيتها أو
    ستنتهي خلال 30 يومًا، بناءً على مدة الصلاحية المحددة لكل مهارة تحتاج تجديدًا دوريًا."""
    conn, is_pg = get_db()
    c = conn.cursor()

    c.execute(
        """SELECT id, role, skill_name, linked_exam_id, required_level, validity_months
           FROM skill_requirements WHERE validity_months IS NOT NULL AND validity_months > 0"""
    )
    skills_with_validity = c.fetchall()
    if not skills_with_validity:
        conn.close()
        return []

    c.execute("SELECT sap_id, name, role FROM users")
    all_users = c.fetchall()

    now = datetime.now()
    results = []

    for sk_id, sk_role, skill_name, linked_exam_id, required_level, validity_months in skills_with_validity:
        norm_role = normalize_arabic(sk_role)
        matching_users = [u for u in all_users if normalize_arabic(u[2]) == norm_role]

        for sap_id, user_name, _ in matching_users:
            achieved_level, achieved_at_raw = None, None

            q_ov = (
                "SELECT achieved_level, updated_at FROM skill_overrides WHERE sap_id = %s AND skill_requirement_id = %s"
                if is_pg
                else "SELECT achieved_level, updated_at FROM skill_overrides WHERE sap_id = ? AND skill_requirement_id = ?"
            )
            c.execute(q_ov, (sap_id, sk_id))
            ov = c.fetchone()
            if ov and ov[0]:
                achieved_level, achieved_at_raw = ov[0], ov[1]
            elif linked_exam_id:
                q_best = (
                    """SELECT overall_level, submitted_at FROM submissions
                       WHERE exam_id = %s AND sap_id = %s ORDER BY total_pct DESC LIMIT 1"""
                    if is_pg
                    else """SELECT overall_level, submitted_at FROM submissions
                       WHERE exam_id = ? AND sap_id = ? ORDER BY total_pct DESC LIMIT 1"""
                )
                c.execute(q_best, (linked_exam_id, sap_id))
                best = c.fetchone()
                if best:
                    achieved_level, achieved_at_raw = best

            if not achieved_level or not achieved_at_raw:
                continue

            try:
                achieved_dt = datetime.fromisoformat(str(achieved_at_raw)[:19])
            except Exception:
                continue
            expires_dt = achieved_dt + timedelta(days=validity_months * 30)
            days_left = (expires_dt - now).days
            if days_left <= 30:
                results.append({
                    "sap_id": sap_id,
                    "name": user_name,
                    "role": sk_role,
                    "skill_name": skill_name,
                    "achieved_at": achieved_dt.strftime("%Y-%m-%d"),
                    "expires_at": expires_dt.strftime("%Y-%m-%d"),
                    "days_left": days_left,
                    "status": "expired" if days_left < 0 else "expiring_soon",
                })

    conn.close()
    results.sort(key=lambda x: x["days_left"])
    return results


@app.get("/api/admin/skills/search-users")
async def search_users_for_skill_assessment(
    q: str = "", _admin: Dict[str, object] = Depends(require_permission("skills"))
):
    """يبحث عن الأفراد بالاسم أو رقم SAP لاستخدامه في صفحة التقييم اليدوي لمهارات فرد."""
    query = q.strip()
    if not query:
        return []
    conn, is_pg = get_db()
    c = conn.cursor()
    like = f"%{query}%"
    q_search = (
        "SELECT sap_id, name, role, department FROM users WHERE sap_id ILIKE %s OR name ILIKE %s ORDER BY name ASC LIMIT 15"
        if is_pg
        else "SELECT sap_id, name, role, department FROM users WHERE sap_id LIKE ? OR name LIKE ? ORDER BY name ASC LIMIT 15"
    )
    c.execute(q_search, (like, like))
    rows = c.fetchall()
    conn.close()
    return [{"sap_id": r[0], "name": r[1], "role": r[2], "department": r[3]} for r in rows]


@app.post("/api/admin/skills/user/{sap_id}/override")
async def set_skill_override(
    sap_id: str,
    skill_requirement_id: int = Form(...),
    achieved_level: Optional[str] = Form(None),
    note: str = Form(""),
    _admin: Dict[str, object] = Depends(require_permission("skills")),
):
    """يسمح للأدمن بتحديد مستوى مهارة معينة لفرد يدويًا (بدون ربطها بامتحان)، أو تجاوز نتيجة
    الامتحان التلقائية. إرسال achieved_level فارغًا يلغي التقييم اليدوي ويعيد الاعتماد التلقائي
    على الامتحان المرتبط (إن وُجد)."""
    conn, is_pg = get_db()
    c = conn.cursor()

    if achieved_level and achieved_level.strip():
        if achieved_level not in LEVEL_ORDER:
            conn.close()
            raise HTTPException(status_code=400, detail="مستوى غير صحيح.")
        if is_pg:
            q = """INSERT INTO skill_overrides (sap_id, skill_requirement_id, achieved_level, note, updated_at)
                   VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                   ON CONFLICT(sap_id, skill_requirement_id) DO UPDATE SET achieved_level=EXCLUDED.achieved_level, note=EXCLUDED.note, updated_at=CURRENT_TIMESTAMP"""
        else:
            q = """INSERT INTO skill_overrides (sap_id, skill_requirement_id, achieved_level, note, updated_at)
                   VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(sap_id, skill_requirement_id) DO UPDATE SET achieved_level=excluded.achieved_level, note=excluded.note, updated_at=CURRENT_TIMESTAMP"""
        c.execute(q, (sap_id.strip(), skill_requirement_id, achieved_level.strip(), note.strip()))
        message = "تم حفظ التقييم اليدوي للمهارة بنجاح."
    else:
        q = (
            "DELETE FROM skill_overrides WHERE sap_id = %s AND skill_requirement_id = %s"
            if is_pg
            else "DELETE FROM skill_overrides WHERE sap_id = ? AND skill_requirement_id = ?"
        )
        c.execute(q, (sap_id.strip(), skill_requirement_id))
        message = "تم إلغاء التقييم اليدوي، وسيُعتمد على الامتحان المرتبط تلقائيًا إن وُجد."

    conn.commit()
    conn.close()
    return {"status": "success", "message": message}


@app.get("/api/admin/analytics/overview")
async def get_analytics_overview(
    department: Optional[str] = None,
    exam_id: Optional[int] = None,
    _admin: Dict[str, object] = Depends(require_permission("analytics")),
):
    conn, is_pg = get_db()
    c = conn.cursor()

    c.execute("SELECT COUNT(id) FROM exams")
    total_exams_global = c.fetchone()[0]

    c.execute("SELECT id, name FROM exams ORDER BY id DESC")
    all_exams = [{"id": r[0], "name": r[1]} for r in c.fetchall()]

    c.execute(
        "SELECT DISTINCT department FROM users WHERE department IS NOT NULL AND department != '' ORDER BY department ASC"
    )
    all_departments = [r[0] for r in c.fetchall()]

    if department:
        q_users = (
            "SELECT COUNT(sap_id) FROM users WHERE department = %s"
            if is_pg
            else "SELECT COUNT(sap_id) FROM users WHERE department = ?"
        )
        c.execute(q_users, (department,))
    else:
        c.execute("SELECT COUNT(sap_id) FROM users")
    total_users = c.fetchone()[0]

    # نجلب كل بيانات النتائج الخام مرة واحدة، ونطبّق فلاتر السلايسر (الإدارة/الامتحان) في بايثون
    c.execute(
        """SELECT s.id, s.sap_id, s.user_name, s.exam_id, e.name, s.total_pct, s.overall_level,
                  s.submitted_at, s.answers_detail, u.department
           FROM submissions s
           LEFT JOIN users u ON s.sap_id = u.sap_id
           LEFT JOIN exams e ON s.exam_id = e.id"""
    )
    all_rows = c.fetchall()
    conn.close()

    rows = [
        r for r in all_rows
        if (not department or (r[9] or "") == department) and (not exam_id or r[3] == exam_id)
    ]

    total_participants = len(set(r[1] for r in rows))
    total_submissions = len(rows)
    pcts = [r[5] for r in rows]
    overall_avg_pct = round(sum(pcts) / len(pcts), 1) if pcts else 0
    passing_count = sum(1 for p in pcts if p >= 60)
    overall_pass_rate = round((passing_count / total_submissions) * 100, 1) if total_submissions else 0

    now = datetime.now()
    d7 = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    d30 = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    submissions_last_7d = sum(1 for r in rows if str(r[7]) >= d7)
    submissions_last_30d = sum(1 for r in rows if str(r[7]) >= d30)

    level_counts: Dict[str, int] = {}
    for r in rows:
        level_counts[r[6]] = level_counts.get(r[6], 0) + 1
    overall_level_distribution = [
        {
            "level": lvl,
            "count": level_counts.get(lvl, 0),
            "pct": round((level_counts.get(lvl, 0) / total_submissions) * 100, 1) if total_submissions else 0,
        }
        for lvl in LEVEL_ORDER
    ]

    # مقارنة الأداء عبر الفترات الزمنية (شهريًا)، على نفس بيانات الفلترة الحالية (الإدارة/الامتحان)
    # بحيث لو حدد الأدمن إدارة معينة، يشوف مباشرة هل أداء هذه الإدارة تحديدًا يتحسن أو يتراجع شهريًا
    monthly_map: Dict[str, Dict[str, object]] = {}
    for r in rows:
        month_key = str(r[7])[:7]  # YYYY-MM
        if month_key not in monthly_map:
            monthly_map[month_key] = {"pcts": [], "passing": 0}
        monthly_map[month_key]["pcts"].append(r[5])
        if r[5] >= 60:
            monthly_map[month_key]["passing"] += 1

    monthly_trend = []
    for month_key in sorted(monthly_map.keys()):
        data = monthly_map[month_key]
        n = len(data["pcts"])
        monthly_trend.append({
            "month": month_key,
            "submissions": n,
            "avg_pct": round(sum(data["pcts"]) / n, 1) if n else 0,
            "pass_rate": round((data["passing"] / n) * 100, 1) if n else 0,
        })

    # اتجاه الأداء: مقارنة متوسط آخر شهرين مقابل ما قبلهما لتلخيص "هل يتحسن أم يتراجع؟"
    trend_direction = None
    if len(monthly_trend) >= 2:
        recent_avg = monthly_trend[-1]["avg_pct"]
        previous_avg = monthly_trend[-2]["avg_pct"]
        diff = round(recent_avg - previous_avg, 1)
        trend_direction = {
            "diff": diff,
            "direction": "up" if diff > 0.5 else ("down" if diff < -0.5 else "flat"),
        }

    # التوزيع الطبيعي (Normal / Gaussian Distribution) محسوبًا على النسب المئوية الفعلية للنتائج
    score_histogram = []
    normal_curve = []
    mean_pct = None
    std_pct = None
    if len(pcts) >= 2:
        mean_pct = sum(pcts) / len(pcts)
        variance = sum((p - mean_pct) ** 2 for p in pcts) / len(pcts)
        std_pct = math.sqrt(variance)
        buckets = [0] * 10
        for p in pcts:
            idx = min(int(p // 10), 9)
            buckets[idx] += 1
        score_histogram = [{"range": f"{i*10}-{i*10+10}", "count": buckets[i]} for i in range(10)]
        n = len(pcts)
        bin_width = 10
        for i in range(10):
            x = i * 10 + 5
            if std_pct > 0:
                density = (1 / (std_pct * math.sqrt(2 * math.pi))) * math.exp(
                    -((x - mean_pct) ** 2) / (2 * std_pct ** 2)
                )
                expected_count = density * n * bin_width
            else:
                expected_count = n if abs(x - mean_pct) < bin_width else 0
            normal_curve.append({"range": f"{i*10}-{i*10+10}", "expected_count": round(expected_count, 2)})
    elif len(pcts) == 1:
        mean_pct = pcts[0]
        std_pct = 0

    exam_map: Dict[int, Dict[str, object]] = {}
    for r in rows:
        eid = r[3]
        exam_map.setdefault(eid, {"exam_name": r[4], "pcts": [], "levels": []})
        exam_map[eid]["pcts"].append(r[5])
        exam_map[eid]["levels"].append(r[6])

    per_exam = []
    for eid, data in exam_map.items():
        p = len(data["pcts"])
        avg = sum(data["pcts"]) / p if p else 0
        passing = sum(1 for x in data["pcts"] if x >= 60)
        lvl_counts: Dict[str, int] = {}
        for lvl in data["levels"]:
            lvl_counts[lvl] = lvl_counts.get(lvl, 0) + 1
        level_dist = [
            {
                "level": lvl,
                "count": lvl_counts.get(lvl, 0),
                "pct": round((lvl_counts.get(lvl, 0) / p) * 100, 1) if p else 0,
            }
            for lvl in LEVEL_ORDER
        ]
        per_exam.append({
            "exam_id": eid,
            "exam_name": data["exam_name"],
            "participants": p,
            "avg_pct": round(avg, 1),
            "pass_rate": round((passing / p) * 100, 1) if p else 0,
            "level_distribution": level_dist,
        })
    per_exam.sort(key=lambda x: -(x["exam_id"] or 0))

    top_participation = sorted(per_exam, key=lambda x: x["participants"], reverse=True)[:5]
    exams_with_participants = [e for e in per_exam if e["participants"] > 0]
    weakest_exams = sorted(exams_with_participants, key=lambda x: x["avg_pct"])[:3]
    strongest_exams = sorted(exams_with_participants, key=lambda x: x["avg_pct"], reverse=True)[:3]

    dept_map: Dict[str, List[float]] = {}
    for r in rows:
        d = r[9] or "غير محدد"
        dept_map.setdefault(d, []).append(r[5])
    dept_breakdown = [
        {"department": d, "participants": len(v), "avg_pct": round(sum(v) / len(v), 1) if v else 0}
        for d, v in dept_map.items()
    ]
    dept_breakdown.sort(key=lambda x: -x["participants"])

    person_map: Dict[str, Dict[str, object]] = {}
    for r in rows:
        sap_id_r, name_r, dept_r = r[1], r[2], r[9]
        person_map.setdefault(sap_id_r, {"name": name_r, "department": dept_r, "pcts": []})
        person_map[sap_id_r]["pcts"].append(r[5])
    top_performers = []
    for sap_id_r, d in person_map.items():
        avg = sum(d["pcts"]) / len(d["pcts"])
        top_performers.append({
            "sap_id": sap_id_r, "name": d["name"], "department": d["department"] or "-",
            "avg_pct": round(avg, 1), "exams_taken": len(d["pcts"]),
        })
    top_performers.sort(key=lambda x: -x["avg_pct"])
    top_performers = top_performers[:5]

    q_stats: Dict[str, Dict[str, object]] = {}
    for r in rows:
        detail_raw = r[8]
        if not detail_raw:
            continue
        try:
            details = json.loads(detail_raw)
        except Exception:
            continue
        for d in details:
            key = str(d.get("question_id"))
            if key not in q_stats:
                q_stats[key] = {"question": d.get("question", ""), "branch": d.get("branch", ""), "total": 0, "correct": 0}
            q_stats[key]["total"] += 1
            if d.get("is_correct"):
                q_stats[key]["correct"] += 1

    weakest_questions = []
    for stats in q_stats.values():
        if stats["total"] >= 2:
            weakest_questions.append({
                "question": stats["question"],
                "branch": stats["branch"],
                "attempts": stats["total"],
                "correct_rate": round((stats["correct"] / stats["total"]) * 100, 1),
            })
    weakest_questions = sorted(weakest_questions, key=lambda x: x["correct_rate"])[:8]

    return {
        "filters": {"departments": all_departments, "exams": all_exams},
        "applied_department": department,
        "applied_exam_id": exam_id,
        "total_exams": total_exams_global,
        "total_users": total_users,
        "total_participants": total_participants,
        "participation_rate": round((total_participants / total_users) * 100, 1) if total_users else 0,
        "total_submissions": total_submissions,
        "overall_avg_pct": overall_avg_pct,
        "overall_pass_rate": overall_pass_rate,
        "submissions_last_7d": submissions_last_7d,
        "submissions_last_30d": submissions_last_30d,
        "overall_level_distribution": overall_level_distribution,
        "monthly_trend": monthly_trend,
        "trend_direction": trend_direction,
        "score_distribution": {
            "mean": round(mean_pct, 1) if mean_pct is not None else None,
            "std_dev": round(std_pct, 1) if std_pct is not None else None,
            "histogram": score_histogram,
            "normal_curve": normal_curve,
        },
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
