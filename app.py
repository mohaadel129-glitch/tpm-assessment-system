import io
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import cloudinary
import cloudinary.uploader
from fastapi import FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI(title="Enterprise Skill Matrix & Assessment System")

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

        if is_pg:
            c.execute("""INSERT INTO admin_settings (id, sap_id, name, email, password)
                         VALUES (1, 'ADMIN01', 'مدير النظام', 'admin@company.com', 'Admin@2026')
                         ON CONFLICT (id) DO NOTHING""")
        else:
            c.execute("""INSERT OR IGNORE INTO admin_settings (id, sap_id, name, email, password)
                         VALUES (1, 'ADMIN01', 'مدير النظام', 'admin@company.com', 'Admin@2026')""")

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
            uploaded_at TIMESTAMP DEFAULT {ts_default}
        )""")

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

        if is_pg:
            c.execute("""INSERT INTO users (sap_id, name, password, role, department) 
                         VALUES ('1001', 'محمد عادل', '123456', 'مهندس صيانة', 'صيانة الاسطمبات')
                         ON CONFLICT (sap_id) DO NOTHING""")
        else:
            c.execute("""INSERT OR IGNORE INTO users (sap_id, name, password, role, department) 
                         VALUES ('1001', 'محمد عادل', '123456', 'مهندس صيانة', 'صيانة الاسطمبات')""")

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
    conn, is_pg = get_db()
    c = conn.cursor()
    query = (
        "SELECT sap_id, name, email FROM admin_settings WHERE id = 1 AND sap_id = %s AND LOWER(email) = %s AND password = %s"
        if is_pg
        else "SELECT sap_id, name, email FROM admin_settings WHERE id = 1 AND sap_id = ? AND LOWER(email) = ? AND password = ?"
    )
    c.execute(query, (sap_id.strip(), email.strip().lower(), password.strip()))
    admin = c.fetchone()
    conn.close()
    if admin:
        return {
            "status": "success",
            "role": "admin",
            "name": admin[1],
            "email": admin[2],
            "sap_id": admin[0],
        }
    raise HTTPException(
        status_code=401, detail="بيانات دخول الإدارة غير صحيحة."
    )


@app.get("/api/admin/profile")
async def get_admin_profile():
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
                password.strip(),
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
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "SELECT sap_id, name, role, department FROM users WHERE sap_id = %s AND password = %s"
        if is_pg
        else "SELECT sap_id, name, role, department FROM users WHERE sap_id = ? AND password = ?"
    )
    c.execute(q, (sap_id.strip(), password.strip()))
    user = c.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="بيانات الدخول غير صحيحة.")
    return {
        "status": "success",
        "sap_id": user[0],
        "name": user[1],
        "role": user[2],
        "department": user[3],
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
    sap_id: str = Form(...),
    old_password: str = Form(...),
    new_password: str = Form(...),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q_sel = (
        "SELECT password FROM users WHERE sap_id = %s"
        if is_pg
        else "SELECT password FROM users WHERE sap_id = ?"
    )
    c.execute(q_sel, (sap_id.strip(),))
    row = c.fetchone()
    if not row or row[0] != old_password.strip():
        conn.close()
        raise HTTPException(
            status_code=400, detail="كلمة المرور الحالية غير صحيحة."
        )

    q_upd = (
        "UPDATE users SET password = %s WHERE sap_id = %s"
        if is_pg
        else "UPDATE users SET password = ? WHERE sap_id = ?"
    )
    c.execute(q_upd, (new_password.strip(), sap_id.strip()))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تغيير كلمة المرور بنجاح."}


# --- إدارة معرض الصور ---
@app.post("/api/admin/upload-multiple-images")
async def upload_multiple_images(files: List[UploadFile] = File(...)):
    conn, is_pg = get_db()
    c = conn.cursor()
    uploaded_urls = []

    for file in files:
        contents = await file.read()
        if CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY:
            upload_res = cloudinary.uploader.upload(
                contents, folder="exam_system"
            )
            file_url = upload_res.get("secure_url")
        else:
            file_url = f"https://via.placeholder.com/300?text={file.filename}"

        q_ins = (
            "INSERT INTO media_gallery (filename, file_url) VALUES (%s, %s)"
            if is_pg
            else "INSERT INTO media_gallery (filename, file_url) VALUES (?, ?)"
        )
        c.execute(q_ins, (file.filename, file_url))
        uploaded_urls.append({"name": file.filename, "url": file_url})

    conn.commit()
    conn.close()
    return {"status": "success", "images": uploaded_urls}


@app.get("/api/admin/gallery")
async def get_gallery():
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
@app.get("/api/admin/users")
async def get_all_users():
    conn, _ = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT sap_id, name, role, department, password FROM users ORDER BY sap_id ASC"
    )
    users = [
        {
            "sap_id": r[0],
            "name": r[1],
            "role": r[2],
            "department": r[3],
            "password": r[4],
        }
        for r in c.fetchall()
    ]
    conn.close()
    return users


@app.post("/api/admin/add-user")
async def add_single_user(
    sap_id: str = Form(...),
    name: str = Form(...),
    password: str = Form(...),
    role: str = Form("فني"),
    department: str = Form("عام"),
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
            password.strip(),
            role.strip(),
            department.strip(),
        ),
    )
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"تم حفظ المستخدم {name} بنجاح."}


@app.delete("/api/admin/delete-user/{sap_id}")
async def delete_user(sap_id: str):
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
async def upload_users_excel(file: UploadFile = File(...)):
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
                c.execute(q, (sap_id, name, password, role, dept))
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
async def download_users_template():
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
async def get_reset_requests():
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
            "current_password": r[4],
            "department": r[5],
        }
        for r in rows
    ]


@app.post("/api/admin/reset-password-action")
async def reset_password_action(
    request_id: int = Form(...),
    sap_id: str = Form(...),
    new_password: Optional[str] = Form(None),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    if new_password and new_password.strip():
        q_upd = (
            "UPDATE users SET password = %s WHERE sap_id = %s"
            if is_pg
            else "UPDATE users SET password = ? WHERE sap_id = ?"
        )
        c.execute(q_upd, (new_password.strip(), sap_id.strip()))
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


# --- الامتحانات والأسئلة ---
@app.post("/api/admin/exams/{exam_id}/update-validity")
async def update_exam_validity(
    exam_id: int,
    is_active: int = Form(...),
    valid_until: Optional[str] = Form(None),
):
    conn, is_pg = get_db()
    c = conn.cursor()
    q = (
        "UPDATE exams SET is_active = %s, valid_until = %s WHERE id = %s"
        if is_pg
        else "UPDATE exams SET is_active = ?, valid_until = ? WHERE id = ?"
    )
    c.execute(q, (is_active, valid_until if valid_until else None, exam_id))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "تم تحديث صلاحية الامتحان."}


@app.post("/api/admin/exams/{exam_id}/allow-retake")
async def allow_retake(exam_id: int, sap_id: str = Form(...)):
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


@app.post("/api/admin/upload-excel")
async def upload_excel(
    exam_name: str = Form(...),
    duration: int = Form(30),
    valid_until: Optional[str] = Form(None),
    departments: str = Form("[]"),
    file: UploadFile = File(...),
):
    try:
        contents = await file.read()
        df = pd.read_excel(io.BytesIO(contents))
        dept_list = json.loads(departments) if departments else ["الكل"]
        if not dept_list:
            dept_list = ["الكل"]

        conn, is_pg = get_db()
        c = conn.cursor()
        if is_pg:
            q_exam = """INSERT INTO exams (name, duration_minutes, departments, is_active, valid_until) 
                        VALUES (%s, %s, %s, 1, %s)
                        ON CONFLICT(name) DO UPDATE SET 
                           duration_minutes=EXCLUDED.duration_minutes, 
                           departments=EXCLUDED.departments,
                           is_active=1,
                           valid_until=EXCLUDED.valid_until RETURNING id"""
            c.execute(
                q_exam,
                (
                    exam_name,
                    duration,
                    json.dumps(dept_list, ensure_ascii=False),
                    valid_until if valid_until else None,
                ),
            )
            exam_id = c.fetchone()[0]
        else:
            q_exam = """INSERT INTO exams (name, duration_minutes, departments, is_active, valid_until) 
                        VALUES (?, ?, ?, 1, ?)
                        ON CONFLICT(name) DO UPDATE SET 
                           duration_minutes=excluded.duration_minutes, 
                           departments=excluded.departments,
                           is_active=1,
                           valid_until=excluded.valid_until"""
            c.execute(
                q_exam,
                (
                    exam_name,
                    duration,
                    json.dumps(dept_list, ensure_ascii=False),
                    valid_until if valid_until else None,
                ),
           
