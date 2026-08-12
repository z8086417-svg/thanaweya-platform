"""
منصة مدرسين الثانوية العامة - Prototype
Thanaweya Amma Teachers Platform - working prototype

Flask + SQLite + Claude API (Anthropic) for a per-teacher AI assistant
and an AI exam/summary generator for teachers.

Run:
    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=sk-ant-...
    python app.py
Then open http://localhost:5000
"""

import os
import io
import re
import tempfile
import random
import sqlite3
import secrets
import string
import uuid
import json
import hmac
import hashlib
import struct
import requests
from datetime import date, datetime, timedelta
from flask import Flask, g, render_template, request, redirect, url_for, session, jsonify, flash, abort, send_from_directory, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask.sessions import SecureCookieSessionInterface

from translations import UI as UI_TRANSLATIONS, PHRASES, CONGRATS

DB_PATH = os.path.join(os.path.dirname(__file__), "platform.db")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = "claude-sonnet-5"

app = Flask(__name__)

# المنصة ورا Cloudflare tunnel (وبعدين كده كده ورا proxy) - بنثق في أول hop
# عشان IP العميل الحقيقي يوصّل لحماية تسجيل الدخول (لو اتركناه، كل الزوار
# هيبينوا بنفس الـ IP ويثبتوا/يخترقوا الحماية بسهولة). لو جالك طلب مباشر على
# الـ LAN من غير proxy، مفيش X-Forwarded-For => بيستخدم IP حقيقي - مفيش مشكلة.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)


# سشن آمن: الكوكي بتتتبت بـ Secure تلقائي لما الطلب جاي من HTTPS (زي اللينك
# العام بتاع Cloudflare) لكن بتشتغل عادي على الـ HTTP المحلي (الـ LAN) - بدون
# ده الطلاب على اللينك العام هيبقوا معرضين لسرقة السشن، وعلى الـ LAN هيتكسر
# الدخول تمامًا لو فصّلناها للأبد.
class _SessionInterface(SecureCookieSessionInterface):
    def save_session(self, app, session, response):
        super().save_session(app, session, response)
        # لو الطلب وصل من HTTPS (عبر proxy بيعيد الـ X-Forwarded-Proto)، نضيف
        # خاصية Secure على كوكي السشن - والمتصفح مش هيبعت الكوكي على اتصال HTTP
        # عادي فالسشن بتتحمى من السرقة.
        if request.headers.get("X-Forwarded-Proto") == "https":
            name = self.get_cookie_name(app)
            for key, value in list(response.headers.items()):
                if key == "Set-Cookie" and value.startswith(name + "=") and "Secure" not in value:
                    response.headers[key] = value + "; Secure"


app.session_interface = _SessionInterface()


def _load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret
    secret_path = os.path.join(os.path.dirname(__file__), ".secret_key")
    if os.path.exists(secret_path):
        with open(secret_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    generated = secrets.token_hex(32)
    with open(secret_path, "w", encoding="utf-8") as f:
        f.write(generated)
    return generated


app.secret_key = _load_or_create_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
VIDEO_FOLDER = os.path.join(UPLOAD_FOLDER, "videos")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(VIDEO_FOLDER, exist_ok=True)
ALLOWED_PHOTO_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_PHOTO_BYTES = 5 * 1024 * 1024  # 5MB
DEFAULT_STUDENT_PHOTO = "default_student.jpg"  # صورة افتراضية لكل طالب مفيش صورته
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "webm", "mov", "m4v"}
MAX_VIDEO_BYTES = 300 * 1024 * 1024  # 300MB

# ===================== حماية الملفات المرفوعة =====================
# ماسح بسيط (signature scanner) بيدور على توقيعات ملفات خطيرة معروفة في أول
# جزء من الملف المرفوع. مينفعش يكون بديل عن antivirus حقيقي، لكنه بيمنع
# أشهر الحاجات اللي بتتحمل على المواقع: Web shells, متسلسلات, polyglots.
MALWARE_SIGNATURES = [
    (b"<?php", "PHP code block"),
    (b"<?=", "PHP short tag"),
    (b"<%=", "ASP/ERB block"),
    (b"<?xml", "XML (possible XXE/SVG bomb)"),
    (b"#include <", "C/C++ include"),
    (b"eval(", "eval() code"),
    (b"base64_decode", "base64 decoder"),
    (b"system(", "system() call"),
    (b"exec(", "exec() call"),
    (b"passthru(", "passthru() call"),
    (b"shell_exec", "shell_exec() call"),
    (b"cmd.exe", "Windows command shell"),
    (b"/bin/sh", "Unix shell"),
    (b"/bin/bash", "Unix bash"),
    (b"powershell", "PowerShell"),
    (b"<?php $_", "PHP webshell"),
    (b"MZ", "Windows PE executable"),
    (b"PK\x03\x04", "ZIP/Office (possible malware container)"),
    (b"\\x7fELF", "Linux ELF executable"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!", "RAR archive"),
    (b"#!/bin/", "Shell script shebang"),
    (b"<script", "HTML/JS script block"),
    (b"javascript:", "JS protocol handler"),
    (b"onerror=", "event handler attribute"),
    (b"<iframe", "embedded iframe"),
    (b".php", "PHP filename hint"),
    (b".asp", "ASP filename hint"),
    (b".jsp", "JSP filename hint"),
]
MALWARE_SCAN_HEAD = 4 * 1024 * 1024  # نمسح أول 4 ميجا من الملف بس (السرعة)


def scan_file_for_malware(data: bytes) -> str | None:
    """يدور على توقيعات خبيثة معروفة في الملف. بيرجع اسم التوقيع اللي اتلاقى
    (عشان يترفض ويتسجل في التدقيق) أو None لو الملف نظيف."""
    head = data[:MALWARE_SCAN_HEAD]
    for sig, name in MALWARE_SIGNATURES:
        if sig in head:
            return name
    return None


def reencode_photo(data: bytes, original_ext: str) -> bytes | None:
    """يعيد ترميز الصورة عبر Pillow فيبنيها من جديد من صفر - أي شيفرة خبيثة
    مخبأة جوه الصورة (polyglot / EXIF ضار / أسهم ملحوقة) بتتجاهل نهائيًا.
    بيرجع البايتات النضيفة أو None لو الملف مش صورة صحيحة."""
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError:
        return data
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception:
        return None
    # الرسوم المتحركة GIF بتتحفظ زي ما هي (ترميز ثابت هيكسرها) - الأمانة مضمونة
    # بفحص الـ signatures قبلها.
    if getattr(img, "format", "").upper() == "GIF":
        out = io.BytesIO()
        img.save(out, format="GIF")
        return out.getvalue()
    # تحويل الشفافية الزايدة والقنوات لـ RGB عشان التنظيف يشمل كل الصور
    if img.mode not in ("RGB", "L", "RGBA", "P", "CMYK"):
        try:
            img = img.convert("RGB")
        except Exception:
            return None
    # خلاصة الصورة الرجاء: احفظها بصيغة نظيفة حسب نوعها
    save_ext = "PNG" if original_ext in ("png", "webp") else "JPEG"
    out = io.BytesIO()
    try:
        if save_ext == "PNG":
            img.save(out, format="PNG", optimize=True)
        else:
            img = img.convert("RGB")
            img.save(out, format="JPEG", quality=88, optimize=True)
    except Exception:
        return None
    result = out.getvalue()
    return result if result else None


def save_photo_securely(file_storage) -> str | None:
    """النسخة المؤمّنة من حفظ الصور: فحص الامتداد + الحجم + magic bytes +
    ماسح الفيروسات + إعادة الترميز. بتستخدم في كل أماكن رفع الصور."""
    if not file_storage or not file_storage.filename:
        return None
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in ALLOWED_PHOTO_EXTENSIONS:
        return None
    data = file_storage.read()
    if len(data) > MAX_PHOTO_BYTES:
        return None
    head = data[:16]
    if _sniff_media_ext(head) not in ALLOWED_PHOTO_EXTENSIONS:
        return None
    hit = scan_file_for_malware(data)
    if hit:
        log_security_event("malware", f"رفضت صورة: {hit}")
        return None
    clean = reencode_photo(data, ext)
    if clean is None:
        log_security_event("malware", "رفضت صورة غير قابلة للترميز")
        return None
    filename = secure_filename(f"{uuid.uuid4().hex}.{ext}")
    with open(os.path.join(UPLOAD_FOLDER, filename), "wb") as f:
        f.write(clean)
    return filename


def save_video_securely(file_storage) -> str | None:
    """النسخة المؤمّنة من حفظ الفيديو: فحص الامتداد + الحجم + magic bytes +
    ماسح الفيروسات (مفيش إعادة ترميز للفيديو - مكلفة جدًا، فالتوقيعات هي الحماية)."""
    if not file_storage or not file_storage.filename:
        return None
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in ALLOWED_VIDEO_EXTENSIONS:
        return None
    data = file_storage.read()
    if len(data) > MAX_VIDEO_BYTES:
        return None
    head = data[:16]
    if _sniff_media_ext(head) not in ("mp4", "webm"):
        return None
    hit = scan_file_for_malware(data)
    if hit:
        log_security_event("malware", f"رفضت فيديو: {hit}")
        return None
    filename = secure_filename(f"{uuid.uuid4().hex}.{ext}")
    with open(os.path.join(VIDEO_FOLDER, filename), "wb") as f:
        f.write(data)
    return filename


ALLOWED_EXAM_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"}
MAX_EXAM_BYTES = 30 * 1024 * 1024


def save_exam_file_securely(file_storage) -> str | None:
    """حفظ ملف امتحان (PDF/Word/Excel/PowerPoint) بأمان: فحص الامتداد +
    الحجم + magic bytes + ماسح الفيروسات. الاسم راندوم عشان مفيش حد يخمّنه."""
    if not file_storage or not file_storage.filename:
        return None
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in ALLOWED_EXAM_EXTENSIONS:
        return None
    data = file_storage.read()
    if len(data) > MAX_EXAM_BYTES:
        return None
    head = data[:16]
    sniff = _sniff_media_ext(head)
    if ext in {"docx", "xlsx", "pptx"} and sniff != "zip":
        return None
    if ext in {"doc", "xls", "ppt"} and sniff != "ole2":
        return None
    if ext == "pdf" and sniff != "pdf":
        return None
    hit = scan_file_for_malware(data)
    if hit:
        log_security_event("malware", f"رفضت ملف امتحان: {hit}")
        return None
    filename = secure_filename(f"{uuid.uuid4().hex}.{ext}")
    with open(os.path.join(UPLOAD_FOLDER, filename), "wb") as f:
        f.write(data)
    return filename


# ===================== التدقيق الأمني (Audit log) =====================
def log_security_event(event: str, detail: str = ""):
    """يسجل حدث أمني في جدول audit_log للرقابة. من غير ما يكسر أي طلب - أي
    خطأ في التسجيل بيتجاهل بصمت."""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (event, detail, actor, ip, created_at) VALUES (?, ?, ?, ?, ?)",
            (
                event,
                (detail or "")[:500],
                session.get("admin_username") or session.get("student_name")
                or session.get("teacher_name") or "",
                request.remote_addr or "",
                datetime.utcnow().isoformat(),
            ),
        )
        db.commit()
    except Exception:
        pass


# ===================== حماية الوصول للملفات الثابتة =====================
_SAFE_STATIC_RX = re.compile(r"\.(png|jpe?g|gif|webp|mp4|webm|mov|m4v|css|js|ico|txt|woff2?|json|pdf|docx?|xlsx?|pptx?)$", re.I)


@app.route("/uploads/<path:filename>")
def protected_upload(filename):
    """يخدم ملفات uploads بس اللي امتدادها آمن (صور/فيديو) - أي ملف تنفيذي
    (PHP/HTML/SVG...) بيتطلب 404 عشان ميتعرضش ولا يتنفذ في المتصفح. المجلد
    نفسه برّه static تمامًا فمفيش أي طريقة تانية يوصل له."""
    safe = os.path.normpath(filename).replace("\\", "/")
    if safe.startswith("../") or safe.startswith("/") or ".." in safe.split("/"):
        abort(404)
    if not _SAFE_STATIC_RX.search(safe):
        abort(404)
    full = os.path.join(UPLOAD_FOLDER, safe)
    if not os.path.isfile(full):
        abort(404)
    with open(full, "rb") as f:
        head = f.read(MALWARE_SCAN_HEAD)
    if scan_file_for_malware(head):
        abort(403)
    return send_from_directory(UPLOAD_FOLDER, safe, as_attachment=False)


MAX_CHAPTERS_PER_LESSON = 10
MAX_QUESTIONS_PER_ASSESSMENT = 56  # أقصى عدد أسئلة في الامتحان/الواجب الواحد
# حد أسئلة شات الذكاء الاصطناعي: أقصى عدد أسئلة للطالب الواحد في الدقيقة
# وحد أقصى لطول السؤال - عشان مفيش حد يعمل سبام أو يخلّي الرسائل تكتل.
CHAT_MAX_QUESTIONS_PER_MINUTE = 6
CHAT_MAX_QUESTION_LENGTH = 2000
# مدة سكون أقصاها الجلسة النشطة الواحدة (جهاز واحد): لو مفيش نشاط من الجهاز
# الأول خلال المدة دي، بيسمح للجهاز التاني بدخول. النبضات (heartbeat) بتحدّث
# آخر نشاط فبتديم الجلسة طول ما الجهاز الأول شغال.
STUDENT_SESSION_MAX_IDLE_SECONDS = 60 * 60
# شعب الثانوية العامة + مسارات البكالوريا الرسمية الجديدة. الطالب بيختار واحد
# منهم عند التسجيل، والمدرس بيحدد الشعبة/المسار عند رفع كل حصة — فبتظهر للطالب
# الحصص اللي على شعبته (أو المسار) بس، والحصص من غير تحديد بتظهر للجميع.
SECONDARY_STREAMS = ["أدبي", "علمي علوم", "علمي رياضة"]
BAC_STREAMS = ["الطب وعلوم الحياة", "الهندسة وعلوم الحاسب", "الأعمال", "الآداب والفنون"]
# عدد المهمات اللي بيظهره للطالب في شاشة "مهماتي" (من 1 لـ 10)
STUDENT_TASKS_COUNT = 10
# رسائل التهنئة اللي بتتقال للطالب لما يخلّص مهمة (عشوائية كل مرة)
STUDENT_TASK_CONGRATS = [
    "اشطر كتكوت 🐥",
    "اجمد يا نجم ⭐",
    "ايوا يشبح 💪",
    "ده أنت عبقري بجد! 🧠",
    "بطل خارق بصراحة 🦸",
    "ربنا يخليك ليا يا بطل 🏆",
    "تسلم إيدك يا محترف 👏",
    "أنت رهيب والله 🚀",
    "جامد أوي كده 🎉",
    "برافو عليك يا بطل 🌟",
]
app.config["MAX_CONTENT_LENGTH"] = MAX_VIDEO_BYTES + (5 * 1024 * 1024)  # + headroom for the rest of the form


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def _inject_csrf_token():
    return {"csrf_token": csrf_token}


# ---- اللغة (عربي / English) ----
LANG_COOKIE = "seniors_lang"
MASCOT_LINES = {
    "ar": [
        "هاي يا اشطر كتكوت 🕸️😎",
        "اية رأيك في المذاكرة النهارده؟ 📚",
        "كمّل، أنا معاك 💪",
        "بصاصة العناكب في خدمتك 🕷️",
    ],
    "en": [
        "Hey, katkoot! 🕸️😎",
        "How about studying today? 📚",
        "Keep going, I got you 💪",
        "Spidey at your service 🕷️",
    ],
}


@app.before_request
def set_language():
    g.lang = "ar"
    cookie_lang = request.cookies.get(LANG_COOKIE)
    if cookie_lang in ("ar", "en"):
        g.lang = cookie_lang
    if request.args.get("lang") in ("ar", "en"):
        g.lang = request.args.get("lang")


@app.context_processor
def inject_language():
    def L(key):
        entry = UI_TRANSLATIONS.get(key)
        if not entry:
            return key
        return entry.get(g.lang, entry.get("ar", key))

    def T(text):
        if not isinstance(text, str):
            return text
        if g.lang == "ar":
            return text
        return PHRASES.get(text, text)

    return {
        "lang": g.lang,
        "L": L,
        "T": T,
        "mascot_lines": MASCOT_LINES.get(g.lang, MASCOT_LINES["ar"]),
        "congrats_map": CONGRATS if g.lang == "en" else {},
    }


@app.context_processor
def inject_notifications():
    """عدادات الإشعارات المعروضة على لوجو المنصة:
    - للأدمن: عدد طلبات تقارير ولي الأمر غير المقروءة (بادج على اللوجو).
    - لولي الأمر: علامة إن تقريره اتسلم للإدارة.
    وكمان رقم دعم المنصة للعرض لولي الأمر."""
    data = {
        "admin_notif_count": 0,
        "parent_report_requested": False,
        "support_phone": "",
    }
    try:
        db = get_db()
        data["support_phone"] = _support_phone(db)
        if session.get("admin_id"):
            data["admin_notif_count"] = db.execute(
                "SELECT COUNT(*) c FROM admin_notifications WHERE is_read = 0"
            ).fetchone()["c"]
        if session.get("parent_student_id"):
            data["parent_report_requested"] = bool(db.execute(
                "SELECT COUNT(*) c FROM admin_notifications "
                "WHERE student_id = ? AND is_read = 0",
                (session["parent_student_id"],),
            ).fetchone()["c"])
    except Exception:
        pass
    return data


@app.route("/lang/<lang>")
def set_lang(lang):
    if lang not in ("ar", "en"):
        lang = "ar"
    resp = redirect(request.referrer or url_for("home"))
    resp.set_cookie(LANG_COOKIE, lang, max_age=60 * 60 * 24 * 365, samesite="Lax")
    return resp


@app.before_request
def protect_from_csrf():
    if app.config.get("TESTING"):
        return None
    if request.method != "POST":
        return None
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if supplied and supplied == session.get("csrf_token"):
        return None
    return ("طلب مرفوض: توكن الحماية ناقص أو قديم. حدّث الصفحة وحاول تاني.", 403)


@app.after_request
def _add_security_headers(resp):
    """هيدرات أمان بتحمي من أنواع هجمات شائعة (clickjacking, MIME sniffing,
    حماية الجلسة من مواقع تانية...). الـ CSP متوازنة عشان متكسرش القالب الحالي
    (فيه جافاسكريبت وستايل inline + خطوط قوقل) لكنها بتقفل مصادر خارجية تانية."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "media-src 'self' https: blob:; "
        "frame-src https:; "
        "connect-src 'self' https:; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
    )
    if request.headers.get("X-Forwarded-Proto") == "https":
        resp.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return resp


@app.before_request
def recheck_blocked_accounts():
    """لو الإدارة قفلت/شالت حساب وهو لسه فاتح في جهاز — بيتطرد فورًا في أي
    طلب بدل ما يفضل قدام حاجات محظورة. فحص سريع على كل دور نشط."""
    if request.path.startswith("/static"):
        return None
    if session.get("student_id"):
        db = get_db()
        row = db.execute(
            "SELECT is_blocked FROM students WHERE id = ?", (session["student_id"],)
        ).fetchone()
        if not row or row["is_blocked"]:
            session.clear()
            return redirect(url_for("student_login"))
    elif session.get("teacher_id"):
        db = get_db()
        row = db.execute(
            "SELECT is_blocked FROM teachers WHERE id = ?", (session["teacher_id"],)
        ).fetchone()
        if not row or row["is_blocked"]:
            session.clear()
            return redirect(url_for("teacher_pick"))
    elif session.get("admin_id"):
        db = get_db()
        row = db.execute(
            "SELECT id FROM admins WHERE id = ?", (session["admin_id"],)
        ).fetchone()
        if not row:
            session.clear()
            return redirect(url_for("admin_login"))
    return None


def _sniff_media_ext(head: bytes) -> str | None:
    """بيفحص أول بايتات الملف ويحدد نوعه الحقيقي (signature) - من غير الاعتماد
    على اسم الملف اللي ممكن يكون مزيف. بيرجع نوع canonical واحد من:
    png / jpg / gif / webp / mp4 / webm - أو None لو الملف مش من الأنواع دي."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head[:3] == b"\xff\xd8\xff":
        return "jpg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "mp4"
    if head[:4] == b"\x1a\x45\xdf\xa3":
        return "webm"
    if head[:4] == b"%PDF":
        return "pdf"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole2"  # doc / xls / ppt
    if head[:4] == b"PK\x03\x04":
        return "zip"   # docx / xlsx / pptx (Office Open XML)
    return None


def save_uploaded_video(file_storage) -> str | None:
    """Saves an uploaded lesson video under uploads/videos with a
    random filename, and returns that filename, or None if there was no
    valid file. Serving is done via Flask's normal /static route - fine for
    a prototype, but for real traffic you'd want this behind a CDN/object
    storage (S3, Bunny, Cloudflare R2, ...) instead of the app server disk."""
    return save_video_securely(file_storage)


def save_uploaded_photo(file_storage) -> str | None:
    """Saves an uploaded profile photo under uploads with a random
    filename (so nobody can guess/overwrite someone else's photo) and
    returns that filename, or None if there was no valid file."""
    return save_photo_securely(file_storage)


def parse_question_rows(prefix: str, limit: int = MAX_QUESTIONS_PER_ASSESSMENT) -> list:
    """Parst صفوف أسئلة الامتحان/الواجب من الفورم: كل صف (نص سؤال + 4 خيارات +
    رقم الإجابة الصحيحة + فيديو شرح اختياري ملف أو رابط). بيرجع قايمة ديكتات
    جاهزة للتخزين، وبيتجاهل الصفوف الفاضية أو الناقصة (سؤال بلا خيارات أو
    الإجابة الصحيحة من غير نص). الحد الأقصى في السيرفر MAX_QUESTIONS_PER_ASSESSMENT."""
    texts = request.form.getlist(f"{prefix}_q_texts")
    a_opts = request.form.getlist(f"{prefix}_q_a")
    b_opts = request.form.getlist(f"{prefix}_q_b")
    c_opts = request.form.getlist(f"{prefix}_q_c")
    d_opts = request.form.getlist(f"{prefix}_q_d")
    corrects = request.form.getlist(f"{prefix}_q_correct")
    urls = request.form.getlist(f"{prefix}_q_urls")
    files = request.files.getlist(f"{prefix}_q_videos")

    rows = []
    for i in range(min(len(texts), limit)):
        text = (texts[i] or "").strip()
        options = [
            (a_opts[i].strip() if i < len(a_opts) else ""),
            (b_opts[i].strip() if i < len(b_opts) else ""),
            (c_opts[i].strip() if i < len(c_opts) else ""),
            (d_opts[i].strip() if i < len(d_opts) else ""),
        ]
        if not text or not any(options):
            continue
        try:
            correct = int(corrects[i]) if i < len(corrects) else 0
        except (TypeError, ValueError):
            correct = 0
        correct = max(0, min(3, correct))
        if not options[correct]:  # الإجابة الصحيحة لازم يكون ليه نص فعلي
            continue
        f = files[i] if i < len(files) else None
        vfile = save_uploaded_video(f) if f and f.filename else ""
        vurl = (urls[i].strip() if i < len(urls) else "")
        rows.append({
            "text": text,
            "options": options,
            "correct": correct,
            "vfile": vfile or "",
            "vurl": vurl,
        })
    return rows


def insert_assessment_rows(db, material_id: int, kind: str, title: str, rows: list) -> int | None:
    """بيحفظ امتحان/واجب جديد بأسئلته. بيرجع id الامتحان أو None لو مفيش أسئلة."""
    if not rows:
        return None
    cur = db.execute(
        "INSERT INTO assessments (material_id, kind, title, created_at) VALUES (?, ?, ?, ?)",
        (material_id, kind, title, datetime.utcnow().isoformat()),
    )
    assessment_id = cur.lastrowid
    for order, q in enumerate(rows):
        db.execute(
            "INSERT INTO assessment_questions "
            " (assessment_id, question_text, option_a, option_b, option_c, option_d, "
            "  correct_index, explain_video, explain_url, sort_order) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (assessment_id, q["text"], q["options"][0], q["options"][1], q["options"][2],
             q["options"][3], q["correct"], q["vfile"], q["vurl"], order),
        )
    return assessment_id


def material_access(db, material_id: int, student_id: int):
    """نفس قواعد فتح الدرس (مجاني/مشترى + مدة الإتاحة) عشان الامتحانات تحترمها."""
    material = db.execute("SELECT * FROM materials WHERE id = ?", (material_id,)).fetchone()
    if not material:
        return None, False
    purchase = db.execute(
        "SELECT * FROM purchases WHERE material_id = ? AND student_id = ?",
        (material_id, student_id),
    ).fetchone()
    unlocked = purchase is not None or material["price"] == 0
    if unlocked and material["access_days"] and purchase:
        purchased_at = datetime.fromisoformat(purchase["purchased_at"])
        deadline = purchased_at + timedelta(days=material["access_days"])
        if (deadline - datetime.utcnow()).total_seconds() <= 0:
            unlocked = False
    return material, unlocked


def lesson_completed(db, material_id: int, student_id: int) -> bool:
    """إتمام الحصة = مشاهدة فيديوهاتها فعليًا (وقت مشاهدة حقيقي من video_watch).
    الحصص من غير فيديوهات بتتحسب مخلصة تلقائيًا عشان التسلسل يكمّل.""" 
    has_videos = db.execute(
        "SELECT 1 FROM lesson_videos WHERE material_id = ? LIMIT 1", (material_id,)
    ).fetchone()
    m = db.execute(
        "SELECT video_filename, video_url FROM materials WHERE id = ?", (material_id,)
    ).fetchone()
    if not has_videos and not (m and (m["video_filename"] or m["video_url"])):
        return True
    w = db.execute(
        "SELECT seconds FROM video_watch WHERE material_id = ? AND student_id = ?",
        (material_id, student_id),
    ).fetchone()
    return w is not None and (w["seconds"] or 0) > 0


def is_lesson_exempt(db, student_id: int, material_id: int) -> bool:
    """استثناء من الإدارة: الحصة متفتحة للطالب دي من غير التسلسل، وبتحسب مخلصة."""
    return db.execute(
        "SELECT 1 FROM admin_exemptions WHERE student_id = ? AND material_id = ?",
        (student_id, material_id),
    ).fetchone() is not None


def stream_matches(material_stream: str, student_stream: str) -> bool:
    """الحصة اللي من غير شعبة (عامة) بتظهر لكل الطلاب، واللي ليها شعبة/مسار
    بتظهر بس لطالب نفس الشعبة/المسار."""
    return (not material_stream) or material_stream == student_stream


def get_student_stream(db, student_id: int) -> str:
    row = db.execute("SELECT stream FROM students WHERE id = ?", (student_id,)).fetchone()
    return row["stream"] if row and row["stream"] else ""


def is_student_blocked(db, teacher_id, student_id):
    """لو المدرس عمِل بلوك للطالب، بيرجع صف البلوك — ولا بيرجع None.
    المحظور ميعرفش يبص على حصص المدرس ولا يشتري ولا يكلمه غير لما
    الإدارة/الدعم الفني يشيل البلوك."""
    if not teacher_id or not student_id:
        return None
    return db.execute(
        "SELECT * FROM teacher_student_blocks WHERE teacher_id = ? AND student_id = ?",
        (teacher_id, student_id),
    ).fetchone()


def get_sequence_blocker(db, material, student_id):
    """أقرب حصة (نفس المدرس + نفس الشعبة/المسار، بترتيب الإضافة = material id)
    قبل الحصة الحالية لسه الطالب مخلصهاش وبتقفله الحالية — أو None لو كل اللي
    قبلها مخلصين أو مستثنيين. الحصص دي بتفتح بالتسلسل: مينفعش حصة تفتح غير لما
    كل اللي قبلها عند نفس المدرس تخلص."""
    if is_lesson_exempt(db, student_id, material["id"]):
        return None
    student_stream = get_student_stream(db, student_id)
    previous = db.execute(
        "SELECT id, title FROM materials WHERE teacher_id = ? AND id < ? "
        "AND (stream = '' OR stream = ?) ORDER BY id",
        (material["teacher_id"], material["id"], student_stream),
    ).fetchall()
    for p in previous:
        if not is_lesson_exempt(db, student_id, p["id"]) and not lesson_completed(db, p["id"], student_id):
            return p
    return None


def sequence_locks_for_materials(db, materials: list, student_id: int) -> None:
    """يملي على كل حصة في القايمة: sequence_locked (هل مقفولة بسبب تسلسل؟)
    و sequence_blocked_by (عنوان الحصة اللي لازم تخلصها الأول). بيمشي بترتيب
    الإضافة (id تصاعدي) عشان يحدد أول حصة لسه مخلصهاش — وهي بتبقى مفتوحة،
    وكل اللي بعدها بيتقفل. الحصص المستثناة من الإدارة بتتحسب مخلصة."""
    first_incomplete = None
    for m in sorted(materials, key=lambda m: m["id"]):
        completed = is_lesson_exempt(db, student_id, m["id"]) or lesson_completed(db, m["id"], student_id)
        m["sequence_completed"] = completed
        m["sequence_locked"] = first_incomplete is not None
        m["sequence_blocked_by"] = first_incomplete
        if first_incomplete is None and not completed:
            first_incomplete = m["title"]


def ensure_student_tasks(db, student_id: int) -> None:
    """يضمن إن الطالب عنده الـ 10 مهمات في شاشة "مهماتي" (1..10) — لو
    مش موجودين (طالب قديم أو جديد) بيتعملوا على طول. بيرجع فاضي وبيشتغل
    بطريقة آمنة للتكرار (INSERT OR IGNORE)."""
    now = datetime.utcnow().isoformat()
    existing = {
        r["task_number"]
        for r in db.execute(
            "SELECT task_number FROM student_tasks WHERE student_id = ?", (student_id,)
        ).fetchall()
    }
    for n in range(1, STUDENT_TASKS_COUNT + 1):
        if n in existing:
            continue
        db.execute(
            "INSERT OR IGNORE INTO student_tasks "
            "(student_id, student_name, task_number, created_at) VALUES (?, ?, ?, ?)",
            (student_id, _student_name_by_id(db, student_id), n, now),
        )
    db.commit()


def _student_name_by_id(db, student_id: int) -> str:
    row = db.execute("SELECT name FROM students WHERE id = ?", (student_id,)).fetchone()
    return row["name"] if row else ""


def parse_iso(ts):
    """يحوّل timestamp ISO للتخزين (UTC) لـ datetime — بيرجع None لو مش قابل
    للقراءة أو فاضي."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def stopwatch_elapsed(row) -> int:
    """بيحسب الوقت الفعلي اللي فاضل على المهمة بالثواني: الثواني المحفوظة
    (لما تكون واقفة) + الوقت اللي مر من آخر بداية لو الساعة شغالة حالياً."""
    base = row["stopwatch_seconds"] or 0
    if row["stopwatch_running"]:
        started = parse_iso(row["stopwatch_started_at"])
        if started:
            base += int((datetime.utcnow() - started).total_seconds())
    return max(base, 0)


def add_stopwatch_elapsed(db, row) -> None:
    """بيضيف الوقت اللي مر من آخر بداية للثواني المحفوظة وبيوقف الساعة
    (أي إن الساعة واقفة). بيستخدم لما الطالب يدوس إيقاف أو يعلّم المهمة مكتملة."""
    started = parse_iso(row["stopwatch_started_at"])
    if row["stopwatch_running"] and started:
        db.execute(
            "UPDATE student_tasks SET stopwatch_seconds = stopwatch_seconds + ?, "
            "stopwatch_running = 0, stopwatch_started_at = NULL WHERE id = ?",
            (int((datetime.utcnow() - started).total_seconds()), row["id"]),
        )
    else:
        db.execute(
            "UPDATE student_tasks SET stopwatch_running = 0, stopwatch_started_at = NULL WHERE id = ?",
            (row["id"],),
        )


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        # WAL: القراءة والكتابة بتشتغلوا مع بعض من غير ما يقفلوا بعض — أساسي
        # مع 100 طالب شغالين في نفس الوقت. busy_timeout بيخلي الكتابة تنتظر
        # بدل ما يرمي "database is locked" طول ما مفيش تضارب حقيقي.
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA busy_timeout = 8000")
        g.db.execute("PRAGMA synchronous = NORMAL")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.context_processor
def inject_active_announcements():
    """Makes active announcements available in every template as
    `active_announcements`, without every route having to fetch them by
    hand. base.html only actually shows them for logged-in students."""
    if "student_id" not in session:
        return {"active_announcements": []}
    db = get_db()
    rows = db.execute(
        "SELECT * FROM announcements WHERE is_active = 1 ORDER BY id DESC"
    ).fetchall()
    return {"active_announcements": rows}


def init_db():
    fresh = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            subject TEXT NOT NULL,
            bio TEXT DEFAULT '',
            account_code TEXT UNIQUE,
            password_hash TEXT,
            phone TEXT DEFAULT '',
            photo TEXT,
            workplace TEXT DEFAULT '',
            commission_percent REAL DEFAULT 0,
            is_blocked INTEGER DEFAULT 0,
            must_change_password INTEGER DEFAULT 0
        );

        -- الصفوف الدراسية (تانية إعدادي ... تالتة ثانوي). ثابتة نسبيًا لكنها
        -- جدول عادي وليست Enum مبرمجة، فتقدر تتعدل من قاعدة البيانات لو احتجت.
        CREATE TABLE IF NOT EXISTS stages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            sort_order INTEGER NOT NULL
        );

        -- الأنظمة الدراسية (حكومي / IG / أمريكي ...). جدول قابل للتوسع -
        -- تضيف نظام جديد بسطر واحد من غير ما تلمس الكود.
        CREATE TABLE IF NOT EXISTS curricula (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );

        -- إيه اللي كل مدرس بيدرّسه بالظبط: (نظام + صف + مادة). مدرس واحد
        -- ممكن يكون ليه أكتر من سطر هنا (مثلاً رياضيات حكومي وIG مع بعض).
        CREATE TABLE IF NOT EXISTS teacher_offerings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            curriculum_id INTEGER NOT NULL,
            stage_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES teachers(id),
            FOREIGN KEY (curriculum_id) REFERENCES curricula(id),
            FOREIGN KEY (stage_id) REFERENCES stages(id),
            UNIQUE (teacher_id, curriculum_id, stage_id, subject)
        );

        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            curriculum_id INTEGER,
            stage_id INTEGER,
            subject TEXT DEFAULT '',
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'نص',   -- نص / فيديو / امتحان / واجب
            video_url TEXT DEFAULT '',
            video_filename TEXT,
            access_days INTEGER,
            price REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES teachers(id),
            FOREIGN KEY (curriculum_id) REFERENCES curricula(id),
            FOREIGN KEY (stage_id) REFERENCES stages(id)
        );

        -- سناتر بيع أكواد الشحن (خطوة أولى - لسه معندناش أكواد فعلية،
        -- بس محتاجين نعرف مصدر كل عملية شراء).
        CREATE TABLE IF NOT EXISTS centers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            purchased_at TEXT NOT NULL,
            amount REAL DEFAULT 0,
            source_type TEXT DEFAULT 'مباشر',   -- مباشر / سنتر / فيزا / فوري / محفظة إلكترونية / هدية
            center_id INTEGER,
            gifted_by TEXT,   -- اسم الطالب اللي أهدى الحصة، لو كانت هدية
            gifted_by_id INTEGER,   -- حساب الطالب اللي أهدى الحصة (للفصل الصحيح)
            FOREIGN KEY (material_id) REFERENCES materials(id),
            FOREIGN KEY (center_id) REFERENCES centers(id),
            UNIQUE (material_id, student_id)
        );

        -- شحن رصيد الطالب - محاكاة دلوقتي (مفيش ربط حقيقي ببوابة دفع بعد).
        CREATE TABLE IF NOT EXISTS wallet_topups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            amount REAL NOT NULL,
            method TEXT NOT NULL,   -- فيزا / فوري / محفظة إلكترونية
            created_at TEXT NOT NULL
        );

        -- حساب الطالب الحقيقي (بدل تسجيل الدخول بالاسم بس). كل طالب بياخد
        -- كود حساب فريد وباسورد بيتبعتله برسالة SMS (محاكاة دلوقتي).
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            parent_name TEXT NOT NULL,
            parent_job TEXT DEFAULT '',
            student_phone TEXT NOT NULL,
            parent_phone TEXT NOT NULL,
            national_id TEXT NOT NULL,
            google_email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            photo TEXT,
            is_blocked INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            rating INTEGER NOT NULL,       -- 1 to 5
            comment TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (material_id, student_id)
        );

        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            role TEXT NOT NULL,          -- 'student' or 'assistant'
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES teachers(id)
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            kind TEXT NOT NULL,          -- homework / exam / assessment
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES teachers(id)
        );
        CREATE INDEX IF NOT EXISTS idx_notifications_teacher ON notifications(teacher_id, is_read);

        -- طلبات تقارير ولي الأمر: بتتبعت للإدارة، والإدارة بتبعتها واتساب.
        CREATE TABLE IF NOT EXISTS admin_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL DEFAULT 'parent_report',
            student_id INTEGER NOT NULL,
            student_name TEXT NOT NULL,
            report_text TEXT NOT NULL,
            phone TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',   -- pending / sent / failed
            created_at TEXT NOT NULL,
            sent_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_admin_notifications ON admin_notifications(status, is_read);

        CREATE TABLE IF NOT EXISTS generated_docs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            kind TEXT NOT NULL,          -- 'exam' or 'summary'
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES teachers(id)
        );

        -- حسابات دخول لوحة تحكم الإدارة. باسورد مشفّر (مش نص عادي)،
        -- على عكس دخول الطالب/المدرس اللي لسه بالاسم بس (بروتوتايب).
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'اداري',   -- رئيس / اداري
            photo TEXT,
            login_start_hour INTEGER,   -- 0-23, مع login_end_hour بيحددوا وقت
            login_end_hour INTEGER,     -- الشغل المسموح بيه للإداري (اختياري)
            created_at TEXT NOT NULL
        );

        -- تسليمات الواجبات. طالب واحد بيسلّم مرة واحدة لكل واجب (لسه من
        -- غير إعادة تسليم بعد التصحيح - تحسين مستقبلي).
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            answer_text TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            grade TEXT,
            feedback TEXT,
            graded_at TEXT,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (material_id, student_id)
        );

        -- تسليمات الامتحانات. نفس منطق الواجبات بالظبط - الطالب بيحل
        -- الامتحان ويسلّمه، والمدرس بيصححه ويحط درجة وملاحظات.
        CREATE TABLE IF NOT EXISTS exam_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            answer_text TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            grade TEXT,
            feedback TEXT,
            graded_at TEXT,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (material_id, student_id)
        );

        -- تتسجل مرة كل ما طالب يفتح صفحة مدرس ويشوف حصة مفتوحة - المصدر
        -- لرسم "كام مرة اتفرجوا على كل حصة" في لوحة المدرس.
        CREATE TABLE IF NOT EXISTS lesson_views (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            viewed_at TEXT NOT NULL,
            FOREIGN KEY (material_id) REFERENCES materials(id)
        );

        -- نبضة كل دقيقة من المتصفح وهو فاتح صفحة مدرس - مصدر تقريبي لعدد
        -- ساعات المذاكرة (مفيش تتبع دقيق للـ focus/idle، ده أبسط تقدير).
        CREATE TABLE IF NOT EXISTS study_heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            teacher_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );

        -- وقت مشاهدة فعلي لكل فيديو، مبني على تقدّم التشغيل الحقيقي (event
        -- timeupdate) مش مجرد فتح الصفحة - فمايزيدش عن مدة الفيديو نفسه في
        -- أي تشغيلة واحدة.
        CREATE TABLE IF NOT EXISTS video_watch (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            seconds REAL NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (material_id, student_id)
        );

        -- إعلانات الإدارة (رئيس أو اداري) اللي بتظهر لكل الطلاب.
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            emoji TEXT DEFAULT '📢',
            created_by TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );

        -- تحويل رصيد بين طالب وصاحبه.
        CREATE TABLE IF NOT EXISTS wallet_transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_student_id INTEGER,
            to_student_id INTEGER,
            from_student TEXT NOT NULL,
            to_student TEXT NOT NULL,
            amount REAL NOT NULL,
            created_at TEXT NOT NULL
        );

        -- شات مباشر بين طالبين (منفصل عن شات المساعد الذكي مع المدرس).
        -- بيستخدم كود الحساب (مش الاسم) عشان الاسم ممكن يتكرر بين طلاب.
        CREATE TABLE IF NOT EXISTS student_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_code TEXT NOT NULL,
            to_code TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        -- بيانات فيزا الإدارة (الرئيس). الإيرادات بتتحول على الفيزا دي تلقائيًا،
        -- والمشروع محاكاة: مفيش ربط حقيقي ببوابة دفع، بس الرقم بيتحفظ هنا
        -- عشان يظهر للرئيس في لوحته مع التقرير اليومي للدخل.
        CREATE TABLE IF NOT EXISTS visa_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            holder_name TEXT NOT NULL DEFAULT '',
            card_number TEXT NOT NULL DEFAULT '',
            bank_name TEXT NOT NULL DEFAULT ''
        );
        INSERT OR IGNORE INTO visa_settings (id) VALUES (1);

        -- إعدادات عامة للمنصة (key-value). بتتظبط من تبويب "الإعدادات" في
        -- لوحة الإدارة، ومش محتاجة تعديل كود.
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );

        -- دفعات عمولات المدرسين: سجل بكل مرة الإدارة صرفت فيها عمولة لمدرس.
        -- بتتعمل من لوحة الإدارة، ولما تتسجل بيظهر تاريخ الدفع في حساب المدرس.
        CREATE TABLE IF NOT EXISTS payouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            teacher_name TEXT NOT NULL,
            amount REAL NOT NULL,
            period TEXT NOT NULL,
            paid_at TEXT NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES teachers(id)
        );

        -- فيديوهات الدرس الواحد: المدرس يقدر يرفع أكتر من فيديو، كل واحد
        -- بعنوانه (ورابطه أو ملفه المرفوع). كل درس بيتفتح في شاشة مستقلة
        -- بتعرض كل الفيديوهات بالترتيب.
        CREATE TABLE IF NOT EXISTS lesson_videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            video_url TEXT DEFAULT '',
            video_filename TEXT,
            chapter_id INTEGER,
            sort_order INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            description TEXT DEFAULT '',
            FOREIGN KEY (material_id) REFERENCES materials(id)
        );

        -- الشبترات: كل شبتر اسم بيختاره المدرس، وفيه الفيديوهات اللي عايزها.
        -- الدرس الواحد بيبقى فيه لحد 10 شبترات، وكل فيديو بيتبع شبتر.
        CREATE TABLE IF NOT EXISTS chapters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (material_id) REFERENCES materials(id)
        );

        -- الامتحانات والواجبات الإلكترونية (اختيار من متعدد) لكل درس. كل
        -- امتحان/واجب سيناريو مستقل ليه أسئلته وأجوبته بتصحيح فوري تلقائي.
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            kind TEXT NOT NULL DEFAULT 'امتحان',   -- 'امتحان' or 'واجب'
            title TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (material_id) REFERENCES materials(id)
        );

        -- أسئلة الامتحان/الواجب: نص السؤال + 4 خيارات + الإجابة الصحيحة +
        -- فيديو شرح اختياري بيتعرض للطالب لو غلط في السؤال بس.
        CREATE TABLE IF NOT EXISTS assessment_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            question_text TEXT NOT NULL,
            option_a TEXT NOT NULL DEFAULT '',
            option_b TEXT NOT NULL DEFAULT '',
            option_c TEXT NOT NULL DEFAULT '',
            option_d TEXT NOT NULL DEFAULT '',
            correct_index INTEGER NOT NULL DEFAULT 0,   -- 0 = أ, 1 = ب, 2 = ج, 3 = د
            explain_video TEXT DEFAULT '',              -- ملف فيديو شرح للغلط بس
            explain_url TEXT DEFAULT '',                -- أو رابط شرح خارجي
            sort_order INTEGER DEFAULT 0,
            FOREIGN KEY (assessment_id) REFERENCES assessments(id)
        );

        -- محاولات حل الطلاب: كل تسليم بييجي بنتيجة فورية (نسبة مئوية) +
        -- إجابات الطالب JSON عشان نعرض الغلط/الصح سؤال سؤال. الطالب يقدر
        -- يعيد الحل ومحاولاته كلها بتتسجل.
        CREATE TABLE IF NOT EXISTS assessment_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            answers TEXT NOT NULL,           -- JSON {question_id: 0..3}
            score REAL NOT NULL DEFAULT 0,   -- النسبة المئوية 0-100
            correct_count INTEGER DEFAULT 0,
            total_count INTEGER DEFAULT 0,
            submitted_at TEXT NOT NULL,
            FOREIGN KEY (assessment_id) REFERENCES assessments(id)
        );

        -- تسجيل دخول جهاز واحد: سطر واحد نشط لكل طالب (في أي وقت) - أول جهاز
        -- بس اللي بيفضل شغال، وأي تسجيل دخول تاني بيتشال طول ما الأول نشط
        -- (الآخر نشاط بتتحدث مع كل طلب/نبضة، ولو عدّت ساعة من غيره بيتسمح
        -- للجهاز الجديد يدخل وياخد السشن).
        CREATE TABLE IF NOT EXISTS student_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            logged_in_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            FOREIGN KEY (student_id) REFERENCES students(id)
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL,
            key TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 1,
            blocked_until TEXT,
            last_attempt_at TEXT NOT NULL,
            UNIQUE (scope, key)
        );

        -- سجل التدقيق الأمني: كل الأحداث المهمة (دخول خاطئ، رفض ملفات،
        -- تغيير إعدادات/باسوردات...) بيتسجلوا هنا للرقابة.
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            detail TEXT DEFAULT '',
            actor TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

        CREATE TABLE IF NOT EXISTS payment_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            kind TEXT NOT NULL,           -- 'buy' | 'topup'
            material_id INTEGER,
            amount REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',   -- pending / paid / failed / manual
            method TEXT DEFAULT '',
            proof_photo TEXT DEFAULT '',
            paymob_order_id INTEGER,
            paymob_transaction_id INTEGER,
            created_at TEXT NOT NULL,
            paid_at TEXT
        );

        CREATE TABLE IF NOT EXISTS recharge_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            amount REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'available',   -- available / used / disabled
            center_name TEXT DEFAULT '',
            created_by TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            used_by TEXT DEFAULT '',
            used_at TEXT
        );

        -- استثناءات الإدارة: سطر (طالب + حصة) بمعنى إن الحصة دي بتتفتح للطالب
        -- من غير ما يخلص اللي قبلها، وبتحسب في التسلسل كأنها مخلصة (ما بتقفلش
        -- اللي بعدها). بيفضّل الاستخدام للتعامل مع شكاوى الطلاب بس.
        CREATE TABLE IF NOT EXISTS admin_exemptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            material_id INTEGER NOT NULL,
            reason TEXT DEFAULT '',
            created_by TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (student_id, material_id)
        );

        -- مهماتي: 10 مهمات مرتبة للطالب (1..10). الطالب بيكتب نص كل مهمة
        -- بنفسه، وليها ساعة إيقاف بتحسب الوقت اللي فاضل شغال، ولما يعلّمها
        -- مكتملة بتحفظ رسالة التهنئة اللي طلعاله.
        CREATE TABLE IF NOT EXISTS student_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            task_number INTEGER NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            is_completed INTEGER NOT NULL DEFAULT 0,
            completed_at TEXT,
            congrats_message TEXT DEFAULT '',
            stopwatch_seconds INTEGER NOT NULL DEFAULT 0,
            stopwatch_running INTEGER NOT NULL DEFAULT 0,
            stopwatch_started_at TEXT,
            created_at TEXT NOT NULL,
            UNIQUE (student_id, task_number)
        );

        -- هدف اليوم: الطالب بيحدد عدد الدقائق اللي ناوي يذاكرها النهارده
        -- (أو في تاريخ معين). سطر واحد لكل طالب لكل يوم.
        CREATE TABLE IF NOT EXISTS student_daily_goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            goal_date TEXT NOT NULL,              -- YYYY-MM-DD
            target_minutes INTEGER NOT NULL DEFAULT 60,
            note TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE (student_id, goal_date)
        );

        -- بنك الامتحانات: أرشيف منظم للامتحانات والنماذج اللي بتضيفه الإدارة
        -- للطلاب. بيشتغل كمكتبة تحميل (ملف PDF/Word) مش امتحان تفاعلي.
        CREATE TABLE IF NOT EXISTS exam_bank (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            subject TEXT DEFAULT '',
            stage_id INTEGER,
            stream_id INTEGER,               -- الشعبة (علمي علوم / أدبي ...)
            curriculum_id INTEGER,           -- النظام (حكومي / IG / أمريكي)
            term INTEGER DEFAULT 0,             -- 0 = عامة/الكل
            year INTEGER,
            description TEXT DEFAULT '',
            file_path TEXT DEFAULT '',
            is_published INTEGER NOT NULL DEFAULT 1,
            downloads INTEGER NOT NULL DEFAULT 0,
            created_by_type TEXT DEFAULT '',       -- 'admin' / 'teacher'
            created_by_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (stage_id) REFERENCES stages(id),
            FOREIGN KEY (stream_id) REFERENCES streams(id),
            FOREIGN KEY (curriculum_id) REFERENCES curricula(id)
        );

        -- الشعب الدراسية (علمي علوم / علمي رياضة / أدبي ...). جدول ثابت قابل
        -- للتوسعة من قاعدة البيانات.
        CREATE TABLE IF NOT EXISTS streams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            sort_order INTEGER NOT NULL
        );

        -- كل مواد المنصة (لغة عربية، فيزياء، رياضيات، تاريخ ...) — بنك الأسئلة
        -- والورقة المطبوعة بيستخدموها. جدول مرجعي يتوسع من قاعدة البيانات.
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            sort_order INTEGER NOT NULL
        );

        -- ربط الشعب بالمواد: الشعبة الواحدة ليها أكتر من مادة، والمادة الواحدة
        -- ممكن تخص أكتر من شعبة (مثلاً لغة عربية = مشتركة بين كل الشعب).
        CREATE TABLE IF NOT EXISTS stream_subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stream_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            UNIQUE (stream_id, subject_id),
            FOREIGN KEY (stream_id) REFERENCES streams(id),
            FOREIGN KEY (subject_id) REFERENCES subjects(id)
        );

        -- بنك الأسئلة: أسئلة اختيار من متعدد منظمة بالصف والشعبة والمادة والنظام.
        -- الأدمن والمدرسين بيضيفوا فيها، والطلاب بيلموا 50 سؤال كل يوم
        -- (لِمة اليوم) وبياخدوا نموذج شرح وإجابة بعد ما يحلوها.
        CREATE TABLE IF NOT EXISTS question_bank (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question_text TEXT NOT NULL,
            option_a TEXT DEFAULT '',
            option_b TEXT DEFAULT '',
            option_c TEXT DEFAULT '',
            option_d TEXT DEFAULT '',
            correct_index INTEGER DEFAULT 0,     -- 0=a / 1=b / 2=c / 3=d
            explanation TEXT DEFAULT '',          -- شرح الإجابة الصح
            difficulty INTEGER DEFAULT 1,        -- 1=سهل / 2=متوسط / 3=صعب
            stage_id INTEGER,
            stream_id INTEGER,
            subject_id INTEGER,
            curriculum_id INTEGER,
            is_published INTEGER NOT NULL DEFAULT 1,
            created_by_type TEXT DEFAULT 'admin',  -- admin / teacher
            created_by_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (stage_id) REFERENCES stages(id),
            FOREIGN KEY (stream_id) REFERENCES streams(id),
            FOREIGN KEY (subject_id) REFERENCES subjects(id),
            FOREIGN KEY (curriculum_id) REFERENCES curricula(id)
        );

        -- لِمة اليوم: بيان لكل طالب، كل يوم 50 سؤال.
        CREATE TABLE IF NOT EXISTS daily_sets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            set_date TEXT NOT NULL,               -- YYYY-MM-DD
            status TEXT NOT NULL DEFAULT 'active', -- active / submitted
            score INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            submitted_at TEXT,
            FOREIGN KEY (student_id) REFERENCES students(id)
        );

        -- أسئلة كل لِمة + إجابة الطالب على كل سؤال.
        CREATE TABLE IF NOT EXISTS daily_set_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            set_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            answer_index INTEGER,                 -- اختيار الطالب (NULL = متجاوبش)
            is_correct INTEGER,
            UNIQUE (set_id, question_id),
            FOREIGN KEY (set_id) REFERENCES daily_sets(id),
            FOREIGN KEY (question_id) REFERENCES question_bank(id)
        );

        -- طلبات الدعم الاجتماعي: 'orphan' = تكفل الأيتام، 'inability' = عدم
        -- المقدرة على الدفع. بتتراجع من لوحة الإدارة.
        CREATE TABLE IF NOT EXISTS support_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,                     -- 'orphan' | 'inability'
            student_id INTEGER,
            student_name TEXT NOT NULL,
            student_code TEXT DEFAULT '',
            contact TEXT DEFAULT '',
            message TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending', -- pending / approved / rejected
            admin_note TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            resolved_at TEXT
        );

        CREATE TABLE IF NOT EXISTS teacher_contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            contract_type TEXT NOT NULL DEFAULT 'عمولة', -- عمولة / ثابت شهري / حساب لكل حصة
            amount REAL NOT NULL DEFAULT 0,
            start_date TEXT DEFAULT '',
            end_date TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'نشط',           -- نشط / منتهي
            created_by TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS teacher_student_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            reason TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE (teacher_id, student_id)
        );
        """
    )
    db.commit()

    # Lightweight migration: DBs created before this feature won't have the
    # 'price' column on materials yet.
    cols = [r[1] for r in db.execute("PRAGMA table_info(materials)")]
    if "price" not in cols:
        db.execute("ALTER TABLE materials ADD COLUMN price REAL NOT NULL DEFAULT 0")
        db.commit()

    # Migration: DBs created before stages/curricula existed won't have
    # curriculum_id/stage_id/subject on materials yet.
    if "curriculum_id" not in cols:
        db.execute("ALTER TABLE materials ADD COLUMN curriculum_id INTEGER")
        db.execute("ALTER TABLE materials ADD COLUMN stage_id INTEGER")
        db.execute("ALTER TABLE materials ADD COLUMN subject TEXT DEFAULT ''")
        db.commit()

    ensure_stages_and_curricula(db)

    # Migration: DBs created before streams/subjects existed won't have the
    # new columns on exam_bank.
    eb_cols = [r[1] for r in db.execute("PRAGMA table_info(exam_bank)")]
    if "stream_id" not in eb_cols:
        db.execute("ALTER TABLE exam_bank ADD COLUMN stream_id INTEGER")
    if "curriculum_id" not in eb_cols:
        db.execute("ALTER TABLE exam_bank ADD COLUMN curriculum_id INTEGER")
    if "created_by_type" not in eb_cols:
        db.execute("ALTER TABLE exam_bank ADD COLUMN created_by_type TEXT DEFAULT ''")
        db.execute("ALTER TABLE exam_bank ADD COLUMN created_by_id INTEGER")
        db.commit()
    db.commit()
    # Migration: difficulty على بنك الأسئلة (1 سهل / 2 متوسط / 3 صعب).
    qb_cols = [r[1] for r in db.execute("PRAGMA table_info(question_bank)")]
    if "difficulty" not in qb_cols:
        db.execute("ALTER TABLE question_bank ADD COLUMN difficulty INTEGER DEFAULT 1")
        db.commit()
    db.commit()
    ensure_streams_and_subjects(db)
    ensure_question_bank_tables(db)

    # Migration: DBs created before the chapters feature won't have
    # chapter_id on lesson_videos yet.
    lv_cols = [r[1] for r in db.execute("PRAGMA table_info(lesson_videos)")]
    if "chapter_id" not in lv_cols:
        db.execute("ALTER TABLE lesson_videos ADD COLUMN chapter_id INTEGER")
        db.commit()
    if "description" not in lv_cols:
        db.execute("ALTER TABLE lesson_videos ADD COLUMN description TEXT DEFAULT ''")
        db.commit()

    # Migration: اشتراك الذكاء الاصطناعي للمدرسين — المدرس بيستخدم مساعده
    # الذكي (توليد امتحانات/ملخصات + شات الطلاب مع المساعد) بس لو ليه اشتراك
    # ساري. التاريخ ده = آخر مدة انتهاء، وبيتجدّد/بيتضاف فوق اللي موجود.
    t_cols = [r[1] for r in db.execute("PRAGMA table_info(teachers)")]
    if "ai_subscription_expires_at" not in t_cols:
        db.execute("ALTER TABLE teachers ADD COLUMN ai_subscription_expires_at TEXT DEFAULT ''")
        db.commit()
    po_cols = [r[1] for r in db.execute("PRAGMA table_info(payment_orders)")]
    if "payer_role" not in po_cols:
        db.execute("ALTER TABLE payment_orders ADD COLUMN payer_role TEXT DEFAULT 'student'")
        db.commit()
    rc_cols = [r[1] for r in db.execute("PRAGMA table_info(recharge_codes)")]
    if "used_by_role" not in rc_cols:
        db.execute("ALTER TABLE recharge_codes ADD COLUMN used_by_role TEXT DEFAULT 'student'")
        db.commit()
    db.execute(
        """CREATE TABLE IF NOT EXISTS teacher_ai_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            method TEXT DEFAULT '',
            code TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            expires_at TEXT,
            granted_by TEXT DEFAULT ''
        )"""
    )
    db.commit()

    # Backfill: any material/teacher without a curriculum+stage yet gets
    # mapped to a sensible default (حكومي / تالتة ثانوي) so the app keeps
    # working for data created before this feature existed.
    default_curriculum_id = db.execute("SELECT id FROM curricula WHERE name = 'حكومي'").fetchone()["id"]
    default_stage_id = db.execute("SELECT id FROM stages WHERE name = 'تالتة ثانوي'").fetchone()["id"]

    orphan_materials = db.execute("SELECT id, teacher_id FROM materials WHERE curriculum_id IS NULL").fetchall()
    for m in orphan_materials:
        teacher = db.execute("SELECT subject FROM teachers WHERE id = ?", (m["teacher_id"],)).fetchone()
        subject = teacher["subject"] if teacher else ""
        db.execute(
            "UPDATE materials SET curriculum_id = ?, stage_id = ?, subject = ? WHERE id = ?",
            (default_curriculum_id, default_stage_id, subject, m["id"]),
        )
    if orphan_materials:
        db.commit()

    teachers_without_offering = db.execute(
        "SELECT t.id, t.subject FROM teachers t "
        "WHERE NOT EXISTS (SELECT 1 FROM teacher_offerings o WHERE o.teacher_id = t.id)"
    ).fetchall()
    for t in teachers_without_offering:
        db.execute(
            "INSERT OR IGNORE INTO teacher_offerings (teacher_id, curriculum_id, stage_id, subject) VALUES (?, ?, ?, ?)",
            (t["id"], default_curriculum_id, default_stage_id, t["subject"]),
        )
    if teachers_without_offering:
        db.commit()

    # Migration: الشعبة/المسار (stream). الحصص اللي من غير stream (فاضي) بتعتبر
    # عامة وبتظهر لكل الطلاب. الطالب بياخد study_system (ثانوية عامة/بكالوريا)
    # + stream (شعبته أو مساره) عند التسجيل، وبيتفتح/بيتاخد في الاعتبار كل حصة
    # على شعبته بس.
    m_stream_cols = [r[1] for r in db.execute("PRAGMA table_info(materials)")]
    if "stream" not in m_stream_cols:
        db.execute("ALTER TABLE materials ADD COLUMN stream TEXT DEFAULT ''")
        db.commit()
    st_cols = [r[1] for r in db.execute("PRAGMA table_info(students)")]
    if "study_system" not in st_cols:
        db.execute("ALTER TABLE students ADD COLUMN study_system TEXT DEFAULT ''")
        db.execute("ALTER TABLE students ADD COLUMN stream TEXT DEFAULT ''")
        db.commit()

    # Migration: DBs created before centers/wallet existed won't have
    # amount/source_type/center_id on purchases yet.
    purchase_cols = [r[1] for r in db.execute("PRAGMA table_info(purchases)")]
    if "amount" not in purchase_cols:
        db.execute("ALTER TABLE purchases ADD COLUMN amount REAL DEFAULT 0")
        db.execute("ALTER TABLE purchases ADD COLUMN source_type TEXT DEFAULT 'مباشر'")
        db.execute("ALTER TABLE purchases ADD COLUMN center_id INTEGER")
        db.commit()
        # Backfill amount from the lesson's current price (best we can do -
        # the exact price paid at the time wasn't recorded before this).
        db.execute(
            "UPDATE purchases SET amount = (SELECT price FROM materials WHERE materials.id = purchases.material_id) "
            "WHERE amount = 0 OR amount IS NULL"
        )
        db.commit()
    if "gifted_by" not in purchase_cols:
        db.execute("ALTER TABLE purchases ADD COLUMN gifted_by TEXT")
        db.commit()

    # Migration: DBs created before teacher login existed won't have
    # account_code/password_hash/phone on teachers yet.
    teacher_cols = [r[1] for r in db.execute("PRAGMA table_info(teachers)")]
    if "account_code" not in teacher_cols:
        db.execute("ALTER TABLE teachers ADD COLUMN account_code TEXT")
        db.execute("ALTER TABLE teachers ADD COLUMN password_hash TEXT")
        db.execute("ALTER TABLE teachers ADD COLUMN phone TEXT DEFAULT ''")
        db.commit()

    # Migration: profile photo support, added after teachers/students/admins
    # already existed - add the column to whichever tables don't have it yet.
    for table in ("teachers", "students", "admins"):
        cols = [r[1] for r in db.execute(f"PRAGMA table_info({table})")]
        if "photo" not in cols:
            db.execute(f"ALTER TABLE {table} ADD COLUMN photo TEXT")
            db.commit()

    # Migration: workplace + platform commission %, added after teachers
    # already existed.
    teacher_cols2 = [r[1] for r in db.execute("PRAGMA table_info(teachers)")]
    if "workplace" not in teacher_cols2:
        db.execute("ALTER TABLE teachers ADD COLUMN workplace TEXT DEFAULT ''")
        db.execute("ALTER TABLE teachers ADD COLUMN commission_percent REAL DEFAULT 0")
        db.commit()
    if "is_blocked" not in teacher_cols2:
        db.execute("ALTER TABLE teachers ADD COLUMN is_blocked INTEGER DEFAULT 0")
        db.commit()

    student_cols = [r[1] for r in db.execute("PRAGMA table_info(students)")]
    if "is_blocked" not in student_cols:
        db.execute("ALTER TABLE students ADD COLUMN is_blocked INTEGER DEFAULT 0")
        db.commit()

    # Migration: DBs created before lesson kinds (video/exam/homework) existed.
    material_cols = [r[1] for r in db.execute("PRAGMA table_info(materials)")]
    if "kind" not in material_cols:
        db.execute("ALTER TABLE materials ADD COLUMN kind TEXT NOT NULL DEFAULT 'نص'")
        db.execute("ALTER TABLE materials ADD COLUMN video_url TEXT DEFAULT ''")
        db.commit()
    if "video_filename" not in material_cols:
        db.execute("ALTER TABLE materials ADD COLUMN video_filename TEXT")
        db.commit()
    if "access_days" not in material_cols:
        db.execute("ALTER TABLE materials ADD COLUMN access_days INTEGER")
        db.commit()

    # Migration: DBs where announcements existed before the emoji field.
    ann_cols = [r[1] for r in db.execute("PRAGMA table_info(announcements)")]
    if ann_cols and "emoji" not in ann_cols:
        db.execute("ALTER TABLE announcements ADD COLUMN emoji TEXT DEFAULT '📢'")
        db.commit()

    # Migration: payment_orders got a 'method' column for manual charges.
    po_cols = [r[1] for r in db.execute("PRAGMA table_info(payment_orders)")]
    if po_cols and "method" not in po_cols:
        db.execute("ALTER TABLE payment_orders ADD COLUMN method TEXT DEFAULT ''")
        db.commit()
    if po_cols and "proof_photo" not in po_cols:
        db.execute("ALTER TABLE payment_orders ADD COLUMN proof_photo TEXT DEFAULT ''")
        db.commit()

    ensure_default_admin(db)
    ensure_demo_centers(db)
    ensure_default_settings(db)

    migrate_student_ids(db)

    if fresh:
        seed(db)

    ensure_teacher_credentials(db)

    # فهارس الاستعلامات الأكثر استخدامًا — مع 100 طالب مفيش حاجة بتبطأ لو
    # الجداول كبرت. كلها "IF NOT EXISTS" فأمانة بتتضاف مرة واحدة بس.
    db.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_students_code ON students(account_code);
        CREATE INDEX IF NOT EXISTS idx_teachers_code ON teachers(account_code);
        CREATE INDEX IF NOT EXISTS idx_materials_teacher ON materials(teacher_id, id);
        CREATE INDEX IF NOT EXISTS idx_purchases_student ON purchases(student_id, material_id);
        CREATE INDEX IF NOT EXISTS idx_chat_teacher ON chat_messages(teacher_id, student_id);
        CREATE INDEX IF NOT EXISTS idx_watch_student ON video_watch(material_id, student_id);
        CREATE INDEX IF NOT EXISTS idx_login_scope_key ON login_attempts(scope, key);
        """
    )
    db.commit()
    db.close()


def migrate_student_ids(db):
    """[ترحيل] كل جداول نشاط الطالب (مشتريات/محفظة/تسليمات/شات/مهمات...) كانت
    بتربط بالطالب عن طريق الاسم بس (student_name) — وأي طالبين بنفس الاسم
    (زي حسابات "Ziad" الستة) كانت بياناتهم بتتداخل في بعض في الرصيد والمصروفات
    والحصص. الحل: كل جدول بياخد عمود student_id حقيقي، والاسم بيتبقى للعرض بس.
    بيشتغل مرة واحدة — أول مرة يلاقي الجدول من غير student_id، وبعدين بيفضل
    مشغّل بدون ما يغيّر حاجة (idempotent)."""
    p_cols = [r["name"] for r in db.execute("PRAGMA table_info(purchases)").fetchall()]
    if "student_id" in p_cols:
        return  # اترحّلت قبل كده

    # كل اللي عايزينه: الاسم → أقل id طالب بنفس الاسم (أقدم حساب هو اللي
    # بياخد البيانات القديمة المختلطة).
    name_to_id = {}
    for s in db.execute("SELECT id, name FROM students ORDER BY id").fetchall():
        if s["name"] not in name_to_id:
            name_to_id[s["name"]] = s["id"]

    def _sid(name):
        return name_to_id.get(name)

    def _add_and_backfill(table, cols):
        """يضيف أعمدة student_id الناقصة للجدول ويمليها من الاسم."""
        existing = [r["name"] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
        for col in cols:
            if col not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {col} INTEGER")
        db.commit()
        for row in db.execute(f"SELECT id, student_name FROM {table}").fetchall():
            db.execute(
                f"UPDATE {table} SET {', '.join(c + ' = ?' for c in cols)} WHERE id = ?",
                tuple(_sid(row["student_name"]) for c in cols) + (row["id"],),
            )
        db.commit()

    # الجداول من غير قيد UNIQUE على الاسم — ADD COLUMN تكفي.
    _add_and_backfill("wallet_topups", ["student_id"])
    _add_and_backfill("chat_messages", ["student_id"])
    _add_and_backfill("lesson_views", ["student_id"])
    _add_and_backfill("study_heartbeats", ["student_id"])
    _add_and_backfill("assessment_attempts", ["student_id"])
    _add_and_backfill("payment_orders", ["student_id"])
    _add_and_backfill("support_requests", ["student_id"])

    # wallet_transfers بستين طرف.
    wt_cols = [r["name"] for r in db.execute("PRAGMA table_info(wallet_transfers)").fetchall()]
    for col in ("from_student_id", "to_student_id"):
        if col not in wt_cols:
            db.execute(f"ALTER TABLE wallet_transfers ADD COLUMN {col} INTEGER")
    db.commit()
    for row in db.execute("SELECT id, from_student, to_student FROM wallet_transfers").fetchall():
        db.execute(
            "UPDATE wallet_transfers SET from_student_id = ?, to_student_id = ? WHERE id = ?",
            (_sid(row["from_student"]), _sid(row["to_student"]), row["id"]),
        )
    db.commit()

    # الجداول اللي عليها UNIQUE (الاسم, ...) — القيد لازم يبقى على student_id
    # عشان طالبين بنفس الاسم ميتخانقوش على نفس الحصة. SQLite مبيسمحش بتغيير
    # قيد UNIQUE بـ ALTER، فنعيد بناء الجدول (جدول جديد + نقل البيانات + حذف
    # القديم + إعادة التسمية).
    def _rebuild(table, schema):
        db.executescript(schema)
        db.commit()

    _rebuild(
        "purchases",
        """
        CREATE TABLE purchases__new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            purchased_at TEXT NOT NULL,
            amount REAL DEFAULT 0,
            source_type TEXT DEFAULT 'مباشر',
            center_id INTEGER,
            gifted_by TEXT,
            gifted_by_id INTEGER,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            FOREIGN KEY (center_id) REFERENCES centers(id),
            UNIQUE (material_id, student_id)
        );
        INSERT INTO purchases__new (id, material_id, student_id, student_name, purchased_at, amount, source_type, center_id, gifted_by, gifted_by_id)
        SELECT id, material_id, (SELECT id FROM students s WHERE s.name = purchases.student_name ORDER BY s.id LIMIT 1), student_name, purchased_at, amount, source_type, center_id, gifted_by,
               (CASE WHEN gifted_by IS NOT NULL THEN (SELECT id FROM students s2 WHERE s2.name = purchases.gifted_by ORDER BY s2.id LIMIT 1) ELSE NULL END) FROM purchases;
        DROP TABLE purchases;
        ALTER TABLE purchases__new RENAME TO purchases;
        """,
    )
    _rebuild(
        "reviews",
        """
        CREATE TABLE reviews__new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            rating INTEGER NOT NULL,
            comment TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (material_id, student_id)
        );
        INSERT INTO reviews__new (id, material_id, student_id, student_name, rating, comment, created_at)
        SELECT id, material_id, (SELECT id FROM students s WHERE s.name = reviews.student_name ORDER BY s.id LIMIT 1), student_name, rating, comment, created_at FROM reviews;
        DROP TABLE reviews;
        ALTER TABLE reviews__new RENAME TO reviews;
        """,
    )
    _rebuild(
        "submissions",
        """
        CREATE TABLE submissions__new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            answer_text TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            grade TEXT,
            feedback TEXT,
            graded_at TEXT,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (material_id, student_id)
        );
        INSERT INTO submissions__new (id, material_id, student_id, student_name, answer_text, submitted_at, grade, feedback, graded_at)
        SELECT id, material_id, (SELECT id FROM students s WHERE s.name = submissions.student_name ORDER BY s.id LIMIT 1), student_name, answer_text, submitted_at, grade, feedback, graded_at FROM submissions;
        DROP TABLE submissions;
        ALTER TABLE submissions__new RENAME TO submissions;
        """,
    )
    _rebuild(
        "exam_submissions",
        """
        CREATE TABLE exam_submissions__new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            answer_text TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            grade TEXT,
            feedback TEXT,
            graded_at TEXT,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (material_id, student_id)
        );
        INSERT INTO exam_submissions__new (id, material_id, student_id, student_name, answer_text, submitted_at, grade, feedback, graded_at)
        SELECT id, material_id, (SELECT id FROM students s WHERE s.name = exam_submissions.student_name ORDER BY s.id LIMIT 1), student_name, answer_text, submitted_at, grade, feedback, graded_at FROM exam_submissions;
        DROP TABLE exam_submissions;
        ALTER TABLE exam_submissions__new RENAME TO exam_submissions;
        """,
    )
    _rebuild(
        "video_watch",
        """
        CREATE TABLE video_watch__new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            seconds REAL NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (material_id, student_id)
        );
        INSERT INTO video_watch__new (id, material_id, student_id, student_name, seconds, updated_at)
        SELECT id, material_id, (SELECT id FROM students s WHERE s.name = video_watch.student_name ORDER BY s.id LIMIT 1), student_name, seconds, updated_at FROM video_watch;
        DROP TABLE video_watch;
        ALTER TABLE video_watch__new RENAME TO video_watch;
        """,
    )
    _rebuild(
        "admin_exemptions",
        """
        CREATE TABLE admin_exemptions__new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            material_id INTEGER NOT NULL,
            reason TEXT DEFAULT '',
            created_by TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (material_id) REFERENCES materials(id),
            UNIQUE (student_id, material_id)
        );
        INSERT INTO admin_exemptions__new (id, student_id, student_name, material_id, reason, created_by, created_at)
        SELECT id, (SELECT id FROM students s WHERE s.name = admin_exemptions.student_name ORDER BY s.id LIMIT 1), student_name, material_id, reason, created_by, created_at FROM admin_exemptions;
        DROP TABLE admin_exemptions;
        ALTER TABLE admin_exemptions__new RENAME TO admin_exemptions;
        """,
    )
    _rebuild(
        "student_tasks",
        """
        CREATE TABLE student_tasks__new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            student_name TEXT NOT NULL,
            task_number INTEGER NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            is_completed INTEGER NOT NULL DEFAULT 0,
            completed_at TEXT,
            congrats_message TEXT DEFAULT '',
            stopwatch_seconds INTEGER NOT NULL DEFAULT 0,
            stopwatch_running INTEGER NOT NULL DEFAULT 0,
            stopwatch_started_at TEXT,
            created_at TEXT NOT NULL,
            UNIQUE (student_id, task_number)
        );
        INSERT INTO student_tasks__new (id, student_id, student_name, task_number, title, is_completed, completed_at, congrats_message, stopwatch_seconds, stopwatch_running, stopwatch_started_at, created_at)
        SELECT id, (SELECT id FROM students s WHERE s.name = student_tasks.student_name ORDER BY s.id LIMIT 1), student_name, task_number, title, is_completed, completed_at, congrats_message, stopwatch_seconds, stopwatch_running, stopwatch_started_at, created_at FROM student_tasks;
        DROP TABLE student_tasks;
        ALTER TABLE student_tasks__new RENAME TO student_tasks;
        """,
    )

    # الفهارس القديمة كانت على (student_name) — نحذفها ونعملها على student_id.
    db.execute("DROP INDEX IF EXISTS idx_purchases_student")
    db.execute("DROP INDEX IF EXISTS idx_chat_teacher")
    db.execute("DROP INDEX IF EXISTS idx_watch_student")
    db.commit()


def ensure_teacher_credentials(db):
    """Any teacher without login credentials yet (freshly seeded, or an
    existing teacher row from before this feature) gets an account_code +
    password generated now. كل مدرس بياخد باسورد عشوائي قوي خاص بيه (مفيش
    باسورد ثابت واحد مشترك) مع علامة must_change_password - أول ما يدخل بيضطر
    يغيّره. الباسورد بيتوصله على الواتساب/اللوج بنفس طريقة تسجيل الطلاب."""
    t_cols = [r[1] for r in db.execute("PRAGMA table_info(teachers)")]
    if "must_change_password" not in t_cols:
        db.execute("ALTER TABLE teachers ADD COLUMN must_change_password INTEGER DEFAULT 0")
        db.commit()

    # المدرسين القدام اللي لسه على باسورد Teacher@123 الثابت (المكتوب في كود
    # قديم) - بندور عليهم ونعيد تعيينهم لباسورد عشوائي جديد خاص بيهم + علامة
    # must_change_password. ده بيمنع إن كل حسابات المدرسين تتفتح بباسورد واحد
    # معروف لأي حد.
    default_hash = None
    try:
        if not db.execute("SELECT 1 FROM teachers WHERE password_hash IS NOT NULL").fetchone():
            default_hash = None
        else:
            default_hash = True
    except Exception:
        default_hash = None
    if default_hash:
        weak_teachers = db.execute("SELECT id, name, phone, password_hash FROM teachers").fetchall()
        changed = 0
        for t in weak_teachers:
            if t["password_hash"] and check_password_hash(t["password_hash"], "Teacher@123"):
                new_pw = generate_strong_password()
                db.execute(
                    "UPDATE teachers SET password_hash = ?, must_change_password = 1 WHERE id = ?",
                    (generate_password_hash(new_pw), t["id"]),
                )
                changed += 1
                if t["phone"]:
                    send_whatsapp(t["phone"], f"أهلاً {t['name']}! تم تحديث كود دخولك: {t['account_code']} - الباسورد الجديد: {new_pw}")
                else:
                    print(f"[بيانات دخول مدرس محدّثة] {t['name']}: باسورد جديد {new_pw} (غيّره بعد أول دخول)")
        if changed:
            db.commit()
            print(f"[أمان] اتعاد تعيين {changed} مدرس من باسورد Teacher@123 الثابت")

    teachers_without_creds = db.execute(
        "SELECT id, name, phone FROM teachers WHERE account_code IS NULL"
    ).fetchall()
    for t in teachers_without_creds:
        code = generate_account_code_for(db, "teachers", "TCH")
        password = generate_strong_password()
        db.execute(
            "UPDATE teachers SET account_code = ?, password_hash = ?, must_change_password = 1 WHERE id = ?",
            (code, generate_password_hash(password), t["id"]),
        )
        if t["phone"]:
            send_whatsapp(t["phone"], f"أهلاً {t['name']}! كود دخولك كمدرس: {code} - الباسورد: {password}")
        else:
            print(f"[بيانات دخول مدرس] {t['name']}: كود {code} - باسورد {password} (غيّره بعد أول دخول)")
    if teachers_without_creds:
        db.commit()



def ensure_demo_centers(db):
    """Seeds a couple of demo recharge centers so 'source' reporting has
    something real to show. Safe to call every startup."""
    centers = ["سنتر النصر - المعادي", "سنتر الأمل - المنصورة"]
    db.executemany("INSERT OR IGNORE INTO centers (name) VALUES (?)", [(c,) for c in centers])
    db.commit()


def ensure_default_settings(db):
    """Seeds the default platform settings (AI key, payment mode, backup
    settings...). Values can be overridden any time from the admin panel.
    Existing rows are never overwritten."""
    defaults = {
        "anthropic_key": os.environ.get("ANTHROPIC_API_KEY", ""),
        "payment_mode": "محاكاة",      # محاكاة / حقيقي
        "topup_methods": "فودافون كاش،انستاباي،فوري،فيزا",
        "backup_enabled": "1",
        "backup_retention": "14",
        "ai_subscription_price": "300",   # سعر اشتراك الذكاء الاصطناعي للمدرس (شهري)
        "ai_subscription_days": "30",     # مدة الاشتراك بالأيام مقابل السعر
    }
    for k, v in defaults.items():
        db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
    db.commit()


def ensure_default_admin(db):
    """Creates one admin account if none exists yet - so a fresh install (or
    an existing DB upgrading to this feature) always has a way in. Override
    the defaults with the ADMIN_USERNAME / ADMIN_PASSWORD env vars before
    first run, and change the password immediately after logging in either way.
    This first account is always 'رئيس' (chief) - only a رئيس can create more
    admin accounts, so someone has to start at the top."""
    admin_cols = [r[1] for r in db.execute("PRAGMA table_info(admins)")]
    if "role" not in admin_cols:
        db.execute("ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'اداري'")
        db.commit()
        # أول حساب اتعمل قبل ما يبقى فيه أدوار أصلاً كان بيدير كل حاجة - يبقى رئيس.
        db.execute("UPDATE admins SET role = 'رئيس' WHERE id = (SELECT MIN(id) FROM admins)")
        db.commit()
    if "login_start_hour" not in admin_cols:
        db.execute("ALTER TABLE admins ADD COLUMN login_start_hour INTEGER")
        db.execute("ALTER TABLE admins ADD COLUMN login_end_hour INTEGER")
        db.commit()
    if "password_plain" not in admin_cols:
        # تخزين باسورد نص واضح عشان الرئيس يشوفه في قائمة الفريق (زي ما عملنا
        # للمدرسين) - الـ hash لسه بيتحفظ ويستخدم في الدخول، وده للعرض بس.
        db.execute("ALTER TABLE admins ADD COLUMN password_plain TEXT")
        db.commit()

    if db.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
        return
    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "ChangeMe@2026")
    db.execute(
        "INSERT INTO admins (username, password_hash, password_plain, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, generate_password_hash(password), password, "رئيس", datetime.utcnow().isoformat()),
    )
    db.commit()


def ensure_stages_and_curricula(db):
    """Seeds the 5 grades and the starting set of curricula. Safe to call
    every startup - INSERT OR IGNORE means it only fills in what's missing,
    so an admin adding a new curriculum by hand in the DB is never touched."""
    stages = [
        ("تانية إعدادي", 1),
        ("تالتة إعدادي", 2),
        ("أولى ثانوي", 3),
        ("تانية ثانوي", 4),
        ("تالتة ثانوي", 5),
    ]
    db.executemany("INSERT OR IGNORE INTO stages (name, sort_order) VALUES (?, ?)", stages)

    curricula = ["حكومي", "IG", "أمريكي", "بكالوريا", "ثانوية عامة"]
    db.executemany("INSERT OR IGNORE INTO curricula (name) VALUES (?)", [(c,) for c in curricula])
    db.commit()


def ensure_streams_and_subjects(db):
    """Seeds the exam-bank streams and subjects reference tables. Safe to call
    every startup - INSERT OR IGNORE fills in only what's missing, so any
    admin-added streams/subjects are never touched."""
    streams = [
        ("علمي علوم", 1),
        ("علمي رياضة", 2),
        ("أدبي", 3),
        ("الأعمال", 4),
        ("الهندسة وعلوم الحاسب", 5),
        ("الطب وعلوم الحياة", 6),
        ("الآداب والفنون", 7),
    ]
    db.executemany("INSERT OR IGNORE INTO streams (name, sort_order) VALUES (?, ?)", streams)

    subjects = [
        ("لغة عربية", 1),
        ("لغة إنجليزية", 2),
        ("لغة فرنسية", 3),
        ("لغة ألمانية", 4),
        ("رياضيات", 5),
        ("رياضيات بحتة", 6),
        ("رياضيات تطبيقية", 7),
        ("فيزياء", 8),
        ("كيمياء", 9),
        ("أحياء", 10),
        ("جيولوجيا", 11),
        ("تاريخ", 12),
        ("جغرافيا", 13),
        ("فلسفة ومنطق", 14),
        ("علم نفس واجتماع", 15),
        ("اقتصاد وإحصاء", 16),
        ("علوم حاسب", 17),
        ("تربية دينية", 18),
        ("لغة عربية للناطقين بغيرها", 19),
        ("علم نفس", 20),
        ("اجتماع", 21),
        ("إحصاء", 22),
        ("تكنولوجيا", 23),
    ]
    db.executemany("INSERT OR IGNORE INTO subjects (name, sort_order) VALUES (?, ?)", subjects)
    db.commit()

    # خريطة الشعب → المواد (ربط في جدول stream_subjects)
    stream_map = {r["name"]: r["id"] for r in db.execute("SELECT id, name FROM streams")}
    subject_map = {r["name"]: r["id"] for r in db.execute("SELECT id, name FROM subjects")}

    # المواد المشتركة بين كل الشعب
    shared = ["لغة عربية", "لغة إنجليزية", "تربية دينية"]
    # المواد المشتركة (بخلاف الثانوية العامة القديمة)
    secondary_shared = ["لغة فرنسية", "لغة ألمانية"]

    mapping = {
        "علمي علوم": ["فيزياء", "كيمياء", "أحياء", "جيولوجيا"] + secondary_shared,
        "علمي رياضة": ["رياضيات بحتة", "رياضيات تطبيقية", "فيزياء", "كيمياء"] + secondary_shared,
        "أدبي": ["تاريخ", "جغرافيا", "فلسفة ومنطق", "علم نفس واجتماع", "اقتصاد وإحصاء", "لغة فرنسية", "لغة ألمانية"],
        "الأعمال": ["رياضيات", "اقتصاد وإحصاء", "لغة فرنسية", "لغة ألمانية"],
        "الهندسة وعلوم الحاسب": ["رياضيات", "فيزياء", "علوم حاسب", "لغة فرنسية", "لغة ألمانية"],
        "الطب وعلوم الحياة": ["رياضيات", "فيزياء", "كيمياء", "أحياء", "لغة فرنسية", "لغة ألمانية"],
        "الآداب والفنون": ["تاريخ", "جغرافيا", "فلسفة ومنطق", "علم نفس واجتماع", "لغة فرنسية", "لغة ألمانية"],
    }

    for stream_name, subj_names in mapping.items():
        sid = stream_map.get(stream_name)
        if not sid:
            continue
        for subj_name in shared + subj_names:
            subjid = subject_map.get(subj_name)
            if subjid:
                db.execute(
                    "INSERT OR IGNORE INTO stream_subjects (stream_id, subject_id) VALUES (?, ?)",
                    (sid, subjid),
                )
    db.commit()


def ensure_question_bank_tables(db):
    """قواعد البيانات القديمة مفيش فيها جداول بنك الأسئلة ولمية اليوم — بننشئهم
    هنا لو مش موجودين (safe على كل boot)."""
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS question_bank (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question_text TEXT NOT NULL,
            option_a TEXT DEFAULT '',
            option_b TEXT DEFAULT '',
            option_c TEXT DEFAULT '',
            option_d TEXT DEFAULT '',
            correct_index INTEGER DEFAULT 0,
            explanation TEXT DEFAULT '',
            stage_id INTEGER,
            stream_id INTEGER,
            subject_id INTEGER,
            curriculum_id INTEGER,
            is_published INTEGER NOT NULL DEFAULT 1,
            created_by_type TEXT DEFAULT 'admin',
            created_by_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (stage_id) REFERENCES stages(id),
            FOREIGN KEY (stream_id) REFERENCES streams(id),
            FOREIGN KEY (subject_id) REFERENCES subjects(id),
            FOREIGN KEY (curriculum_id) REFERENCES curricula(id)
        );
        CREATE TABLE IF NOT EXISTS daily_sets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            set_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            score INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            submitted_at TEXT,
            FOREIGN KEY (student_id) REFERENCES students(id)
        );
        CREATE TABLE IF NOT EXISTS daily_set_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            set_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            answer_index INTEGER,
            is_correct INTEGER,
            UNIQUE (set_id, question_id),
            FOREIGN KEY (set_id) REFERENCES daily_sets(id),
            FOREIGN KEY (question_id) REFERENCES question_bank(id)
        );
        """
    )
    db.commit()


def seed(db):
    teachers = [
        ("أ. محمد سامي", "رياضيات", "مدرس رياضيات - متخصص في الجبر والتفاضل والتكامل، بيدرّس النظامين الحكومي وIG."),
        ("أ. منى الشريف", "فيزياء", "مدرسة فيزياء - تبسيط قوانين الفيزياء بأمثلة من الحياة اليومية."),
        ("أ. كريم فتحي", "لغة عربية", "مدرس لغة عربية - النحو والبلاغة والتعبير."),
    ]
    db.executemany("INSERT INTO teachers (name, subject, bio) VALUES (?, ?, ?)", teachers)
    db.commit()

    stage_id = {r["name"]: r["id"] for r in db.execute("SELECT id, name FROM stages")}
    curriculum_id = {r["name"]: r["id"] for r in db.execute("SELECT id, name FROM curricula")}

    # (teacher_id, curriculum, stage, subject)
    offerings = [
        (1, "حكومي", "تالتة ثانوي", "رياضيات"),
        (1, "IG", "تانية ثانوي", "Mathematics"),
        (2, "حكومي", "تالتة ثانوي", "فيزياء"),
        (3, "حكومي", "تالتة إعدادي", "لغة عربية"),
    ]
    db.executemany(
        "INSERT INTO teacher_offerings (teacher_id, curriculum_id, stage_id, subject) VALUES (?, ?, ?, ?)",
        [(t, curriculum_id[c], stage_id[s], subj) for (t, c, s, subj) in offerings],
    )
    db.commit()

    # (teacher_id, curriculum, stage, subject, title, content, price)
    materials = [
        (1, "حكومي", "تالتة ثانوي", "رياضيات", "المتتاليات الحسابية والهندسية",
         "المتتالية الحسابية هي متتالية يكون الفرق بين أي حدين متتاليين فيها ثابت، ويسمى هذا الفرق أساس المتتالية (د). "
         "الحد العام: أن = أ1 + (ن-1)د. أما المتتالية الهندسية فالنسبة بين أي حدين متتاليين ثابتة وتسمى الأساس (ر)، "
         "والحد العام: أن = أ1 × ر^(ن-1). مجموع ن حد من متتالية حسابية = ن/2 × (2أ1 + (ن-1)د).", 0),
        (1, "حكومي", "تالتة ثانوي", "رياضيات", "التفاضل - المشتقة الأولى",
         "مشتقة الدالة تمثل معدل تغير الدالة عند نقطة معينة، وهندسيًا هي ميل المماس للمنحنى عند تلك النقطة. "
         "قاعدة القوة: مشتقة س^ن = ن×س^(ن-1). مشتقة مجموع دالتين = مجموع مشتقتيهما.", 25),
        (1, "IG", "تانية ثانوي", "Mathematics", "Quadratic Equations",
         "A quadratic equation has the form ax^2 + bx + c = 0. It can be solved by factoring, "
         "completing the square, or using the quadratic formula: x = (-b ± √(b²-4ac)) / 2a.", 30),
        (2, "حكومي", "تالتة ثانوي", "فيزياء", "قوانين نيوتن للحركة",
         "القانون الأول: الجسم الساكن يظل ساكنًا والجسم المتحرك يستمر في حركته بسرعة ثابتة ما لم تؤثر عليه قوة خارجية (القصور الذاتي). "
         "القانون الثاني: ق = ك×ع (القوة = الكتلة × التسارع). القانون الثالث: لكل فعل رد فعل مساوٍ له في المقدار ومضاد له في الاتجاه.", 20),
        (3, "حكومي", "تالتة إعدادي", "لغة عربية", "الفرق بين الفعل اللازم والمتعدي",
         "الفعل اللازم هو ما يكتفي بفاعله ولا يحتاج مفعولاً به لتمام المعنى، مثل: نام الطفل. "
         "الفعل المتعدي هو ما يحتاج إلى مفعول به واحد أو أكثر لتمام المعنى، مثل: كتب الطالبُ الدرسَ.", 0),
    ]
    now = datetime.utcnow().isoformat()
    db.executemany(
        "INSERT INTO materials (teacher_id, curriculum_id, stage_id, subject, title, content, price, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(t, curriculum_id[c], stage_id[s], subj, ti, ct, p, now) for (t, c, s, subj, ti, ct, p) in materials],
    )
    db.commit()

    # مثال توضيحي: عملية شراء جاية من سنتر، عشان شاشة "حسباتي" يبقى فيها
    # بيانات حقيقية تتعرض من أول تشغيل.
    demo_center_id = db.execute("SELECT id FROM centers ORDER BY id LIMIT 1").fetchone()
    demo_material = db.execute("SELECT id, price FROM materials WHERE price > 0 ORDER BY id LIMIT 1").fetchone()
    if demo_center_id and demo_material:
        db.execute(
            "INSERT OR IGNORE INTO purchases (material_id, student_name, purchased_at, amount, source_type, center_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (demo_material["id"], "طالب تجريبي", now, demo_material["price"], "سنتر", demo_center_id["id"]),
        )
        db.commit()


# ---------------------------------------------------------------------------
# Claude API helper
# ---------------------------------------------------------------------------

def get_setting(db, key: str, default: str = "") -> str:
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def backup_folder() -> str:
    folder = os.path.join(os.path.dirname(__file__), "backups")
    os.makedirs(folder, exist_ok=True)
    return folder


def create_backup() -> str:
    """Copies platform.db into backups/ with a timestamp name. Returns the
    backup file path."""
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dest = os.path.join(backup_folder(), f"platform-{stamp}.db")
    # بياخد نسخة آمنة من قاعدة بيانات مشغولة (لو فيه اتصال شغال).
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(dest)
    src.backup(dst)
    dst.close()
    src.close()
    return dest


def run_daily_backup_if_needed():
    """At startup, creates a backup if one hasn't been made today (and the
    feature is enabled). Safe to call every boot."""
    try:
        db = get_db()
        if get_setting(db, "backup_enabled", "0") != "1":
            return
        latest = None
        for f in os.listdir(backup_folder()):
            if f.startswith("platform-") and f.endswith(".db"):
                latest = max(latest or f, f)
        today = datetime.now().strftime("%Y-%m-%d")
        if not latest or not latest.startswith(f"platform-{today}"):
            create_backup()
    except Exception as exc:  # النسخ مش محتاج يوقف تشغيل المنصة لو حصل غلط.
        print(f"[نسخ احتياطي] تحذير: {exc}")


def call_claude(system_prompt: str, user_prompt: str, max_tokens: int = 1000) -> str:
    db = get_db()
    api_key = get_setting(db, "anthropic_key", "")
    if not api_key:
        return ("⚠️ لم يتم ضبط مفتاح Anthropic API بعد. افتح لوحة الإدارة ← "
                "الإعدادات وحط المفتاح عشان مساعد الذكاء الاصطناعي يشتغل.")
    if not api_key.startswith(("sk-ant", "sk-")):
        return "⚠️ مفتاح Anthropic API غير صالح. تأكد إنك كتبته صح في الإعدادات."

    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return "".join(
            block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
        ).strip() or "لم يصل رد من المساعد."
    except requests.exceptions.RequestException as exc:
        return f"⚠️ حصل خطأ في الاتصال بمساعد الذكاء الاصطناعي: {exc}"


def get_materials_with_meta(db, teacher_id: int, student_id: int, student_stream: str = "") -> list:
    """Materials for a teacher, enriched per-student with purchase + rating info.
    الحصص اللي على شعبة/مسار الطالب بس (مع الحصص العامة اللي من غير تحديد)."""
    materials = db.execute(
        "SELECT m.*, c.name curriculum_name, s.name stage_name, "
        "  (SELECT COUNT(*) FROM lesson_videos lv WHERE lv.material_id = m.id) video_count "
        "FROM materials m "
        "LEFT JOIN curricula c ON c.id = m.curriculum_id "
        "LEFT JOIN stages s ON s.id = m.stage_id "
        "WHERE m.teacher_id = ? AND (m.stream = '' OR m.stream = ?) ORDER BY m.id DESC",
        (teacher_id, student_stream),
    ).fetchall()

    result = []
    for m in materials:
        purchase = db.execute(
            "SELECT * FROM purchases WHERE material_id = ? AND student_id = ?",
            (m["id"], student_id),
        ).fetchone()
        unlocked = purchase is not None or m["price"] == 0

        # لو المدرس حدد مدة إتاحة (3-14 يوم) وفيه عملية شراء فعلية (مش حصة
        # مجانية)، نتأكد إن المدة دي لسه ماخلصتش من وقت الشراء.
        expired = False
        days_left = None
        if unlocked and m["access_days"] and purchase:
            purchased_at = datetime.fromisoformat(purchase["purchased_at"])
            deadline = purchased_at + timedelta(days=m["access_days"])
            remaining = deadline - datetime.utcnow()
            if remaining.total_seconds() <= 0:
                expired = True
                unlocked = False
            else:
                days_left = max(1, remaining.days + (1 if remaining.seconds > 0 else 0))

        purchased = unlocked

        agg = db.execute(
            "SELECT AVG(rating) avg_rating, COUNT(*) cnt FROM reviews WHERE material_id = ?",
            (m["id"],),
        ).fetchone()

        my_review = db.execute(
            "SELECT * FROM reviews WHERE material_id = ? AND student_id = ?",
            (m["id"], student_id),
        ).fetchone()

        my_submission = None
        if m["kind"] == "واجب":
            my_submission = db.execute(
                "SELECT * FROM submissions WHERE material_id = ? AND student_id = ?",
                (m["id"], student_id),
            ).fetchone()

        my_exam_submission = None
        if m["kind"] == "امتحان":
            my_exam_submission = db.execute(
                "SELECT * FROM exam_submissions WHERE material_id = ? AND student_id = ?",
                (m["id"], student_id),
            ).fetchone()

        item = dict(m)
        item["purchased"] = purchased
        item["expired"] = expired
        item["days_left"] = days_left
        item["avg_rating"] = round(agg["avg_rating"], 1) if agg["avg_rating"] else None
        item["review_count"] = agg["cnt"]
        item["my_review"] = dict(my_review) if my_review else None
        item["my_submission"] = dict(my_submission) if my_submission else None
        item["my_exam_submission"] = dict(my_exam_submission) if my_exam_submission else None
        result.append(item)

    # القفل التسلسلي: كل حصة بترجع بحالة whether مقفولة لحد ما تخلص اللي قبلها.
    sequence_locks_for_materials(db, result, student_id)
    return result


def build_teacher_context(db, teacher_id: int, student_id: int) -> str:
    """RAG-lite: concatenate only the lessons this student has unlocked
    (free lessons + lessons they purchased) as grounding context, so a
    student can't get paid-lesson content through the chat without buying it."""
    unlocked = [m for m in get_materials_with_meta(db, teacher_id, student_id, get_student_stream(db, student_id)) if m["purchased"]]
    if not unlocked:
        return "لا يوجد محتوى متاح لهذا الطالب حتى الآن (لسه محدش اشترى أي حصة)."
    parts = [f"### {m['title']}\n{m['content']}" for m in unlocked]
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Routes - general
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("home.html")


# ---------------------------------------------------------------------------
# Routes - student side
# ---------------------------------------------------------------------------

def generate_account_code_for(db, table: str, prefix: str) -> str:
    """A short unique code like STU-4821 or TCH-4821, checked against the
    given table's account_code column."""
    while True:
        code = f"{prefix}-" + "".join(secrets.choice(string.digits) for _ in range(4))
        if not db.execute(f"SELECT 1 FROM {table} WHERE account_code = ?", (code,)).fetchone():
            return code


def generate_password() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(8))


def generate_strong_password(length: int = 12) -> str:
    """باسورد عشوائي قوي: حروف كبيرة وصغيرة + أرقام + رمز خاص. بيستخدم secrets
    (مش random) عشان مفيش حد يتوقع قيمته."""
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*"
    all_chars = lower + upper + digits + symbols
    # نضمن وجود صنف واحد من كل نوع على الأقل
    chars = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    chars += [secrets.choice(all_chars) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def send_sms_simulated(phone: str, message: str):
    """No real SMS gateway wired up yet - logs instead of sending.
    Swap this for a real provider (Vodafone/Orange/Twilio/...) before launch."""
    print(f"[SMS محاكاة] إلى {phone}: {message}")


def _to_e164(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    if digits.startswith("002"):
        digits = digits[3:]
    if digits.startswith("20") and len(digits) > 11:
        return digits
    if digits.startswith("0"):
        digits = digits[1:]
    return "20" + digits


def student_phone_exists(db, phone: str) -> bool:
    """True if this phone (normalized) already belongs to an existing student
    account — يمنع الطالب يعمل أكونت تاني بنفس الرقم."""
    target = _to_e164(phone)
    if not target:
        return False
    rows = db.execute("SELECT student_phone FROM students").fetchall()
    return any(_to_e164(r["student_phone"]) == target for r in rows if r["student_phone"])


def _whatsapp_config() -> dict:
    cfg = {
        "phone_number_id": os.environ.get("WHATSAPP_PHONE_NUMBER_ID", ""),
        "access_token": os.environ.get("WHATSAPP_ACCESS_TOKEN", ""),
        "code_template": os.environ.get("WHATSAPP_CODE_TEMPLATE", ""),
        "grade_template": os.environ.get("WHATSAPP_GRADE_TEMPLATE", ""),
        "lang": os.environ.get("WHATSAPP_TEMPLATE_LANG", "ar"),
    }
    try:
        row = {r["key"]: r["value"] for r in get_db().execute("SELECT key, value FROM settings")}
    except Exception:
        row = {}
    for key in cfg:
        if row.get(f"whatsapp_{key}"):
            cfg[key] = row[f"whatsapp_{key}"]
    return cfg


def _whatsapp_ready(cfg: dict) -> bool:
    return bool(cfg.get("phone_number_id") and cfg.get("access_token"))


def whatsapp_send(phone: str, message: str, template_name: str | None = None,
                  template_params: list | None = None):
    """Sends via WhatsApp Business (Meta Cloud API) if configured, otherwise
    falls back to the SMS simulation. Returns (ok, status)."""
    cfg = _whatsapp_config()
    if not _whatsapp_ready(cfg):
        print(f"[واتساب محاكاة - لسه من غير حساب حقيقي] إلى {phone}: {message}")
        send_sms_simulated(phone, message)
        return False, "واتساب غير مفعل - محاكاة"

    to_number = _to_e164(phone)
    if template_name and template_params is not None:
        payload = {
            "messaging_product": "whatsapp",
            "to": to_number,
            "type": "template",
            "template": {
                "name": template_name,
                "language": {"code": cfg.get("lang") or "ar"},
                "components": [{
                    "type": "body",
                    "parameters": [{"type": "text", "text": str(p)} for p in template_params],
                }],
            },
        }
    else:
        payload = {
            "messaging_product": "whatsapp",
            "to": to_number,
            "type": "text",
            "text": {"body": message},
        }

    try:
        resp = requests.post(
            f"https://graph.facebook.com/v20.0/{cfg['phone_number_id']}/messages",
            headers={"Authorization": f"Bearer {cfg['access_token']}"},
            json=payload,
            timeout=10,
        )
        if resp.ok:
            print(f"[واتساب أُرسل] إلى {to_number}: {message[:60]}")
            return True, "اترسلت"
        detail = resp.text[:400]
        print(f"[واتساب فشل - {resp.status_code}] {detail}")
        send_sms_simulated(phone, message)
        return False, f"خطأ {resp.status_code}: {detail}"
    except requests.RequestException as e:
        print(f"[واتساب خطأ اتصال] {e}")
        send_sms_simulated(phone, message)
        return False, f"خطأ اتصال: {e}"


def send_whatsapp(phone: str, message: str):
    whatsapp_send(phone, message)


def send_whatsapp_code(phone: str, name: str, code: str, password: str):
    cfg = _whatsapp_config()
    if cfg.get("code_template"):
        whatsapp_send(
            phone,
            f"أهلاً {name} في Seniors! كود حسابك: {code} - الباسورد: {password}",
            template_name=cfg["code_template"],
            template_params=[name, code, password],
        )
    else:
        whatsapp_send(phone, f"أهلاً {name} في Seniors! كود حسابك: {code} - الباسورد: {password}")


PAYMOB_BASE = "https://accept.paymob.com"


def get_setting(db, key: str, default: str = "") -> str:
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def _paymob_config() -> dict:
    cfg = {
        "api_key": os.environ.get("PAYMOB_API_KEY", ""),
        "integration_id": os.environ.get("PAYMOB_INTEGRATION_ID", ""),
        "iframe_id": os.environ.get("PAYMOB_IFRAME_ID", ""),
        "hmac_secret": os.environ.get("PAYMOB_HMAC_SECRET", ""),
    }
    try:
        row = {r["key"]: r["value"] for r in get_db().execute("SELECT key, value FROM settings")}
    except Exception:
        row = {}
    for key in cfg:
        if row.get(f"paymob_{key}"):
            cfg[key] = row[f"paymob_{key}"]
    return cfg


def _paymob_ready(cfg: dict) -> bool:
    return bool(cfg.get("api_key") and cfg.get("integration_id") and cfg.get("iframe_id"))


def paymob_auth_token(cfg: dict) -> str:
    resp = requests.post(f"{PAYMOB_BASE}/api/auth/tokens", json={"api_key": cfg["api_key"]}, timeout=15)
    resp.raise_for_status()
    return resp.json()["token"]


def paymob_create_order(cfg: dict, auth_token: str, amount_cents: int, merchant_order_id: int,
                        items: list) -> int:
    resp = requests.post(
        f"{PAYMOB_BASE}/api/ecommerce/orders",
        json={
            "auth_token": auth_token,
            "delivery_needed": "false",
            "amount_cents": amount_cents,
            "currency": "EGP",
            "merchant_order_id": str(merchant_order_id),
            "items": items,
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["id"]


def paymob_payment_key(cfg: dict, auth_token: str, amount_cents: int, order_id: int,
                       billing_data: dict, redirect_url: str) -> str:
    resp = requests.post(
        f"{PAYMOB_BASE}/api/acceptance/payment_keys",
        json={
            "auth_token": auth_token,
            "amount_cents": amount_cents,
            "currency": "EGP",
            "integration_id": int(cfg["integration_id"]),
            "order_id": order_id,
            "billing_data": billing_data,
            "lock_order_when_paid": "true",
            "redirect_url": redirect_url,
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["token"]


def paymob_verify_hmac(obj: dict, hmac_secret: str, received_hmac: str) -> bool:
    data = dict(obj)
    canonical = ""
    for key in sorted(data.keys()):
        value = data[key]
        if isinstance(value, (dict, list)):
            canonical += json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        elif isinstance(value, bool):
            canonical += "true" if value else "false"
        elif value is None:
            canonical += ""
        else:
            canonical += str(value)
    expected = hmac.new(hmac_secret.encode(), canonical.encode(), hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, received_hmac or "")


def _start_paymob_payment(db, order_id: int, student_id: int, student_name: str, amount: float,
                          description: str) -> str | None:
    cfg = _paymob_config()
    site_url = get_setting(db, "site_url", "").rstrip("/")
    student = db.execute(
        "SELECT name, google_email, student_phone FROM students WHERE id = ?", (student_id,)
    ).fetchone()
    first, _, last = (student["name"].partition(" ") if student else ("طالب", " ", "الطالب"))
    billing_data = {
        "apartment": "NA",
        "email": (student["google_email"] if student and student["google_email"] else "student@example.com"),
        "floor": "NA",
        "first_name": first or "طالب",
        "street": "NA",
        "building": "NA",
        "phone_number": (student["student_phone"] if student and student["student_phone"] else "01000000000"),
        "shipping_method": "PKG",
        "postal_code": "NA",
        "city": "Cairo",
        "country": "EG",
        "last_name": last or "الطالب",
        "state": "Cairo",
    }
    try:
        auth_token = paymob_auth_token(cfg)
        amount_cents = int(round(amount * 100))
        paymob_order_id = paymob_create_order(
            cfg, auth_token, amount_cents, order_id,
            [{"name": description, "amount_cents": amount_cents, "quantity": 1}],
        )
        db.execute("UPDATE payment_orders SET paymob_order_id = ? WHERE id = ?", (paymob_order_id, order_id))
        db.commit()
        payment_token = paymob_payment_key(
            cfg, auth_token, amount_cents, paymob_order_id, billing_data,
            f"{site_url}/student/payment/result",
        )
        return f"{PAYMOB_BASE}/api/acceptance/iframes/{cfg['iframe_id']}?payment_token={payment_token}"
    except Exception as e:
        db.execute("UPDATE payment_orders SET status = 'failed' WHERE id = ?", (order_id,))
        db.commit()
        flash(f"حصلت مشكلة في بدء الدفع: {e}", "danger")
        return None


def _fulfill_payment(db, po, transaction_id):
    now = datetime.utcnow().isoformat()
    if po["kind"] == "buy" and po["material_id"]:
        db.execute(
            """INSERT INTO purchases (material_id, student_id, student_name, purchased_at, amount, source_type)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(material_id, student_id)
               DO UPDATE SET purchased_at = excluded.purchased_at, amount = excluded.amount""",
            (po["material_id"], po["student_id"], po["student_name"], now, po["amount"], "أونلاين"),
        )
    elif po["kind"] == "topup":
        db.execute(
            "INSERT INTO wallet_topups (student_id, student_name, amount, method, created_at) VALUES (?, ?, ?, 'أونلاين', ?)",
            (po["student_id"], po["student_name"], po["amount"], now),
        )
    db.execute(
        "UPDATE payment_orders SET status = 'paid', paymob_transaction_id = ?, paid_at = ? WHERE id = ?",
        (transaction_id, now, po["id"]),
    )
    db.commit()


RECHARGE_CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def generate_recharge_code(length: int = 12) -> str:
    """Random voucher code that's easy to type: no confusing chars (no 0/O,
    1/I/L). Keeps retrying until it's unique against the DB."""
    db = get_db()
    while True:
        code = "".join(secrets.choice(RECHARGE_CODE_CHARS) for _ in range(length))
        exists = db.execute("SELECT 1 FROM recharge_codes WHERE code = ?", (code,)).fetchone()
        if not exists:
            return code


def redeem_recharge_code(db, student_id: int, student_name: str, raw_code: str):
    """Credits a student's wallet from an unused recharge code. Returns a
    (ok, message) tuple."""
    code = "".join(raw_code.strip().upper().split())
    if not code:
        return False, "اكتب الكود الأول."
    row = db.execute("SELECT * FROM recharge_codes WHERE code = ?", (code,)).fetchone()
    if not row:
        return False, "الكود ده مش موجود — تأكد منه واكتبه تاني."
    if row["status"] == "used":
        return False, f"الكود ده اتنزل عليه قبل كده لـ {row['used_by']} — اتأكد من الكود."
    if row["status"] == "disabled":
        return False, "الكود ده متوقف — اتصل بالإدارة."
    now = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO wallet_topups (student_id, student_name, amount, method, created_at) VALUES (?, ?, ?, 'كود شحن', ?)",
        (student_id, student_name, row["amount"], now),
    )
    db.execute(
        "UPDATE recharge_codes SET status = 'used', used_by = ?, used_at = ? WHERE id = ?",
        (student_name, now, row["id"]),
    )
    db.commit()
    return True, f"تم إضافة {int(row['amount'])} ج لمحفظتك من الكود."


def ai_subscription_config(db) -> dict:
    """سعر ومدة اشتراك الذكاء الاصطناعي للمدرسين (من الإعدادات)."""
    try:
        price = float(get_setting(db, "ai_subscription_price", "300") or 300)
    except ValueError:
        price = 300.0
    try:
        days = int(get_setting(db, "ai_subscription_days", "30") or 30)
    except ValueError:
        days = 30
    return {"price": price, "days": days}


def teacher_ai_expiry(teacher) -> str:
    """تاريخ انتهاء اشتراك AI للمدرس (أو سلسلة فاضية)."""
    if not teacher:
        return ""
    return teacher["ai_subscription_expires_at"] or ""


def teacher_ai_active(db, teacher) -> bool:
    """هل اشتراك الذكاء الاصطناعي بتاع المدرس ده لسه ساري؟"""
    expires = teacher_ai_expiry(teacher)
    if not expires:
        return False
    try:
        return datetime.fromisoformat(expires) > datetime.utcnow()
    except ValueError:
        return False


def teacher_ai_days_left(db, teacher) -> int:
    """كم يوم فاضل في الاشتراك (0 = منتهي أو مش مفعّل)."""
    expires = teacher_ai_expiry(teacher)
    if not expires:
        return 0
    try:
        diff = (datetime.fromisoformat(expires) - datetime.utcnow()).total_seconds()
        return max(0, int(diff // 86400))
    except ValueError:
        return 0


def extend_teacher_ai(db, teacher_id, extra_days, amount=0.0, method="", code="", granted_by=""):
    """بيزوّد اشتراك المدرس بأيام إضافية. لو الاشتراك لسه ساري، الوقت بيتضاف
    على نهاية الاشتراك الحالي (موفّر للمدرس) — لو منتهي، بيبتدي من النهارده.
    وبيعمل سجل في teacher_ai_payments للإدارة تشوف تاريخ الدفعات."""
    now = datetime.utcnow()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    base = now
    expires = teacher_ai_expiry(teacher)
    if expires:
        try:
            cur = datetime.fromisoformat(expires)
            if cur > now:
                base = cur
        except ValueError:
            pass
    new_expiry = base + timedelta(days=extra_days)
    iso = new_expiry.isoformat()
    db.execute(
        "UPDATE teachers SET ai_subscription_expires_at = ? WHERE id = ?",
        (iso, teacher_id),
    )
    db.execute(
        "INSERT INTO teacher_ai_payments (teacher_id, amount, method, code, created_at, expires_at, granted_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (teacher_id, amount, method, code, now.isoformat(), iso, granted_by),
    )
    db.commit()
    return iso


def redeem_recharge_code_for_teacher(db, teacher_id, teacher_name, raw_code):
    """استبدال كود شحن عشان المدرس يفعّل اشتراك الذكاء الاصطناعي. الكود بيقفل،
    وقيمته بتتحول لأيام اشتراك حسب سعر الاشتراك (المبلغ ÷ السعر × المدة).
    بترجّع (ok, message)."""
    code = "".join(raw_code.strip().upper().split())
    if not code:
        return False, "اكتب الكود الأول."
    row = db.execute("SELECT * FROM recharge_codes WHERE code = ?", (code,)).fetchone()
    if not row:
        return False, "الكود ده مش موجود — تأكد منه واكتبه تاني."
    if row["status"] == "used":
        return False, "الكود ده اتنزل عليه قبل كده — اتأكد من الكود."
    if row["status"] == "disabled":
        return False, "الكود ده متوقف — اتصل بالإدارة."
    cfg = ai_subscription_config(db)
    days = max(1, int(round(row["amount"] / cfg["price"] * cfg["days"])))
    now = datetime.utcnow().isoformat()
    db.execute(
        "UPDATE recharge_codes SET status = 'used', used_by = ?, used_by_role = 'teacher', used_at = ? WHERE id = ?",
        (teacher_name, now, row["id"]),
    )
    db.commit()
    extend_teacher_ai(
        db, teacher_id, days, amount=row["amount"], method="كود شحن",
        code=code, granted_by="المدرس نفسه",
    )
    return True, f"تم تفعيل اشتراك الذكاء الاصطناعي {days} يوم — الكود بقيمته {int(row['amount'])} ج."


LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 15
ACCOUNT_MAX_ATTEMPTS = 15
ACCOUNT_LOCK_MINUTES = 30
IP_MAX_ATTEMPTS = 60
IP_LOCK_MINUTES = 15


def _is_strong_enough_password(password: str) -> bool:
    """8 خانات على الأقل + فيه رقم + فيه حرف (الرموز بتتسامح)."""
    return (
        len(password) >= 8
        and any(c.isdigit() for c in password)
        and any(c.isalpha() for c in password)
    )


def _login_key(account_code: str, ip: str) -> str:
    return f"{account_code}|{ip}"


def _bump_login(db, scope: str, key: str, max_attempts: int, lock_minutes: int):
    now = datetime.utcnow().isoformat()
    row = db.execute(
        "SELECT id, attempts FROM login_attempts WHERE scope = ? AND key = ?",
        (scope, key),
    ).fetchone()
    if row:
        attempts = row["attempts"] + 1
        blocked_until = (
            (datetime.utcnow() + timedelta(minutes=lock_minutes)).isoformat()
            if attempts >= max_attempts
            else None
        )
        db.execute(
            "UPDATE login_attempts SET attempts = ?, blocked_until = ?, last_attempt_at = ? WHERE id = ?",
            (attempts, blocked_until, now, row["id"]),
        )
    else:
        db.execute(
            "INSERT INTO login_attempts (scope, key, attempts, blocked_until, last_attempt_at) "
            "VALUES (?, ?, 1, NULL, ?)",
            (scope, key, now),
        )
    db.commit()


def _login_lock_message(db, scope: str, key: str):
    row = db.execute(
        "SELECT blocked_until FROM login_attempts WHERE scope = ? AND key = ?",
        (scope, key),
    ).fetchone()
    if row and row["blocked_until"]:
        until = datetime.fromisoformat(row["blocked_until"])
        if until > datetime.utcnow():
            remaining = int((until - datetime.utcnow()).total_seconds() // 60) + 1
            return f"محاولات دخول غلط كتيرة - انتظر {remaining} دقيقة وارجع جرب."
        db.execute(
            "DELETE FROM login_attempts WHERE scope = ? AND key = ?",
            (scope, key),
        )
        db.commit()
    return None


def login_blocked(db, scope: str, account_code: str, ip: str):
    """قفل من 3 مستويات: حساب+جهاز (5 محاولات)، الحساب نفسه من أي جهاز
    (15 محاولة عشان حد يبدّل IP)، والـ IP نفسه (60 محاولة عشان البوتات).
    المستويات الأعلى تسامحًا عشان الطلاب في مدرسة واحدة (نفس الـ IP) مايتقفوش
    بسهولة على بعض."""
    for key in (_login_key(account_code, ip), account_code, ip):
        msg = _login_lock_message(db, scope, key)
        if msg:
            return msg
    return None


def record_login_attempt(db, scope: str, account_code: str, ip: str):
    _bump_login(db, scope, _login_key(account_code, ip), LOGIN_MAX_ATTEMPTS, LOGIN_LOCK_MINUTES)
    _bump_login(db, scope, account_code, ACCOUNT_MAX_ATTEMPTS, ACCOUNT_LOCK_MINUTES)
    _bump_login(db, scope, ip, IP_MAX_ATTEMPTS, IP_LOCK_MINUTES)


def clear_login_attempts(db, scope: str, account_code: str, ip: str):
    for key in (_login_key(account_code, ip), account_code, ip):
        db.execute(
            "DELETE FROM login_attempts WHERE scope = ? AND key = ?",
            (scope, key),
        )
    db.commit()


@app.route("/login", methods=["GET", "POST"])
def login():
    """صفحة دخول موحدة للطلاب والمدرسين — الدور بيتحدد تلقائيًا من بادئة
    كود الحساب (STU- للطالب، TCH- للمدرس)."""
    error = None
    if request.method == "POST":
        account_code = request.form.get("account_code", "").strip().upper()
        password = request.form.get("password", "")
        db = get_db()
        ip = request.remote_addr or ""
        blocked = login_blocked(db, "login", account_code, ip)
        if blocked:
            error = blocked
        elif account_code.startswith("TCH-"):
            teacher = db.execute("SELECT * FROM teachers WHERE account_code = ?", (account_code,)).fetchone()
            if teacher and teacher["is_blocked"]:
                error = "الحساب ده متوقف حاليًا - تواصل مع الإدارة."
            elif teacher and teacher["password_hash"] and check_password_hash(teacher["password_hash"], password):
                clear_login_attempts(db, "login", account_code, ip)
                session.clear()
                session["teacher_id"] = teacher["id"]
                session["teacher_name"] = teacher["name"]
                session["must_change_password"] = bool(teacher["must_change_password"])
                log_security_event("teacher_login", f"{teacher['name']} ({account_code})")
                return redirect(url_for("teacher_dashboard", teacher_id=teacher["id"]))
            else:
                record_login_attempt(db, "login", account_code, ip)
                log_security_event("login_failed", f"مدرس {account_code} من {ip}")
                error = "كود الحساب أو الباسورد غلط."
        elif account_code.startswith("STU-"):
            student = db.execute("SELECT * FROM students WHERE account_code = ?", (account_code,)).fetchone()
            if student and student["is_blocked"]:
                error = "الحساب ده متوقف حاليًا - تواصل مع الإدارة."
            elif student and check_password_hash(student["password_hash"], password):
                # بلا قيود أجهزة: نفس حساب الطالب يفتح من أي عدد أجهزة في نفس
                # الوقت — كل جهاز ليه جلسة مستقلة بتتشال لما يسجل خروج بس.
                clear_login_attempts(db, "login", account_code, ip)
                session.clear()
                token = secrets.token_hex(32)
                db.execute(
                    "INSERT INTO student_sessions (student_id, token, logged_in_at, last_seen_at) "
                    "VALUES (?, ?, ?, ?)",
                    (student["id"], token, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()),
                )
                db.commit()
                session["student_id"] = student["id"]
                session["student_name"] = student["name"]
                session["student_code"] = student["account_code"]
                session["session_token"] = token
                log_security_event("student_login", f"{student['name']} ({account_code})")
                return redirect(url_for("student_browse"))
            else:
                record_login_attempt(db, "login", account_code, ip)
                log_security_event("login_failed", f"طالب {account_code} من {ip}")
                error = "كود الحساب أو الباسورد غلط."
        else:
            error = "الكود غير معروف - تأكد إنه يبدأ بـ STU (طالب) أو TCH (مدرس)."
    return render_template("login.html", error=error)


@app.route("/student", methods=["GET", "POST"])
def student_login():
    # الواجهة القديمة — كل حاجة بقت على صفحة الدخول الموحدة /login.
    return redirect(url_for("login"))


@app.route("/student/logout", methods=["POST"])
def student_logout():
    db = get_db()
    if "student_id" in session and session.get("session_token"):
        db.execute(
            "DELETE FROM student_sessions WHERE student_id = ? AND token = ?",
            (session["student_id"], session.get("session_token")),
        )
        db.commit()
    session.pop("student_id", None)
    session.pop("student_name", None)
    session.pop("student_code", None)
    session.pop("session_token", None)
    return redirect(url_for("home"))


@app.route("/student/register", methods=["GET", "POST"])
def student_register():
    error = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        parent_name = request.form.get("parent_name", "").strip()
        parent_job = request.form.get("parent_job", "").strip()
        student_phone = request.form.get("student_phone", "").strip()
        parent_phone = request.form.get("parent_phone", "").strip()
        national_id = request.form.get("national_id", "").strip()
        google_email = request.form.get("google_email", "").strip()
        study_system = request.form.get("study_system", "").strip()
        stream = request.form.get("stream", "").strip()

        # التحقق من الشعبة/المسار: لازم يبقى فعلاً من القوائم بتاعة النظام المختار.
        if study_system not in ("ثانوية عامة", "بكالوريا"):
            study_system = ""
            stream = ""
        elif study_system == "ثانوية عامة" and stream not in SECONDARY_STREAMS:
            stream = ""
        elif study_system == "بكالوريا" and stream not in BAC_STREAMS:
            stream = ""

        db = get_db()
        ip = request.remote_addr or ""
        blocked = login_blocked(db, "register", ip, ip)
        if blocked:
            error = blocked
        elif not all([name, parent_name, student_phone, parent_phone, national_id, google_email]):
            error = "من فضلك املأ كل البيانات المطلوبة."
        elif not national_id.isdigit() or len(national_id) != 14:
            error = "الرقم القومي لازم يكون 14 رقم."
        elif len(name) > 80 or len(parent_name) > 80:
            error = "الاسم أطول من اللازم."
        elif not all(p.isdigit() for p in (student_phone, parent_phone)):
            error = "رقم الموبايل لازم يكون أرقام بس (كود الدولة 010/011/012/015...)."
        elif len(student_phone) > 20 or len(parent_phone) > 20:
            error = "رقم الموبايل أطول من اللازم."
        elif not study_system or not stream:
            error = "من فضلك اختر نظام شهادتك والشعبة/المسار بتاعك."
        elif student_phone_exists(db, student_phone):
            error = "رقم الموبايل ده مسجل بالفعل على حساب تاني — مينفعش تعمل حساب جديد بنفس الرقم."
        else:
            account_code = generate_account_code_for(db, "students", "STU")
            password = generate_password()
            photo = save_uploaded_photo(request.files.get("photo")) or DEFAULT_STUDENT_PHOTO
            db.execute(
                "INSERT INTO students "
                "(account_code, name, parent_name, parent_job, student_phone, parent_phone, "
                " national_id, google_email, study_system, stream, password_hash, photo, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (account_code, name, parent_name, parent_job, student_phone, parent_phone,
                 national_id, google_email, study_system, stream,
                 generate_password_hash(password), photo, datetime.utcnow().isoformat()),
            )
            db.commit()
            record_login_attempt(db, "register", ip, ip)
            send_whatsapp_code(student_phone, name, account_code, password)
            return render_template(
                "student_register_success.html",
                account_code=account_code, password=password, student_phone=student_phone,
                study_system=study_system, stream=stream,
            )
    return render_template("student_register.html", error=error)


@app.route("/student/browse")
def student_browse():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()

    me_check = db.execute("SELECT is_blocked FROM students WHERE id = ?", (session.get("student_id"),)).fetchone()
    if not me_check or me_check["is_blocked"]:
        session.pop("student_id", None)
        session.pop("student_name", None)
        return redirect(url_for("student_login"))

    stages = db.execute("SELECT * FROM stages ORDER BY sort_order").fetchall()
    curricula = db.execute("SELECT * FROM curricula ORDER BY name").fetchall()

    stage_id = request.args.get("stage_id", type=int)
    curriculum_id = request.args.get("curriculum_id", type=int)

    query = (
        "SELECT DISTINCT t.*, "
        "  (SELECT GROUP_CONCAT(DISTINCT o.subject) FROM teacher_offerings o "
        "   WHERE o.teacher_id = t.id"
    )
    params = []
    if stage_id:
        query += " AND o.stage_id = ?"
        params.append(stage_id)
    if curriculum_id:
        query += " AND o.curriculum_id = ?"
        params.append(curriculum_id)
    query += "  ) subjects_here FROM teachers t JOIN teacher_offerings o ON o.teacher_id = t.id WHERE 1=1"
    if stage_id:
        query += " AND o.stage_id = ?"
        params.append(stage_id)
    if curriculum_id:
        query += " AND o.curriculum_id = ?"
        params.append(curriculum_id)
    query += " ORDER BY t.name"

    teachers = db.execute(query, params).fetchall()

    # ودجت هدف النهارده في شاشة التصفح.
    sid = session["student_id"]
    today_str = datetime.utcnow().date().isoformat()
    goal_row = db.execute(
        "SELECT target_minutes FROM student_daily_goals WHERE student_id = ? AND goal_date = ?",
        (sid, today_str),
    ).fetchone()
    today_target = goal_row["target_minutes"] if goal_row else 0
    today_minutes = round(get_study_minutes_for_day(db, sid, today_str), 1)

    return render_template(
        "student_browse.html", teachers=teachers, student_name=session["student_name"],
        stages=stages, curricula=curricula,
        selected_stage_id=stage_id, selected_curriculum_id=curriculum_id,
        today_target=today_target, today_minutes=today_minutes,
        today_streak=study_streak(db, sid),
    )


@app.route("/student/teacher/<int:teacher_id>")
def student_teacher_view(teacher_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student_id = session["student_id"]
    student_name = session["student_name"]
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    block = is_student_blocked(db, teacher_id, student_id)
    if block:
        return render_template("student_blocked.html", teacher=teacher, block=block), 403
    materials = get_materials_with_meta(db, teacher_id, student_id, get_student_stream(db, student_id))

    now = datetime.utcnow().isoformat()
    for m in materials:
        if m["purchased"]:  # يعني الحصة مفتوحة وبتتعرض فعليًا للطالب
            db.execute(
                "INSERT INTO lesson_views (material_id, student_id, student_name, viewed_at) VALUES (?, ?, ?, ?)",
                (m["id"], student_id, student_name, now),
            )
    if materials:
        db.commit()

    offerings = db.execute(
        "SELECT o.*, c.name curriculum_name, s.name stage_name FROM teacher_offerings o "
        "JOIN curricula c ON c.id = o.curriculum_id JOIN stages s ON s.id = o.stage_id "
        "WHERE o.teacher_id = ? ORDER BY s.sort_order",
        (teacher_id,),
    ).fetchall()
    history = db.execute(
        "SELECT * FROM chat_messages WHERE teacher_id = ? AND student_id = ? ORDER BY id",
        (teacher_id, student_id),
    ).fetchall()
    gift_credits = get_gift_credits(db, student_id)
    return render_template(
        "student_teacher.html", teacher=teacher, materials=materials, offerings=offerings,
        history=history, student_name=student_name, gift_credits=gift_credits,
    )


@app.route("/student/lesson/<int:material_id>")
def student_lesson(material_id):
    """شاشة مستقلة لكل درس — فيها كل فيديوهات الدرس (كل فيديو بعنوانه)،
    المحتوى، الواجب/الامتحان، والتقييم."""
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student_id = session["student_id"]
    student_name = session["student_name"]

    material = db.execute(
        "SELECT m.*, c.name curriculum_name, s.name stage_name, t.name teacher_name, t.id teacher_id "
        "FROM materials m "
        "LEFT JOIN curricula c ON c.id = m.curriculum_id "
        "LEFT JOIN stages s ON s.id = m.stage_id "
        "JOIN teachers t ON t.id = m.teacher_id "
        "WHERE m.id = ?",
        (material_id,),
    ).fetchone()
    if not material:
        return redirect(url_for("student_browse"))

    # بلوك من المدرس: لو المدرس محظر الطالب، ميفتحش عليه الدرس ولا المحتوى.
    block = is_student_blocked(db, material["teacher_id"], student_id)
    if block:
        teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (material["teacher_id"],)).fetchone()
        return render_template("student_blocked.html", teacher=teacher, block=block), 403

    # الشعبة/المسار: الحصة اللي ليها شعبة مش بتتفتح غير لطالب نفس الشعبة.
    if material["stream"] and material["stream"] != get_student_stream(db, student_id):
        return redirect(url_for("student_browse"))

    purchase = db.execute(
        "SELECT * FROM purchases WHERE material_id = ? AND student_id = ?",
        (material_id, student_id),
    ).fetchone()
    unlocked = purchase is not None or material["price"] == 0
    expired = False
    days_left = None
    if unlocked and material["access_days"] and purchase:
        purchased_at = datetime.fromisoformat(purchase["purchased_at"])
        deadline = purchased_at + timedelta(days=material["access_days"])
        remaining = deadline - datetime.utcnow()
        if remaining.total_seconds() <= 0:
            expired = True
            unlocked = False
        else:
            days_left = max(1, remaining.days + (1 if remaining.seconds > 0 else 0))
    purchased = unlocked

    # القفل التسلسلي: الحصة دي مش بتفتح غير لما كل الحصص اللي قبلها (عند نفس
    # المدرس، بترتيب الإضافة) تخلص — إلا لو الإدارة استثنتها. أول حصة مش
    # مخلصة بتبقى مفتوحة وهي المقصودة بمذاكرة الطالب.
    sequence_blocker = None
    sequence_locked = False
    if purchased:
        sequence_blocker = get_sequence_blocker(db, material, student_id)
        sequence_locked = sequence_blocker is not None
        if sequence_locked:
            purchased = False  # المحتوى مقفول + بيظهر سبب القفل مكان شاشة الشراء

    if purchased:
        db.execute(
            "INSERT INTO lesson_views (material_id, student_id, student_name, viewed_at) VALUES (?, ?, ?, ?)",
            (material_id, student_id, student_name, datetime.utcnow().isoformat()),
        )
        db.commit()

    videos = db.execute(
        "SELECT * FROM lesson_videos WHERE material_id = ? ORDER BY sort_order, id",
        (material_id,),
    ).fetchall()
    chapters = db.execute(
        "SELECT * FROM chapters WHERE material_id = ? ORDER BY sort_order, id",
        (material_id,),
    ).fetchall()
    chapter_videos = {c["id"]: [] for c in chapters}
    orphans = []
    for v in videos:
        if v["chapter_id"] and v["chapter_id"] in chapter_videos:
            chapter_videos[v["chapter_id"]].append(v)
        else:
            orphans.append(v)

    agg = db.execute(
        "SELECT AVG(rating) avg_rating, COUNT(*) cnt FROM reviews WHERE material_id = ?",
        (material_id,),
    ).fetchone()
    my_review = db.execute(
        "SELECT * FROM reviews WHERE material_id = ? AND student_id = ?",
        (material_id, student_id),
    ).fetchone()
    my_submission = None
    if material["kind"] == "واجب":
        my_submission = db.execute(
            "SELECT * FROM submissions WHERE material_id = ? AND student_id = ?",
            (material_id, student_id),
        ).fetchone()
    my_exam_submission = None
    if material["kind"] == "امتحان":
        my_exam_submission = db.execute(
            "SELECT * FROM exam_submissions WHERE material_id = ? AND student_id = ?",
            (material_id, student_id),
        ).fetchone()

    # الامتحانات/الواجبات الإلكترونية للدرس + آخر محاولة حل لكل طالب.
    assessments = db.execute(
        """SELECT a.*,
                  (SELECT COUNT(*) FROM assessment_questions q WHERE q.assessment_id = a.id) question_count
           FROM assessments a WHERE a.material_id = ? ORDER BY a.id""",
        (material_id,),
    ).fetchall()
    my_attempts = {}
    for a in assessments:
        att = db.execute(
            "SELECT * FROM assessment_attempts WHERE assessment_id = ? AND student_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (a["id"], student_id),
        ).fetchone()
        my_attempts[a["id"]] = dict(att) if att else None

    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (material["teacher_id"],)).fetchone()
    gift_credits = get_gift_credits(db, student_id)

    return render_template(
        "student_lesson.html", material=material, teacher=teacher, videos=videos,
        chapters=chapters, chapter_videos=chapter_videos, orphans=orphans,
        purchased=purchased, expired=expired, days_left=days_left,
        avg_rating=round(agg["avg_rating"], 1) if agg["avg_rating"] else None,
        review_count=agg["cnt"], my_review=my_review,
        my_submission=my_submission, my_exam_submission=my_exam_submission,
        assessments=assessments, my_attempts=my_attempts,
        gift_credits=gift_credits, student_name=student_name,
        sequence_locked=sequence_locked, sequence_blocker=sequence_blocker,
    )


@app.route("/student/exams")
def student_exams():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    student_id = session["student_id"]
    db = get_db()
    student_stream = get_student_stream(db, student_id)
    exams = db.execute(
        """SELECT m.*, t.name teacher_name,
                  es.answer_text, es.grade, es.feedback, es.graded_at, es.submitted_at
           FROM materials m
           JOIN teachers t ON t.id = m.teacher_id
           LEFT JOIN exam_submissions es ON es.material_id = m.id AND es.student_id = ?
           WHERE m.kind = 'امتحان' AND (m.stream = '' OR m.stream = ?) AND (
             m.price = 0 OR EXISTS (
               SELECT 1 FROM purchases p WHERE p.material_id = m.id AND p.student_id = ?
             )
           )
           ORDER BY m.id DESC""",
        (student_id, student_stream, student_id),
    ).fetchall()
    e_assessments = db.execute(
        """SELECT a.id, a.title, a.material_id, m.title lesson_title, t.name teacher_name,
                  (SELECT COUNT(*) FROM assessment_questions q WHERE q.assessment_id = a.id) question_count,
                  (SELECT score FROM assessment_attempts at WHERE at.assessment_id = a.id
                     AND at.student_id = ? ORDER BY at.id DESC LIMIT 1) my_score
           FROM assessments a
           JOIN materials m ON m.id = a.material_id
           JOIN teachers t ON t.id = m.teacher_id
           WHERE a.kind = 'امتحان' AND (m.stream = '' OR m.stream = ?) AND (m.price = 0 OR EXISTS (
             SELECT 1 FROM purchases p WHERE p.material_id = m.id AND p.student_id = ?
           ))
           ORDER BY a.id DESC""",
        (student_id, student_stream, student_id),
    ).fetchall()
    return render_template("student_exams.html", exams=exams, e_assessments=e_assessments)


@app.route("/student/exam-bank")
def student_exam_bank():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    q_subject = request.args.get("subject", "").strip()
    q_stage = request.args.get("stage_id", type=int)
    q_stream = request.args.get("stream_id", type=int)
    q_curriculum = request.args.get("curriculum_id", type=int)

    subjects = db.execute("SELECT name subject FROM subjects ORDER BY sort_order").fetchall()
    stages = db.execute("SELECT * FROM stages ORDER BY sort_order").fetchall()
    streams = db.execute("SELECT * FROM streams ORDER BY sort_order").fetchall()
    curricula = db.execute("SELECT * FROM curricula ORDER BY id").fetchall()

    query = """SELECT e.*, s.name stage_name, st.name stream_name, c.name curriculum_name
               FROM exam_bank e
               LEFT JOIN stages s ON s.id = e.stage_id
               LEFT JOIN streams st ON st.id = e.stream_id
               LEFT JOIN curricula c ON c.id = e.curriculum_id
               WHERE e.is_published = 1"""
    params = []
    if q_subject:
        query += " AND e.subject = ?"
        params.append(q_subject)
    if q_stage:
        query += " AND e.stage_id = ?"
        params.append(q_stage)
    if q_stream:
        query += " AND e.stream_id = ?"
        params.append(q_stream)
    if q_curriculum:
        query += " AND e.curriculum_id = ?"
        params.append(q_curriculum)
    query += " ORDER BY e.id DESC"
    exams = db.execute(query, params).fetchall()

    return render_template(
        "student_exam_bank.html", exams=exams, subjects=subjects, stages=stages,
        streams=streams, curricula=curricula,
        q_subject=q_subject, q_stage=q_stage, q_stream=q_stream, q_curriculum=q_curriculum,
    )


@app.route("/student/exam-bank/<int:exam_id>/download")
def student_exam_bank_download(exam_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    row = db.execute(
        "SELECT * FROM exam_bank WHERE id = ? AND is_published = 1", (exam_id,)
    ).fetchone()
    if not row or not row["file_path"]:
        abort(404)
    db.execute(
        "UPDATE exam_bank SET downloads = downloads + 1 WHERE id = ?", (exam_id,)
    )
    db.commit()
    return send_from_directory(UPLOAD_FOLDER, row["file_path"], as_attachment=True)


DAILY_QUESTION_COUNT = 50


def _get_or_create_today_set(db, student_id):
    """لِمة اليوم للطالب: لو في لِمة نشطة النهارده برجعها، غير كده بجمع 50
    سؤال من بنك الأسئلة المطبوعة (حسب صف وشعبة الطالب لو متحددين) وبعمل لِمة
    جديدة. لو مفيش 50 سؤال مطابقين، بناخد اللي موجود."""
    today = datetime.now().strftime("%Y-%m-%d")
    existing = db.execute(
        "SELECT * FROM daily_sets WHERE student_id = ? AND set_date = ? AND status = 'active' "
        "ORDER BY id DESC LIMIT 1",
        (student_id, today),
    ).fetchone()
    if existing:
        return existing

    student = db.execute("SELECT id, stream, study_system FROM students WHERE id = ?", (student_id,)).fetchone()
    where = "WHERE is_published = 1"
    params = []
    stream_only_params = []
    stream_only_where = "WHERE is_published = 1"
    if student and student["stream"]:
        sid = db.execute("SELECT id FROM streams WHERE name = ?", (student["stream"],)).fetchone()
        if sid:
            where += " AND stream_id = ?"
            params.append(sid["id"])
            stream_only_where += " AND stream_id = ?"
            stream_only_params.append(sid["id"])
    if student and student["study_system"]:
        cid = db.execute("SELECT id FROM curricula WHERE name = ?", (student["study_system"],)).fetchone()
        if cid:
            where += " AND curriculum_id = ?"
            params.append(cid["id"])
    # مزيج متوازن من الصعوبات: سهل 40%، متوسط 40%، صعب 20%.
    quotas = {1: int(DAILY_QUESTION_COUNT * 0.4), 2: int(DAILY_QUESTION_COUNT * 0.4),
              3: DAILY_QUESTION_COUNT - 2 * int(DAILY_QUESTION_COUNT * 0.4)}
    # الأول بندوّر على أسئلة بنفس الشعبة والنظام، ولو مفيش كفاية بننزل للشعبة
    # بس، وبعدين أي سؤال منشور.
    questions = []
    used = set()
    for where_clause, params_clause in ((where, params), (stream_only_where, stream_only_params), ("WHERE is_published = 1", [])):
        if len(questions) >= DAILY_QUESTION_COUNT:
            break
        # لكل مستوى صعوبة نجيب حصته (باستبعاد اللي اتعملهم).
        for level in (1, 2, 3):
            if len(questions) >= DAILY_QUESTION_COUNT:
                break
            qty = quotas[level] if level == 3 else quotas[level]
            qty = max(0, min(qty, DAILY_QUESTION_COUNT - len(questions)))
            if qty <= 0:
                continue
            w = where_clause + " AND difficulty = ?"
            p = list(params_clause) + [level]
            if used:
                w += " AND id NOT IN (%s)" % ",".join("?" * len(used))
                p += list(used)
            batch = db.execute(
                f"SELECT id FROM question_bank {w} ORDER BY RANDOM() LIMIT ?", p + [qty]
            ).fetchall()
            for q in batch:
                questions.append(q)
                used.add(q["id"])
        # لو فاضل من الحصة في نفس الطبقة، نكمل بأي صعوبة (باستبعاد المستخدمين).
        qty = DAILY_QUESTION_COUNT - len(questions)
        if qty > 0:
            w = where_clause
            p = list(params_clause)
            if used:
                w += " AND id NOT IN (%s)" % ",".join("?" * len(used))
                p += list(used)
            batch = db.execute(
                f"SELECT id FROM question_bank {w} ORDER BY RANDOM() LIMIT ?", p + [qty]
            ).fetchall()
            for q in batch:
                questions.append(q)
                used.add(q["id"])
    if not questions:
        return None

    now = datetime.utcnow().isoformat()
    cur = db.execute(
        "INSERT INTO daily_sets (student_id, set_date, status, score, total, created_at) "
        "VALUES (?, ?, 'active', 0, 0, ?)",
        (student_id, today, now),
    )
    set_id = cur.lastrowid
    db.executemany(
        "INSERT OR IGNORE INTO daily_set_questions (set_id, question_id) VALUES (?, ?)",
        [(set_id, q["id"]) for q in questions],
    )
    db.commit()
    return db.execute("SELECT * FROM daily_sets WHERE id = ?", (set_id,)).fetchone()


@app.route("/student/question-bank")
def student_question_bank():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student_id = session["student_id"]
    today = datetime.now().strftime("%Y-%m-%d")

    q_subject = request.args.get("subject_id", type=int)
    q_stage = request.args.get("stage_id", type=int)
    q_stream = request.args.get("stream_id", type=int)
    q_curriculum = request.args.get("curriculum_id", type=int)

    stages = db.execute("SELECT * FROM stages ORDER BY sort_order").fetchall()
    streams = db.execute("SELECT * FROM streams ORDER BY sort_order").fetchall()
    curricula = db.execute("SELECT * FROM curricula ORDER BY id").fetchall()
    subjects = db.execute("SELECT * FROM subjects ORDER BY sort_order").fetchall()

    query = """SELECT q.*, st.name stage_name, sm.name stream_name,
                      su.name subject_name, c.name curriculum_name
               FROM question_bank q
               LEFT JOIN stages st ON st.id = q.stage_id
               LEFT JOIN streams sm ON sm.id = q.stream_id
               LEFT JOIN subjects su ON su.id = q.subject_id
               LEFT JOIN curricula c ON c.id = q.curriculum_id
               WHERE q.is_published = 1"""
    params = []
    if q_subject:
        query += " AND q.subject_id = ?"
        params.append(q_subject)
    if q_stage:
        query += " AND q.stage_id = ?"
        params.append(q_stage)
    if q_stream:
        query += " AND q.stream_id = ?"
        params.append(q_stream)
    if q_curriculum:
        query += " AND q.curriculum_id = ?"
        params.append(q_curriculum)
    query += " ORDER BY q.id DESC LIMIT 100"
    questions = db.execute(query, params).fetchall()

    today_set = db.execute(
        "SELECT * FROM daily_sets WHERE student_id = ? AND set_date = ? ORDER BY id DESC LIMIT 1",
        (student_id, today),
    ).fetchone()
    prev_sets = db.execute(
        """SELECT ds.*, (SELECT COUNT(*) FROM daily_set_questions q WHERE q.set_id = ds.id) q_count
           FROM daily_sets ds WHERE ds.student_id = ? ORDER BY ds.id DESC LIMIT 10""",
        (student_id,),
    ).fetchall()

    return render_template(
        "student_question_bank.html",
        questions=questions, stages=stages, streams=streams, curricula=curricula, subjects=subjects,
        q_subject=q_subject, q_stage=q_stage, q_stream=q_stream, q_curriculum=q_curriculum,
        today_set=today_set, prev_sets=prev_sets,
    )


@app.route("/student/question-bank/start", methods=["POST"])
def student_question_bank_start():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    daily_set = _get_or_create_today_set(db, session["student_id"])
    if not daily_set:
        flash("لسه مفيش أسئلة في البنك — رجّع تاني قريب.", "danger")
        return redirect(url_for("student_question_bank"))
    return redirect(url_for("student_question_bank_set", set_id=daily_set["id"]))


@app.route("/student/question-bank/set/<int:set_id>")
def student_question_bank_set(set_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    daily_set = db.execute(
        "SELECT * FROM daily_sets WHERE id = ? AND student_id = ?",
        (set_id, session["student_id"]),
    ).fetchone()
    if not daily_set:
        abort(404)
    if daily_set["status"] == "submitted":
        return redirect(url_for("student_question_bank_result", set_id=set_id))
    questions = db.execute(
        """SELECT q.*, dsq.id dsq_id, st.name stage_name, su.name subject_name
           FROM daily_set_questions dsq
           JOIN question_bank q ON q.id = dsq.question_id
           LEFT JOIN stages st ON st.id = q.stage_id
           LEFT JOIN subjects su ON su.id = q.subject_id
           WHERE dsq.set_id = ? ORDER BY dsq.id""",
        (set_id,),
    ).fetchall()
    return render_template(
        "student_question_set.html", daily_set=daily_set, questions=questions,
    )


@app.route("/student/question-bank/set/<int:set_id>/submit", methods=["POST"])
def student_question_bank_submit(set_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    daily_set = db.execute(
        "SELECT * FROM daily_sets WHERE id = ? AND student_id = ?",
        (set_id, session["student_id"]),
    ).fetchone()
    if not daily_set:
        abort(404)
    if daily_set["status"] == "submitted":
        return redirect(url_for("student_question_bank_result", set_id=set_id))

    items = db.execute(
        "SELECT id, question_id FROM daily_set_questions WHERE set_id = ?", (set_id,)
    ).fetchall()
    questions = db.execute(
        "SELECT id, correct_index FROM question_bank WHERE id IN (%s)"
        % ",".join("?" * len(items)),
        [i["question_id"] for i in items],
    ).fetchall()
    qmap = {q["id"]: q["correct_index"] for q in questions}

    score = 0
    for item in items:
        answer = request.form.get(f"answer_{item['id']}", type=int)
        correct = (answer is not None and qmap.get(item["question_id"]) == answer)
        if correct:
            score += 1
        db.execute(
            "UPDATE daily_set_questions SET answer_index = ?, is_correct = ? WHERE id = ?",
            (answer, 1 if correct else 0, item["id"]),
        )
    now = datetime.utcnow().isoformat()
    db.execute(
        "UPDATE daily_sets SET status = 'submitted', score = ?, total = ?, submitted_at = ? WHERE id = ?",
        (score, len(items), now, set_id),
    )
    db.commit()
    return redirect(url_for("student_question_bank_result", set_id=set_id))


@app.route("/student/question-bank/set/<int:set_id>/result")
def student_question_bank_result(set_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    daily_set = db.execute(
        "SELECT * FROM daily_sets WHERE id = ? AND student_id = ?",
        (set_id, session["student_id"]),
    ).fetchone()
    if not daily_set:
        abort(404)
    questions = db.execute(
        """SELECT q.*, dsq.answer_index, dsq.is_correct,
                  st.name stage_name, su.name subject_name, sm.name stream_name
           FROM daily_set_questions dsq
           JOIN question_bank q ON q.id = dsq.question_id
           LEFT JOIN stages st ON st.id = q.stage_id
           LEFT JOIN subjects su ON su.id = q.subject_id
           LEFT JOIN streams sm ON sm.id = q.stream_id
           WHERE dsq.set_id = ? ORDER BY dsq.id""",
        (set_id,),
    ).fetchall()
    return render_template(
        "student_question_result.html", daily_set=daily_set, questions=questions,
    )


@app.route("/student/homework")
def student_homework_list():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    student_id = session["student_id"]
    db = get_db()
    student_stream = get_student_stream(db, student_id)
    homework = db.execute(
        """SELECT m.*, t.name teacher_name, s.answer_text, s.grade, s.feedback, s.graded_at, s.submitted_at
           FROM materials m
           JOIN teachers t ON t.id = m.teacher_id
           LEFT JOIN submissions s ON s.material_id = m.id AND s.student_id = ?
           WHERE m.kind = 'واجب' AND (m.stream = '' OR m.stream = ?) AND (
             m.price = 0 OR EXISTS (
               SELECT 1 FROM purchases p WHERE p.material_id = m.id AND p.student_id = ?
             )
           )
           ORDER BY m.id DESC""",
        (student_id, student_stream, student_id),
    ).fetchall()
    hw_assessments = db.execute(
        """SELECT a.id, a.title, a.material_id, m.title lesson_title, t.name teacher_name,
                  (SELECT COUNT(*) FROM assessment_questions q WHERE q.assessment_id = a.id) question_count,
                  (SELECT score FROM assessment_attempts at WHERE at.assessment_id = a.id
                     AND at.student_id = ? ORDER BY at.id DESC LIMIT 1) my_score
           FROM assessments a
           JOIN materials m ON m.id = a.material_id
           JOIN teachers t ON t.id = m.teacher_id
           WHERE a.kind = 'واجب' AND (m.stream = '' OR m.stream = ?) AND (m.price = 0 OR EXISTS (
             SELECT 1 FROM purchases p WHERE p.material_id = m.id AND p.student_id = ?
           ))
           ORDER BY a.id DESC""",
        (student_id, student_stream, student_id),
    ).fetchall()
    return render_template("student_homework.html", homework=homework, hw_assessments=hw_assessments)


@app.route("/student/account")
def student_account():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    student_id = session["student_id"]
    student_name = session["student_name"]
    db = get_db()
    me = db.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()

    purchases = db.execute(
        "SELECT p.material_id, p.purchased_at, p.amount, p.source_type, p.gifted_by, c.name center_name, "
        "  m.title material_title, t.name teacher_name "
        "FROM purchases p "
        "JOIN materials m ON m.id = p.material_id "
        "JOIN teachers t ON t.id = m.teacher_id "
        "LEFT JOIN centers c ON c.id = p.center_id "
        "WHERE p.student_id = ? ORDER BY p.purchased_at DESC",
        (student_id,),
    ).fetchall()
    total_spent = sum(p["amount"] or 0 for p in purchases)

    topups = db.execute(
        "SELECT * FROM wallet_topups WHERE student_id = ? ORDER BY created_at DESC",
        (student_id,),
    ).fetchall()
    wallet_balance = get_wallet_balance(db, student_id)

    transfers = db.execute(
        """SELECT * FROM wallet_transfers WHERE from_student_id = ? OR to_student_id = ?
           ORDER BY created_at DESC""",
        (student_id, student_id),
    ).fetchall()

    # كل نبضة = دقيقة تقريبية من المذاكرة (شوف /student/heartbeat) - بنجمعها
    # لكل مدرس ونحولها لساعات لرسم "كام ساعة قعدت تذاكر عند كل مدرس".
    study_minutes_by_teacher = db.execute(
        """SELECT t.name teacher_name,
             COALESCE(hb.minutes, 0) + COALESCE(vw.minutes, 0) minutes
           FROM teachers t
           LEFT JOIN (
             SELECT teacher_id, COUNT(id) minutes FROM study_heartbeats
             WHERE student_id = ? GROUP BY teacher_id
           ) hb ON hb.teacher_id = t.id
           LEFT JOIN (
             SELECT m.teacher_id, SUM(v.seconds) / 60.0 minutes FROM video_watch v
             JOIN materials m ON m.id = v.material_id
             WHERE v.student_id = ? GROUP BY m.teacher_id
           ) vw ON vw.teacher_id = t.id
           WHERE COALESCE(hb.minutes, 0) + COALESCE(vw.minutes, 0) > 0
           ORDER BY minutes DESC""",
        (student_id, student_id),
    ).fetchall()

    # "مشترك مع كام مستر" = عدد المدرسين المختلفين اللي الطالب فعليًا اشترى
    # منهم حاجة أو كلّم مساعدهم الذكي (مش أي مدرس عنده حصة مجانية بالصدفة).
    teacher_count = db.execute(
        """SELECT COUNT(DISTINCT teacher_id) c FROM (
             SELECT m.teacher_id FROM purchases p JOIN materials m ON m.id = p.material_id
             WHERE p.student_id = ?
             UNION
             SELECT teacher_id FROM chat_messages WHERE student_id = ?
           )""",
        (student_id, student_id),
    ).fetchone()["c"]

    transfer_error = session.pop("transfer_error", None)
    gift_credits = get_gift_credits(db, student_id)

    # --- التقدم: نسبة الحصص المخلصة لكل مدرس + المخطط الشهري + الستريك ---
    progress_by_teacher = []
    teacher_rows = {}
    for p in purchases:
        teacher_rows.setdefault(p["teacher_name"], []).append(p["material_id"])
    for tname, mids in teacher_rows.items():
        done = sum(1 for mid in mids if lesson_completed(db, mid, student_id))
        progress_by_teacher.append({
            "teacher_name": tname,
            "purchased": len(mids),
            "completed": done,
            "percent": round(done / len(mids) * 100) if mids else 0,
        })
    overall_done = sum(m["completed"] for m in progress_by_teacher)
    overall_total = sum(m["purchased"] for m in progress_by_teacher)
    overall_percent = round(overall_done / overall_total * 100) if overall_total else 0

    # كل نبضة = دقيقة، ووقت الفيديو = ثواني. بنجمعهم بالشهر (آخر 6 شهور).
    monthly = db.execute(
        """SELECT ym, SUM(minutes) minutes FROM (
             SELECT substr(created_at, 1, 7) ym, 1 minutes FROM study_heartbeats WHERE student_id = ?
             UNION ALL
             SELECT substr(updated_at, 1, 7) ym, seconds / 60.0 minutes FROM video_watch WHERE student_id = ?
           ) GROUP BY ym ORDER BY ym""",
        (student_id, student_id),
    ).fetchall()
    from collections import OrderedDict
    months = OrderedDict()
    now_dt = datetime.utcnow()
    for i in range(5, -1, -1):
        ym = (now_dt - timedelta(days=30 * i)).strftime("%Y-%m")
        months[ym] = 0.0
    for r in monthly:
        if r["ym"] in months:
            months[r["ym"]] = r["minutes"] or 0
    monthly_hours = [{"month": ym, "hours": round(minutes / 60.0, 1)} for ym, minutes in months.items()]

    # الستريك: أيام متتالية فيهم نشاط مذاكرة.
    streak = study_streak(db, student_id)

    manual_charges = db.execute(
        "SELECT * FROM payment_orders WHERE student_id = ? AND status = 'manual' ORDER BY id DESC",
        (student_id,),
    ).fetchall()
    manual_payment_details = get_setting(db, "manual_payment_details", "")
    instapay_number = get_setting(db, "instapay_number", "")
    vodafone_number = get_setting(db, "vodafone_number", "")
    recharge_whatsapp = get_setting(db, "recharge_whatsapp", "")

    return render_template(
        "student_account.html", student_name=student_name, me=me,
        purchases=purchases, total_spent=total_spent, teacher_count=teacher_count,
        topups=topups, wallet_balance=wallet_balance, transfers=transfers, transfer_error=transfer_error,
        study_minutes_by_teacher=study_minutes_by_teacher, gift_credits=gift_credits,
        manual_charges=manual_charges, manual_payment_details=manual_payment_details,
        instapay_number=instapay_number, vodafone_number=vodafone_number,
        recharge_whatsapp=recharge_whatsapp,
        progress_by_teacher=progress_by_teacher, overall_percent=overall_percent,
        overall_done=overall_done, overall_total=overall_total,
        monthly_hours=monthly_hours, streak=streak,
    )


SUPPORT_KINDS = {
    "orphan": {
        "title": "🤲 تكفل الأيتام",
        "heading": "🤲 شارك في كفالة الأيتام",
        "sub": "ساهم في تعليم يتيم — كفالتك بتفتح حصة لطالب يتيم على حسابك.",
        "details": [
            "ممكن تكفل حصة/دروس كاملة لطالب يتيم عشان يكمل مذاكرته.",
            "الطلب بيوصل للإدارة وهم هيتواصلوا معاك بالتفاصيل.",
            "أي مبلغ معاك — كل حاجة بتفرق.",
        ],
        "placeholder": "اكتب هنا: حابب أكفل حصة في مادة إيه، أو عندي استفسار عن الكفالة...",
    },
    "inability": {
        "title": "عدم المقدرة على الدفع",
        "heading": "طلب إعفاء لعدم المقدرة على الدفع",
        "sub": "مش قادر تدفع؟ قدّم طلب إعفاء والإدارة هتراجع حالتك.",
        "details": [
            "الإدارة بتراجع الطلبات وبتقرر الإعفاء أو التخفيض.",
            "اكتب حالتك بصراحة — المعلومات كلها سرية.",
            "لو تمت الموافقة، الحصص المطلوبة هتتفتح لك مجانًا.",
        ],
        "placeholder": "اكتب هنا: حالتك، إيه المواد اللي محتاجها، وأي تفاصيل الإدارة تحتاج تعرفها...",
    },
}


@app.route("/student/support/<kind>")
def student_support(kind):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    info = SUPPORT_KINDS.get(kind)
    if not info:
        return redirect(url_for("student_account"))
    db = get_db()
    me = db.execute("SELECT * FROM students WHERE id = ?", (session["student_id"],)).fetchone()
    my_requests = db.execute(
        "SELECT * FROM support_requests WHERE student_id = ? AND kind = ? ORDER BY id DESC",
        (session["student_id"], kind),
    ).fetchall()
    return render_template(
        "student_support.html", kind=kind, info=info, me=me, my_requests=my_requests,
    )


@app.route("/student/support/submit", methods=["POST"])
def student_support_submit():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    ip = request.remote_addr or ""
    db = get_db()
    blocked = login_blocked(db, "support", ip, ip)
    if blocked:
        flash(blocked, "danger")
        return redirect(url_for("student_account"))
    kind = request.form.get("kind", "")
    if kind not in SUPPORT_KINDS:
        return redirect(url_for("student_account"))
    message = request.form.get("message", "").strip()[:500]
    contact = request.form.get("contact", "").strip()[:100]
    me = db.execute("SELECT * FROM students WHERE id = ?", (session["student_id"],)).fetchone()
    if me:
        record_login_attempt(db, "support", ip, ip)
        db.execute(
            "INSERT INTO support_requests (kind, student_id, student_name, student_code, contact, message, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (kind, me["id"], me["name"], me["account_code"], contact, message, datetime.utcnow().isoformat()),
        )
        db.commit()
    flash("طلبك اتسجل — الإدارة هتراجعه وتواصل معاك قريبًا.", "success")
    return redirect(url_for("student_support", kind=kind))


@app.route("/student/photo", methods=["POST"])
def student_update_photo():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    photo = save_uploaded_photo(request.files.get("photo"))
    if photo:
        db = get_db()
        db.execute("UPDATE students SET photo = ? WHERE id = ?", (photo, session["student_id"]))
        db.commit()
    return redirect(url_for("student_account"))


# ---------------------------------------------------------------------------
# مهماتي: 10 مهمات بيكتبها الطالب بنفسه، وليها ساعة إيقاف لكل واحدة، ولما
# يعلّمها مكتملة بطلعلو رسالة تهنئة عشوائية. كل حاجة بتحصل بـ AJAX فبترجع
# JSON، والصفحة الرئيسية بتعرض الحالة الحالية (وقت شغال محسوب من الـ DB).
# ---------------------------------------------------------------------------

def fetch_student_tasks(db, student_id: int) -> list:
    ensure_student_tasks(db, student_id)
    rows = db.execute(
        "SELECT * FROM student_tasks WHERE student_id = ? ORDER BY task_number",
        (student_id,),
    ).fetchall()
    tasks = [dict(r) for r in rows]
    for t in tasks:
        t["elapsed_seconds"] = stopwatch_elapsed(t)
    return tasks


@app.route("/student/tasks")
def student_tasks():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student_id = session["student_id"]
    tasks = fetch_student_tasks(db, student_id)
    completed = sum(1 for t in tasks if t["is_completed"])
    return render_template(
        "student_tasks.html",
        student_name=session["student_name"],
        tasks=tasks,
        completed_count=completed,
        total_count=STUDENT_TASKS_COUNT,
    )


@app.route("/student/tasks/save-title", methods=["POST"])
def student_tasks_save_title():
    if "student_id" not in session:
        return jsonify({"error": "not logged in"}), 401
    data = request.get_json(silent=True) or {}
    task_number = int(data.get("task_number") or 0)
    title = str(data.get("title") or "").strip()
    db = get_db()
    ensure_student_tasks(db, session["student_id"])
    if not 1 <= task_number <= STUDENT_TASKS_COUNT:
        return jsonify({"error": "bad task number"}), 400
    db.execute(
        "UPDATE student_tasks SET title = ? WHERE student_id = ? AND task_number = ?",
        (title, session["student_id"], task_number),
    )
    db.commit()
    return jsonify({"ok": True, "title": title})


@app.route("/student/tasks/timer", methods=["POST"])
def student_tasks_timer():
    """التحكم في ساعة الإيقاف بتاعة المهمة: start | pause | reset"""
    if "student_id" not in session:
        return jsonify({"error": "not logged in"}), 401
    data = request.get_json(silent=True) or {}
    task_number = int(data.get("task_number") or 0)
    action = str(data.get("action") or "")
    if action not in {"start", "pause", "reset"}:
        return jsonify({"error": "bad action"}), 400
    db = get_db()
    ensure_student_tasks(db, session["student_id"])
    if not 1 <= task_number <= STUDENT_TASKS_COUNT:
        return jsonify({"error": "bad task number"}), 400
    row = db.execute(
        "SELECT * FROM student_tasks WHERE student_id = ? AND task_number = ?",
        (session["student_id"], task_number),
    ).fetchone()
    if not row:
        return jsonify({"error": "task not found"}), 404

    if action == "start":
        if not row["stopwatch_running"]:
            db.execute(
                "UPDATE student_tasks SET stopwatch_running = 1, stopwatch_started_at = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), row["id"]),
            )
    elif action == "pause":
        add_stopwatch_elapsed(db, row)
    elif action == "reset":
        db.execute(
            "UPDATE student_tasks SET stopwatch_seconds = 0, stopwatch_running = 0, "
            "stopwatch_started_at = NULL WHERE id = ?",
            (row["id"],),
        )
    db.commit()
    refreshed = db.execute(
        "SELECT * FROM student_tasks WHERE id = ?", (row["id"],)
    ).fetchone()
    return jsonify({"ok": True, "elapsed_seconds": stopwatch_elapsed(refreshed)})


@app.route("/student/tasks/complete", methods=["POST"])
def student_tasks_complete():
    """يعلّم المهمة مكتملة (أو يلغيها لو كان كاتب مكتمل) ويرجّع رسالة تهنئة
    عشوائية من القايمة لما بيتعلّم مكتملة. الساعة بتقف تلقائيًا عند الإكمال."""
    if "student_id" not in session:
        return jsonify({"error": "not logged in"}), 401
    data = request.get_json(silent=True) or {}
    task_number = int(data.get("task_number") or 0)
    db = get_db()
    ensure_student_tasks(db, session["student_id"])
    if not 1 <= task_number <= STUDENT_TASKS_COUNT:
        return jsonify({"error": "bad task number"}), 400
    row = db.execute(
        "SELECT * FROM student_tasks WHERE student_id = ? AND task_number = ?",
        (session["student_id"], task_number),
    ).fetchone()
    if not row:
        return jsonify({"error": "task not found"}), 404

    if row["is_completed"]:
        db.execute(
            "UPDATE student_tasks SET is_completed = 0, completed_at = NULL, "
            "congrats_message = '' WHERE id = ?",
            (row["id"],),
        )
        db.commit()
        return jsonify({"ok": True, "completed": False, "message": ""})

    # بيكمل الوقت الجاري لو الساعة شغالة وبيعلّم المهمة مكتملة.
    if row["stopwatch_running"]:
        add_stopwatch_elapsed(db, row)
    message = random.choice(STUDENT_TASK_CONGRATS)
    db.execute(
        "UPDATE student_tasks SET is_completed = 1, completed_at = ?, "
        "congrats_message = ? WHERE id = ?",
        (datetime.utcnow().isoformat(), message, row["id"]),
    )
    db.commit()
    return jsonify({"ok": True, "completed": True, "message": message, "task_number": task_number})


def study_streak(db, student_id: int) -> int:
    """عدد الأيام المتتالية اللي الطالب ذاكر فيها (نبضة / فيديو / فتح حصة).
    لو النهارده مفيش نشاط لسه، بنبدأ العد من إمبارح عشان الستريك ميتقطعش
    قبل آخر اليوم."""
    active_days = set()
    for r in db.execute(
        """SELECT substr(created_at, 1, 10) d FROM study_heartbeats WHERE student_id = ?
           UNION SELECT substr(updated_at, 1, 10) d FROM video_watch WHERE student_id = ?
           UNION SELECT substr(viewed_at, 1, 10) d FROM lesson_views WHERE student_id = ?""",
        (student_id, student_id, student_id),
    ).fetchall():
        active_days.add(r["d"])
    today = datetime.utcnow().date().isoformat()
    cursor = today
    if cursor not in active_days:
        cursor = (datetime.utcnow().date() - timedelta(days=1)).isoformat()
    streak = 0
    while cursor in active_days:
        streak += 1
        cursor = (datetime.strptime(cursor, "%Y-%m-%d") - timedelta(days=1)).isoformat()
    return streak


def L_weekday(d: date, today: str) -> str:
    """اسم اليوم (بالعربي) في شريط الأهداف. النهارده = 'النهارده'."""
    if d.isoformat() == today:
        return "النهارده"
    names = ["السبت", "الأحد", "الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة"]
    return names[d.weekday()]


def get_study_minutes_for_day(db, student_id: int, day: str) -> float:
    """دقايق المذاكرة في يوم معين (YYYY-MM-DD) من النبضات + وقت الفيديو."""
    beats = db.execute(
        "SELECT COUNT(*) c FROM study_heartbeats WHERE student_id = ? AND substr(created_at, 1, 10) = ?",
        (student_id, day),
    ).fetchone()["c"]
    video = db.execute(
        "SELECT COALESCE(SUM(seconds), 0) s FROM video_watch WHERE student_id = ? AND substr(updated_at, 1, 10) = ?",
        (student_id, day),
    ).fetchone()["s"]
    return (beats or 0) + (video or 0) / 60.0


@app.route("/student/goals")
def student_goals():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student_id = session["student_id"]
    now_dt = datetime.utcnow().date()
    today = now_dt.isoformat()
    days = [now_dt + timedelta(days=i) for i in range(-1, 6)]  # إمبارح + 7 أيام
    week = []
    for d in days:
        ds = d.isoformat()
        row = db.execute(
            "SELECT * FROM student_daily_goals WHERE student_id = ? AND goal_date = ?",
            (student_id, ds),
        ).fetchone()
        week.append({
            "date": ds,
            "label": L_weekday(d, today),
            "is_today": ds == today,
            "target_minutes": row["target_minutes"] if row else 0,
            "note": row["note"] if row else "",
            "minutes": round(get_study_minutes_for_day(db, student_id, ds), 1),
        })
        if row and week[-1]["minutes"] >= (row["target_minutes"] or 1):
            week[-1]["achieved"] = 1
        else:
            week[-1]["achieved"] = 0
    today_row = db.execute(
        "SELECT * FROM student_daily_goals WHERE student_id = ? AND goal_date = ?",
        (student_id, today),
    ).fetchone()
    return render_template(
        "student_goals.html",
        student_name=session["student_name"],
        week=week,
        today=today,
        today_target=today_row["target_minutes"] if today_row else 0,
        today_note=today_row["note"] if today_row else "",
        today_minutes=round(get_study_minutes_for_day(db, student_id, today), 1),
        streak=study_streak(db, student_id),
    )


@app.route("/student/goals/set", methods=["POST"])
def student_goals_set():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student_id = session["student_id"]
    goal_date = str(request.form.get("goal_date") or datetime.utcnow().date().isoformat())
    try:
        target = max(1, min(1440, int(float(request.form.get("target_minutes") or 0))))
    except ValueError:
        target = 60
    note = str(request.form.get("note") or "").strip()[:200]
    now = datetime.utcnow().isoformat()
    db.execute(
        """INSERT INTO student_daily_goals (student_id, goal_date, target_minutes, note, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT (student_id, goal_date) DO UPDATE SET
             target_minutes = excluded.target_minutes,
             note = excluded.note,
             updated_at = excluded.updated_at""",
        (student_id, goal_date, target, note, now, now),
    )
    db.commit()
    return redirect(url_for("student_goals"))


def get_my_student_code() -> str | None:
    """Session has the account_code since the messaging/gifting features were
    added; older active sessions (logged in before that) won't have it yet,
    so fall back to a DB lookup by student_id."""
    code = session.get("student_code")
    if code:
        return code
    db = get_db()
    row = db.execute("SELECT account_code FROM students WHERE id = ?", (session.get("student_id"),)).fetchone()
    if row:
        session["student_code"] = row["account_code"]
        return row["account_code"]
    return None


def get_gift_credits(db, student_id: int) -> int:
    """الطالب بيكسب هدية مجانية واحدة (يقدر يديها لأي صاحب) كل ما يشتري
    حصتين فعليين (مش هدايا واصلاله هو). كل هدية بيديها بتستهلك كريديت واحد."""
    real_purchases = db.execute(
        "SELECT COUNT(*) c FROM purchases WHERE student_id = ? AND (gifted_by IS NULL) AND amount > 0",
        (student_id,),
    ).fetchone()["c"]
    earned = real_purchases // 2
    used = db.execute(
        "SELECT COUNT(*) c FROM purchases WHERE gifted_by_id = ? OR (gifted_by_id IS NULL AND gifted_by = ?)",
        (student_id, _student_name_by_id(db, student_id)),
    ).fetchone()["c"]
    return max(0, earned - used)


def get_wallet_balance(db, student_id: int) -> float:
    topped_up = db.execute(
        "SELECT COALESCE(SUM(amount), 0) t FROM wallet_topups WHERE student_id = ?", (student_id,)
    ).fetchone()["t"]
    sent = db.execute(
        "SELECT COALESCE(SUM(amount), 0) t FROM wallet_transfers WHERE from_student_id = ?", (student_id,)
    ).fetchone()["t"]
    received = db.execute(
        "SELECT COALESCE(SUM(amount), 0) t FROM wallet_transfers WHERE to_student_id = ?", (student_id,)
    ).fetchone()["t"]
    return topped_up - sent + received


@app.route("/student/transfer", methods=["POST"])
def student_transfer():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    my_id = session["student_id"]
    my_name = session["student_name"]
    ip = request.remote_addr or ""
    db = get_db()
    blocked = login_blocked(db, "transfer", my_name, ip)
    if blocked:
        session["transfer_error"] = blocked
        return redirect(url_for("student_account"))
    friend_code = request.form.get("friend_code", "").strip().upper()
    try:
        amount = float(request.form.get("amount", 0) or 0)
    except ValueError:
        amount = 0

    friend = db.execute("SELECT * FROM students WHERE account_code = ?", (friend_code,)).fetchone()

    if not friend:
        error = "كود صاحبك غلط."
    elif friend["id"] == my_id:
        error = "مينفعش تحوّل لنفسك."
    elif amount <= 0:
        error = "حط مبلغ صحيح."
    elif get_wallet_balance(db, my_id) < amount:
        error = "رصيدك مش كفاية."
    else:
        record_login_attempt(db, "transfer", my_name, ip)
        db.execute(
            "INSERT INTO wallet_transfers (from_student_id, to_student_id, from_student, to_student, amount, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (my_id, friend["id"], my_name, friend["name"], amount, datetime.utcnow().isoformat()),
        )
        db.commit()
        error = None

    if error:
        session["transfer_error"] = error
    return redirect(url_for("student_account"))


@app.route("/student/gift/<int:material_id>", methods=["POST"])
def student_gift_lesson(material_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    my_id = session["student_id"]
    my_name = session["student_name"]
    friend_code = request.form.get("friend_code", "").strip().upper()

    db = get_db()
    material = db.execute("SELECT * FROM materials WHERE id = ?", (material_id,)).fetchone()
    friend = db.execute("SELECT * FROM students WHERE account_code = ?", (friend_code,)).fetchone()
    credits = get_gift_credits(db, my_id)

    if material and friend and credits > 0 and friend["id"] != my_id:
        db.execute(
            """INSERT INTO purchases (material_id, student_id, student_name, purchased_at, amount, source_type, gifted_by, gifted_by_id)
               VALUES (?, ?, ?, ?, ?, 'هدية', ?, ?)
               ON CONFLICT(material_id, student_id)
               DO UPDATE SET purchased_at = excluded.purchased_at, source_type = 'هدية', gifted_by = excluded.gifted_by, gifted_by_id = excluded.gifted_by_id""",
            (material_id, friend["id"], friend["name"], datetime.utcnow().isoformat(), 0, my_name, my_id),
        )
        db.commit()
        return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))

    return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"] if material else 1))


@app.route("/student/messages")
def student_messages():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    my_code = get_my_student_code()
    db = get_db()
    friends = db.execute(
        """SELECT DISTINCT other FROM (
             SELECT to_code other FROM student_messages WHERE from_code = ?
             UNION
             SELECT from_code other FROM student_messages WHERE to_code = ?
           )""",
        (my_code, my_code),
    ).fetchall()
    friend_rows = []
    for f in friends:
        s = db.execute("SELECT name, account_code FROM students WHERE account_code = ?", (f["other"],)).fetchone()
        if s:
            friend_rows.append(s)
    return render_template("student_messages.html", friends=friend_rows)


@app.route("/student/messages/<friend_code>", methods=["GET", "POST"])
def student_chat_with_friend(friend_code):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    my_code = get_my_student_code()
    db = get_db()
    friend_code = friend_code.strip().upper()
    friend = db.execute("SELECT * FROM students WHERE account_code = ?", (friend_code,)).fetchone()
    if not friend or friend_code == my_code:
        return redirect(url_for("student_messages"))

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if content:
            db.execute(
                "INSERT INTO student_messages (from_code, to_code, content, created_at) VALUES (?, ?, ?, ?)",
                (my_code, friend_code, content, datetime.utcnow().isoformat()),
            )
            db.commit()
        return redirect(url_for("student_chat_with_friend", friend_code=friend_code))

    messages = db.execute(
        """SELECT * FROM student_messages
           WHERE (from_code = ? AND to_code = ?) OR (from_code = ? AND to_code = ?)
           ORDER BY id""",
        (my_code, friend_code, friend_code, my_code),
    ).fetchall()
    return render_template(
        "student_chat.html", friend_name=friend["name"], friend_code=friend_code,
        messages=messages, my_code=my_code,
    )


@app.route("/student/topup", methods=["POST"])
def student_topup():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    ip = request.remote_addr or ""
    db = get_db()
    my_id = session["student_id"]
    my_name = session["student_name"]
    blocked = login_blocked(db, "topup", my_name, ip)
    if blocked:
        flash(blocked, "danger")
        return redirect(url_for("student_account"))
    method = request.form.get("method", "").strip()
    valid_methods = {"فيزا", "فوري", "محفظة إلكترونية"}
    manual_methods = {"فودافون كاش", "إنستاباي", "تحويل بنكي"}
    try:
        amount = float(request.form.get("amount", 0) or 0)
    except ValueError:
        amount = 0

    if method in manual_methods and amount > 0:
        # شحن يدوي: الطالب بيبعت المبلغ لرقم الإدارة (إنستاباي/فودافون كاش) ويرفع
        # سكرين التحويل، والإدارة بتتأكد وبتعتمد الشحنة من لوحة التحكم.
        record_login_attempt(db, "topup", my_name, ip)
        proof = save_uploaded_photo(request.files.get("proof_photo"))
        db.execute(
            "INSERT INTO payment_orders (student_id, student_name, kind, amount, status, method, proof_photo, created_at) "
            "VALUES (?, ?, 'topup', ?, 'manual', ?, ?, ?)",
            (my_id, my_name, amount, method, proof or "", datetime.utcnow().isoformat()),
        )
        db.commit()
        flash(
            f"حلو! ابعت {int(amount)} ج على {method} لرقم الإدارة، وخلّي اسمك واضح في التحويل — "
            "الإدارة هتتأكد من الصورة وتضيفها لمحفظتك على طول.",
            "success",
        )
        return redirect(url_for("student_account"))
    if method in valid_methods and amount > 0:
        record_login_attempt(db, "topup", my_name, ip)
        cfg = _paymob_config()
        if get_setting(db, "payment_mode", "محاكاة") == "حقيقي" and _paymob_ready(cfg):
            cur = db.execute(
                "INSERT INTO payment_orders (student_id, student_name, kind, amount, status, method, created_at) "
                "VALUES (?, ?, 'topup', ?, 'pending', ?, ?)",
                (my_id, my_name, amount, method, datetime.utcnow().isoformat()),
            )
            db.commit()
            url = _start_paymob_payment(
                db, cur.lastrowid, my_id, my_name, amount, f"شحن محفظة {my_name}"
            )
            return redirect(url) if url else redirect(url_for("student_account"))
        db.execute(
            "INSERT INTO wallet_topups (student_id, student_name, amount, method, created_at) VALUES (?, ?, ?, ?, ?)",
            (my_id, my_name, amount, method, datetime.utcnow().isoformat()),
        )
        db.commit()
    return redirect(url_for("student_account"))


@app.route("/student/redeem-code", methods=["POST"])
def student_redeem_code():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    ip = request.remote_addr or ""
    db = get_db()
    my_id = session["student_id"]
    my_name = session["student_name"]
    blocked = login_blocked(db, "redeem", my_name, ip)
    if blocked:
        flash(blocked, "danger")
        return redirect(url_for("student_account"))
    ok, msg = redeem_recharge_code(db, my_id, my_name, request.form.get("code", ""))
    record_login_attempt(db, "redeem", my_name, ip)
    flash(msg, "success" if ok else "danger")
    return redirect(url_for("student_account"))


@app.route("/student/buy/<int:material_id>", methods=["POST"])
def student_buy(material_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    my_id = session["student_id"]
    my_name = session["student_name"]
    material = db.execute("SELECT * FROM materials WHERE id = ?", (material_id,)).fetchone()
    if not material:
        return redirect(url_for("student_browse"))
    block = is_student_blocked(db, material["teacher_id"], my_id)
    if block:
        teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (material["teacher_id"],)).fetchone()
        return render_template("student_blocked.html", teacher=teacher, block=block), 403
    if material["stream"] and material["stream"] != get_student_stream(db, my_id):
        return redirect(url_for("student_browse"))
    cfg = _paymob_config()
    if (get_setting(db, "payment_mode", "محاكاة") == "حقيقي"
            and material["price"] > 0 and _paymob_ready(cfg)):
        cur = db.execute(
            "INSERT INTO payment_orders (student_id, student_name, kind, material_id, amount, status, created_at) "
            "VALUES (?, ?, 'buy', ?, ?, 'pending', ?)",
            (my_id, my_name, material_id, material["price"], datetime.utcnow().isoformat()),
        )
        db.commit()
        url = _start_paymob_payment(
            db, cur.lastrowid, my_id, my_name, material["price"], f"شراء حصة: {material['title']}"
        )
        return redirect(url) if url else redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))
    if material["price"] > 0 and get_setting(db, "payment_mode", "محاكاة") == "حقيقي":
        flash("بوابة الدفع لسه مش متظبطة — أتصل بالإدارة.", "danger")
        return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))
    # Prototype "purchase": instant, no real payment gateway wired up yet.
    # ON CONFLICT DO UPDATE (مش INSERT OR IGNORE) عشان لو الطالب بيشتري تاني
    # بعد ما انتهت مدة الإتاحة، الشراء الجديد يجدد المدة فعليًا بدل ما يتجاهله.
    db.execute(
        """INSERT INTO purchases (material_id, student_id, student_name, purchased_at, amount, source_type)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(material_id, student_id)
           DO UPDATE SET purchased_at = excluded.purchased_at, amount = excluded.amount""",
        (material_id, my_id, my_name, datetime.utcnow().isoformat(), material["price"], "مباشر"),
    )
    db.commit()
    return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))


@app.route("/student/payment/result")
def student_payment_result():
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    payment = db.execute(
        "SELECT * FROM payment_orders WHERE student_id = ? ORDER BY id DESC LIMIT 1",
        (session["student_id"],),
    ).fetchone()
    return render_template("student_payment_result.html", payment=payment)


@app.route("/paymob/callback", methods=["POST"])
def paymob_callback():
    data = request.get_json(force=True, silent=True) or {}
    cfg = _paymob_config()
    if not _paymob_ready(cfg):
        return ("not configured", 200)
    hmac_secret = cfg.get("hmac_secret")
    obj = data.get("obj") or {}
    received_hmac = data.get("hmac", "")
    if not hmac_secret or not paymob_verify_hmac(obj, hmac_secret, received_hmac):
        return ("bad signature", 200)
    order = obj.get("order") or {}
    merchant_order_id = order.get("merchant_order_id")
    if merchant_order_id:
        try:
            order_id = int(merchant_order_id)
        except (TypeError, ValueError):
            order_id = None
        if order_id:
            db = get_db()
            po = db.execute("SELECT * FROM payment_orders WHERE id = ?", (order_id,)).fetchone()
            if po and po["status"] == "pending":
                if obj.get("success"):
                    _fulfill_payment(db, po, obj.get("id"))
                else:
                    db.execute("UPDATE payment_orders SET status = 'failed' WHERE id = ?", (po["id"],))
                    db.commit()
    return ("success", 200)


@app.route("/student/review/<int:material_id>", methods=["POST"])
def student_review(material_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    student_id = session["student_id"]
    student_name = session["student_name"]
    db = get_db()
    material = db.execute("SELECT * FROM materials WHERE id = ?", (material_id,)).fetchone()
    if not material:
        return redirect(url_for("student_browse"))

    owns = material["price"] == 0 or db.execute(
        "SELECT 1 FROM purchases WHERE material_id = ? AND student_id = ?",
        (material_id, student_id),
    ).fetchone()
    if not owns:
        return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))
    if material["stream"] and material["stream"] != get_student_stream(db, student_id):
        return redirect(url_for("student_browse"))
    if get_sequence_blocker(db, material, student_id):
        return redirect(url_for("student_lesson", material_id=material_id))

    try:
        rating = int(request.form.get("rating", 0))
    except (TypeError, ValueError):
        rating = 0
    rating = max(1, min(5, rating))
    comment = request.form.get("comment", "").strip()

    db.execute(
        """INSERT INTO reviews (material_id, student_id, student_name, rating, comment, created_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(material_id, student_id)
           DO UPDATE SET rating = excluded.rating, comment = excluded.comment""",
        (material_id, student_id, student_name, rating, comment, datetime.utcnow().isoformat()),
    )
    db.commit()
    return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))


@app.route("/student/heartbeat/<int:teacher_id>", methods=["POST"])
def student_heartbeat(teacher_id):
    if "student_id" not in session:
        return jsonify({"ok": False}), 401
    db = get_db()
    db.execute(
        "INSERT INTO study_heartbeats (student_id, student_name, teacher_id, created_at) VALUES (?, ?, ?, ?)",
        (session["student_id"], session["student_name"], teacher_id, datetime.utcnow().isoformat()),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/student/video-progress/<int:material_id>", methods=["POST"])
def student_video_progress(material_id):
    if "student_id" not in session:
        return jsonify({"ok": False}), 401
    student_id = session["student_id"]
    student_name = session["student_name"]
    db = get_db()
    material = db.execute("SELECT * FROM materials WHERE id = ? AND kind = 'فيديو'", (material_id,)).fetchone()
    if not material:
        return jsonify({"ok": False}), 404

    owns = material["price"] == 0 or db.execute(
        "SELECT 1 FROM purchases WHERE material_id = ? AND student_id = ?",
        (material_id, student_id),
    ).fetchone()
    if not owns:
        return jsonify({"ok": False}), 403
    if material["stream"] and material["stream"] != get_student_stream(db, student_id):
        return jsonify({"ok": False}), 403
    if get_sequence_blocker(db, material, student_id):
        return jsonify({"ok": False}), 403

    try:
        seconds = float(request.get_json(silent=True).get("seconds", 0))
    except (TypeError, ValueError, AttributeError):
        seconds = 0
    # سقف لكل نبضة - عشان محدش يبعت رقم مصطنع كبير من الـ devtools
    # ويضخم وقت مذاكرته. النبضة الحقيقية بتتبعت كل 10 ثواني تقريبًا.
    seconds = max(0, min(seconds, 20))

    db.execute(
        """INSERT INTO video_watch (material_id, student_id, student_name, seconds, updated_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(material_id, student_id)
           DO UPDATE SET seconds = seconds + excluded.seconds, updated_at = excluded.updated_at""",
        (material_id, student_id, student_name, seconds, datetime.utcnow().isoformat()),
    )
    db.commit()
    return jsonify({"ok": True})


def notify_teacher(db, teacher_id, kind, material_id, student_id, student_name, message):
    """يسجل إشعار للمدرس (بيظهر في لوحته مع بادج للغير المقروء). لو حصل
    خطأ بيتجاهله بصمت عشان ميخربش تسليم الطالب."""
    try:
        db.execute(
            "INSERT INTO notifications (teacher_id, kind, material_id, student_id, student_name, message, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (teacher_id, kind, material_id, student_id, student_name, message, datetime.utcnow().isoformat()),
        )
    except Exception:
        pass


@app.route("/student/homework/<int:material_id>/submit", methods=["POST"])
def student_submit_homework(material_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    student_id = session["student_id"]
    student_name = session["student_name"]
    db = get_db()
    material = db.execute("SELECT * FROM materials WHERE id = ?", (material_id,)).fetchone()
    if not material or material["kind"] != "واجب":
        return redirect(url_for("student_login"))

    owns = material["price"] == 0 or db.execute(
        "SELECT 1 FROM purchases WHERE material_id = ? AND student_id = ?",
        (material_id, student_id),
    ).fetchone()
    if not owns:
        return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))
    if material["stream"] and material["stream"] != get_student_stream(db, student_id):
        return redirect(url_for("student_browse"))
    if get_sequence_blocker(db, material, student_id):
        return redirect(url_for("student_lesson", material_id=material_id))

    answer_text = request.form.get("answer_text", "").strip()
    if answer_text:
        # طالب واحد بيسلّم مرة واحدة لكل واجب، لكن يقدر يعيد التسليم (تعديل
        # إجابته) طول ما الواجب لسه من غير تصحيح. أول ما المدرس يصحّح،
        # التسليم بيتقفل نهائيًا.
        existing = db.execute(
            "SELECT * FROM submissions WHERE material_id = ? AND student_id = ?",
            (material_id, student_id),
        ).fetchone()
        if existing is None or existing["graded_at"] is None:
            db.execute(
                """INSERT INTO submissions (material_id, student_id, student_name, answer_text, submitted_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(material_id, student_id)
                   DO UPDATE SET answer_text = excluded.answer_text, submitted_at = excluded.submitted_at""",
                (material_id, student_id, student_name, answer_text, datetime.utcnow().isoformat()),
            )
            db.commit()
            if existing is None:
                notify_teacher(
                    db, material["teacher_id"], "homework", material_id, student_id, student_name,
                    f"سلّم {student_name} واجب: {material['title']}",
                )
                db.commit()
    return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))


@app.route("/student/exam/<int:material_id>/submit", methods=["POST"])
def student_submit_exam(material_id):
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    student_id = session["student_id"]
    student_name = session["student_name"]
    db = get_db()
    material = db.execute("SELECT * FROM materials WHERE id = ?", (material_id,)).fetchone()
    if not material or material["kind"] != "امتحان":
        return redirect(url_for("student_browse"))

    owns = material["price"] == 0 or db.execute(
        "SELECT 1 FROM purchases WHERE material_id = ? AND student_id = ?",
        (material_id, student_id),
    ).fetchone()
    if not owns:
        return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))
    if material["stream"] and material["stream"] != get_student_stream(db, student_id):
        return redirect(url_for("student_browse"))
    if get_sequence_blocker(db, material, student_id):
        return redirect(url_for("student_lesson", material_id=material_id))

    answer_text = request.form.get("answer_text", "").strip()
    if answer_text:
        # نفس منطق الواجبات: تسليم واحد، وإعادة تسليم مسموحة بس قبل التصحيح.
        existing = db.execute(
            "SELECT * FROM exam_submissions WHERE material_id = ? AND student_id = ?",
            (material_id, student_id),
        ).fetchone()
        if existing is None or existing["graded_at"] is None:
            db.execute(
                """INSERT INTO exam_submissions (material_id, student_id, student_name, answer_text, submitted_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(material_id, student_id)
                   DO UPDATE SET answer_text = excluded.answer_text, submitted_at = excluded.submitted_at""",
                (material_id, student_id, student_name, answer_text, datetime.utcnow().isoformat()),
            )
            db.commit()
            if existing is None:
                notify_teacher(
                    db, material["teacher_id"], "exam", material_id, student_id, student_name,
                    f"سلّم {student_name} امتحان: {material['title']}",
                )
                db.commit()
    return redirect(url_for("student_teacher_view", teacher_id=material["teacher_id"]))


@app.route("/student/assessment/<int:assessment_id>", methods=["GET"])
def student_assessment(assessment_id):
    """شاشة لوحده للطالب: بيحل فيها الامتحان/الواجب (اختيار من متعدد)."""
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student_id = session["student_id"]
    assessment = db.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
    if not assessment:
        return redirect(url_for("student_browse"))
    material, unlocked = material_access(db, assessment["material_id"], student_id)
    if not material:
        return redirect(url_for("student_browse"))
    if material["stream"] and material["stream"] != get_student_stream(db, student_id):
        return redirect(url_for("student_browse"))
    if not unlocked:
        return redirect(url_for("student_lesson", material_id=material["id"]))
    if get_sequence_blocker(db, material, student_id):
        return redirect(url_for("student_lesson", material_id=material["id"]))
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (material["teacher_id"],)).fetchone()
    questions = db.execute(
        "SELECT * FROM assessment_questions WHERE assessment_id = ? ORDER BY sort_order, id",
        (assessment_id,),
    ).fetchall()
    latest = db.execute(
        "SELECT * FROM assessment_attempts WHERE assessment_id = ? AND student_id = ? "
        "ORDER BY id DESC LIMIT 1",
        (assessment_id, student_id),
    ).fetchone()
    return render_template(
        "student_assessment.html", assessment=assessment, material=material, teacher=teacher,
        questions=questions, latest=latest,
    )


@app.route("/student/assessment/<int:assessment_id>/submit", methods=["POST"])
def student_assessment_submit(assessment_id):
    """تصحيح فوري: يحسب النتيجة فور التسليم ويسجّل محاولة للطالب."""
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student_id = session["student_id"]
    student_name = session["student_name"]
    assessment = db.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
    if not assessment:
        return redirect(url_for("student_browse"))
    material, unlocked = material_access(db, assessment["material_id"], student_id)
    if not material or not unlocked:
        return redirect(url_for("student_lesson", material_id=assessment["material_id"]))
    if material["stream"] and material["stream"] != get_student_stream(db, student_id):
        return redirect(url_for("student_browse"))
    if get_sequence_blocker(db, material, student_id):
        return redirect(url_for("student_lesson", material_id=assessment["material_id"]))
    questions = db.execute(
        "SELECT * FROM assessment_questions WHERE assessment_id = ? ORDER BY sort_order, id",
        (assessment_id,),
    ).fetchall()
    answers = {}
    for q in questions:
        raw = request.form.get(f"q_{q['id']}")
        if raw in ("0", "1", "2", "3"):
            answers[str(q["id"])] = int(raw)
    correct = sum(1 for q in questions if answers.get(str(q["id"])) == q["correct_index"])
    total = len(questions)
    score = round(correct / total * 100, 1) if total else 0.0
    db.execute(
        "INSERT INTO assessment_attempts (assessment_id, student_id, student_name, answers, score, correct_count, total_count, submitted_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (assessment_id, student_id, student_name, json.dumps(answers), score, correct, total, datetime.utcnow().isoformat()),
    )
    db.commit()
    notify_teacher(
        db, material["teacher_id"], "assessment", material["id"], student_id, student_name,
        f"حلّ {student_name} {assessment['title']} وحصل على {score:.0f}%",
    )
    db.commit()
    return redirect(url_for("student_assessment_result", assessment_id=assessment_id))


@app.route("/student/assessment/<int:assessment_id>/result")
def student_assessment_result(assessment_id):
    """النتيجة فورية: نسبة الطالب + صح/غلط لكل سؤال + فيديو شرح للأسئلة
    الغلط بس (لو المدرس حط فيديو للسؤال ده)."""
    if "student_id" not in session:
        return redirect(url_for("student_login"))
    db = get_db()
    student_id = session["student_id"]
    assessment = db.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
    if not assessment:
        return redirect(url_for("student_browse"))
    material, unlocked = material_access(db, assessment["material_id"], student_id)
    if not material or not unlocked:
        return redirect(url_for("student_lesson", material_id=assessment["material_id"]))
    if material["stream"] and material["stream"] != get_student_stream(db, student_id):
        return redirect(url_for("student_browse"))
    if get_sequence_blocker(db, material, student_id):
        return redirect(url_for("student_lesson", material_id=assessment["material_id"]))
    attempt = db.execute(
        "SELECT * FROM assessment_attempts WHERE assessment_id = ? AND student_id = ? "
        "ORDER BY id DESC LIMIT 1",
        (assessment_id, student_id),
    ).fetchone()
    if not attempt:
        return redirect(url_for("student_assessment", assessment_id=assessment_id))
    questions = db.execute(
        "SELECT * FROM assessment_questions WHERE assessment_id = ? ORDER BY sort_order, id",
        (assessment_id,),
    ).fetchall()
    try:
        answers = json.loads(attempt["answers"])
    except (ValueError, TypeError):
        answers = {}
    per_question = []
    for q in questions:
        chosen = answers.get(str(q["id"]))
        is_correct = chosen is not None and chosen == q["correct_index"]
        per_question.append({
            "question": q,
            "chosen": chosen,
            "correct": is_correct,
            "show_video": (not is_correct) and bool(q["explain_video"] or q["explain_url"]),
        })
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (material["teacher_id"],)).fetchone()
    return render_template(
        "student_assessment_result.html", assessment=assessment, material=material, teacher=teacher,
        attempt=attempt, per_question=per_question, student_name=student_name,
    )


@app.route("/teacher/<int:teacher_id>/exam-submissions/<int:submission_id>/grade", methods=["POST"])
def teacher_grade_exam_submission(teacher_id, submission_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    grade = request.form.get("grade", "").strip()
    feedback = request.form.get("feedback", "").strip()
    db = get_db()
    owns_it = db.execute(
        "SELECT 1 FROM exam_submissions s JOIN materials m ON m.id = s.material_id "
        "WHERE s.id = ? AND m.teacher_id = ?",
        (submission_id, teacher_id),
    ).fetchone()
    if owns_it and grade:
        db.execute(
            "UPDATE exam_submissions SET grade = ?, feedback = ?, graded_at = ? WHERE id = ?",
            (grade, feedback, datetime.utcnow().isoformat(), submission_id),
        )
        db.commit()
    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))


@app.route("/teacher/<int:teacher_id>/submissions/<int:submission_id>/grade", methods=["POST"])
def teacher_grade_submission(teacher_id, submission_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    grade = request.form.get("grade", "").strip()
    feedback = request.form.get("feedback", "").strip()
    db = get_db()
    # يتأكد إن الواجب فعلاً بتاع نفس المدرس قبل ما يعدّل حاجة.
    owns_it = db.execute(
        "SELECT 1 FROM submissions s JOIN materials m ON m.id = s.material_id "
        "WHERE s.id = ? AND m.teacher_id = ?",
        (submission_id, teacher_id),
    ).fetchone()
    if owns_it and grade:
        db.execute(
            "UPDATE submissions SET grade = ?, feedback = ?, graded_at = ? WHERE id = ?",
            (grade, feedback, datetime.utcnow().isoformat(), submission_id),
        )
        db.commit()
    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))


@app.route("/api/chat/<int:teacher_id>", methods=["POST"])
def api_chat(teacher_id):
    if "student_id" not in session:
        return jsonify({"error": "not logged in"}), 401

    student_id = session["student_id"]
    student_name = session["student_name"]
    question = request.json.get("question", "").strip()
    if not question:
        return jsonify({"error": "empty question"}), 400
    if len(question) > CHAT_MAX_QUESTION_LENGTH:
        return jsonify({"error": "السؤال طويل أوي - اختصره."}), 400

    db = get_db()
    cutoff = (datetime.utcnow() - timedelta(minutes=1)).isoformat()
    recent = db.execute(
        "SELECT COUNT(*) AS n FROM chat_messages WHERE student_id = ? AND role = 'student' AND created_at > ?",
        (student_id, cutoff),
    ).fetchone()["n"]
    if recent >= CHAT_MAX_QUESTIONS_PER_MINUTE:
        return jsonify({"error": "بتسأل بسرعة جدًا - استنى شوية وجرب تاني."}), 429
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    if not teacher:
        return jsonify({"error": "المدرس ده مش موجود."}), 404
    if is_student_blocked(db, teacher_id, student_id):
        return jsonify({
            "error": "المدرس وقّف الدردشة معاك — راسل الدعم الفني لو محتاج مساعدة.",
        }), 403
    if not teacher_ai_active(db, teacher):
        return jsonify({
            "error": "مساعد الذكاء الاصطناعي بتاع المدرس ده لسه مش شغال دلوقتي — اسأل المدرس مباشرة.",
        }), 403
    context = build_teacher_context(db, teacher_id, student_name)

    system_prompt = (
        f"أنت مساعد ذكاء اصطناعي خاص بالمدرس {teacher['name']} لمادة {teacher['subject']} "
        f"لطلاب الثانوية العامة المصرية. أجب على أسئلة الطالب بالاعتماد فقط على محتوى المدرس "
        f"التالي، وبأسلوب مبسط وتشجيعي باللغة العربية. لو السؤال خارج نطاق المحتوى المتاح، "
        f"وضح للطالب إن المحتوى ده لسه مش متاح من المدرس واقترح إنه يسأل المدرس مباشرة.\n\n"
        f"محتوى المدرس:\n{context}"
    )

    answer = call_claude(system_prompt, question)

    now = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO chat_messages (teacher_id, student_id, student_name, role, content, created_at) VALUES (?, ?, ?, 'student', ?, ?)",
        (teacher_id, student_id, student_name, question, now),
    )
    db.execute(
        "INSERT INTO chat_messages (teacher_id, student_id, student_name, role, content, created_at) VALUES (?, ?, ?, 'assistant', ?, ?)",
        (teacher_id, student_id, student_name, answer, now),
    )
    db.commit()

    return jsonify({"answer": answer})


# ---------------------------------------------------------------------------
# Routes - parent side (متابعة ولي الأمر)
# ---------------------------------------------------------------------------

def _phone_key(phone: str) -> str:
    """يطبّع رقم موبايل للمقارنة: يخلّي الأرقام بس ويرجّعها بصيغة موحدة
    (010... / 011... / 015...). بيتعامل مع 2+ / +20 / صفر كدولة مصر."""
    digits = "".join(ch for ch in phone if ch.isdigit())
    if not digits:
        return ""
    if digits.startswith("0020"):
        digits = digits[4:]
    elif digits.startswith("20"):
        digits = digits[2:]
    elif digits.startswith("00"):
        digits = digits[2:]
    if not digits.startswith("0") and len(digits) == 10:
        digits = "0" + digits
    return digits


@app.route("/parent/login", methods=["GET", "POST"])
def parent_login():
    """دخول ولي الأمر: بيستخدم كود حساب الطالب + رقم موبايل ولي الأمر المسجل
    عند التسجيل. عرض كامل وبيقرأ بس — ولي الأمر مبيقدرش يعدّل حاجة."""
    error = None
    if request.method == "POST":
        account_code = request.form.get("account_code", "").strip().upper()
        parent_phone = request.form.get("parent_phone", "").strip()
        db = get_db()
        ip = request.remote_addr or ""
        blocked = login_blocked(db, "parent", account_code, ip)
        if blocked:
            error = blocked
        elif not account_code or not parent_phone:
            error = "اكتب كود حساب الطالب ورقم موبايل ولي الأمر."
        else:
            student = db.execute("SELECT * FROM students WHERE account_code = ?", (account_code,)).fetchone()
            if student and student["is_blocked"]:
                error = "حساب الطالب ده متوقف حاليًا."
            elif student and _phone_key(student["parent_phone"]) == _phone_key(parent_phone):
                clear_login_attempts(db, "parent", account_code, ip)
                session.clear()
                session["parent_student_id"] = student["id"]
                session["parent_name"] = student["parent_name"] or student["name"]
                log_security_event("parent_login", f"{student['name']} ({account_code})")
                return redirect(url_for("parent_dashboard"))
            else:
                record_login_attempt(db, "parent", account_code, ip)
                log_security_event("parent_login_failed", f"{account_code} من {ip}")
                error = "كود الحساب أو رقم الموبايل غلط — اتأكد من البيانات المسجلة."
    return render_template("parent_login.html", error=error)


@app.route("/parent/logout", methods=["POST"])
def parent_logout():
    session.pop("parent_student_id", None)
    session.pop("parent_name", None)
    return redirect(url_for("home"))


@app.route("/parent")
def parent_index():
    if "parent_student_id" in session:
        return redirect(url_for("parent_dashboard"))
    return redirect(url_for("parent_login"))


@app.route("/parent/dashboard")
def parent_dashboard():
    """لوحة متابعة ولي الأمر: ساعات المذاكرة، الحصص المشترك فيها والمخلصة،
    المصروفات، والنتائج — كل حاجة بتتقري من بيانات النشاط اللي الطالب بيعملها."""
    if "parent_student_id" not in session:
        return redirect(url_for("parent_login"))
    db = get_db()
    student_id = session["parent_student_id"]
    me = db.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if not me:
        session.pop("parent_student_id", None)
        return redirect(url_for("parent_login"))

    # ساعات المذاكرة: كل نبضة = دقيقة، + وقت الفيديو الحقيقي. (نفس منطق
    # صفحة الحساب بتاعة الطالب).
    now = datetime.utcnow().isoformat()
    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    total_seconds = db.execute(
        """SELECT
             (SELECT COUNT(id) FROM study_heartbeats WHERE student_id = ?) * 60 +
             (SELECT COALESCE(SUM(seconds), 0) FROM video_watch WHERE student_id = ?) AS total""",
        (student_id, student_id),
    ).fetchone()["total"] or 0
    week_seconds = db.execute(
        """SELECT
             (SELECT COUNT(id) FROM study_heartbeats WHERE student_id = ? AND created_at >= ?) * 60 +
             (SELECT COALESCE(SUM(seconds), 0) FROM video_watch WHERE student_id = ? AND updated_at >= ?) AS total""",
        (student_id, week_ago, student_id, week_ago),
    ).fetchone()["total"] or 0

    last_studied_at = db.execute(
        """SELECT MAX(ts) ts FROM (
             SELECT viewed_at ts FROM lesson_views WHERE student_id = ?
             UNION ALL
             SELECT updated_at ts FROM video_watch WHERE student_id = ?
             UNION ALL
             SELECT created_at ts FROM study_heartbeats WHERE student_id = ?
           )""",
        (student_id, student_id, student_id),
    ).fetchone()["ts"]

    purchases = db.execute(
        """SELECT p.material_id, p.purchased_at, p.amount, p.source_type, m.title material_title,
                  t.name teacher_name, m.kind
           FROM purchases p
           JOIN materials m ON m.id = p.material_id
           JOIN teachers t ON t.id = m.teacher_id
           WHERE p.student_id = ? ORDER BY p.purchased_at DESC""",
        (student_id,),
    ).fetchall()
    total_spent = sum((p["amount"] or 0) for p in purchases)
    subscribed_teachers = db.execute(
        "SELECT COUNT(DISTINCT m.teacher_id) c FROM purchases p "
        "JOIN materials m ON m.id = p.material_id WHERE p.student_id = ?",
        (student_id,),
    ).fetchone()["c"]

    # الحصص المخلصة: نفس منطق إتمام الحصة عند الطالب (وقت فيديو فعلي).
    completed = 0
    for p in purchases:
        if lesson_completed(db, p["material_id"], student_id):
            completed += 1

    study_by_teacher = db.execute(
        """SELECT t.name teacher_name,
             COALESCE(hb.minutes, 0) + COALESCE(vw.minutes, 0) minutes
           FROM teachers t
           LEFT JOIN (
             SELECT teacher_id, COUNT(id) minutes FROM study_heartbeats
             WHERE student_id = ? GROUP BY teacher_id
           ) hb ON hb.teacher_id = t.id
           LEFT JOIN (
             SELECT m.teacher_id, SUM(v.seconds) / 60.0 minutes FROM video_watch v
             JOIN materials m ON m.id = v.material_id
             WHERE v.student_id = ? GROUP BY m.teacher_id
           ) vw ON vw.teacher_id = t.id
           WHERE COALESCE(hb.minutes, 0) + COALESCE(vw.minutes, 0) > 0
           ORDER BY minutes DESC""",
        (student_id, student_id),
    ).fetchall()

    # النتائج: سيناريوهات اختيار من متعدد + تصحيح المدرس للواجب/الامتحان.
    assessment_results = db.execute(
        """SELECT a.title, m.title material_title, att.score, att.correct_count,
                  att.total_count, att.submitted_at
           FROM assessment_attempts att
           JOIN assessments a ON a.id = att.assessment_id
           JOIN materials m ON m.id = a.material_id
           WHERE att.student_id = ? ORDER BY att.submitted_at DESC""",
        (student_id,),
    ).fetchall()
    graded_homework = db.execute(
        """SELECT s.grade, s.feedback, s.submitted_at, m.title material_title,
                  t.name teacher_name
           FROM submissions s
           JOIN materials m ON m.id = s.material_id
           JOIN teachers t ON t.id = m.teacher_id
           WHERE s.student_id = ? AND s.graded_at IS NOT NULL
           ORDER BY s.graded_at DESC""",
        (student_id,),
    ).fetchall()
    graded_exams = db.execute(
        """SELECT s.grade, s.feedback, s.submitted_at, m.title material_title,
                  t.name teacher_name
           FROM exam_submissions s
           JOIN materials m ON m.id = s.material_id
           JOIN teachers t ON t.id = m.teacher_id
           WHERE s.student_id = ? AND s.graded_at IS NOT NULL
           ORDER BY s.graded_at DESC""",
        (student_id,),
    ).fetchall()

    report_flash = session.pop("parent_report_flash", None)
    return render_template(
        "parent_dashboard.html", me=me,
        total_hours=total_seconds / 3600.0, week_hours=week_seconds / 3600.0,
        last_studied_at=last_studied_at, last_study_label=_since_label(last_studied_at),
        purchases=purchases, total_spent=total_spent,
        subscribed_teachers=subscribed_teachers, completed=completed,
        study_by_teacher=study_by_teacher,
        assessment_results=assessment_results,
        graded_homework=graded_homework, graded_exams=graded_exams,
        report_flash=report_flash,
    )


def _support_phone(db) -> str:
    """رقم دعم المنصة اللي بيظهر في التقرير — بيتحط من الإعدادات أو من رقم
    الواتساب بتاع إعادة الشحن لو متحطش رقم مخصوص."""
    for key in ("support_phone", "recharge_whatsapp"):
        val = get_setting(db, key, "").strip()
        if val:
            return val
    return "01xxxxxxxxx"


def _build_parent_report(db, me) -> str:
    """نص تقرير ولي الأمر الأسبوعي مع لوجو المنصة ورقم الدعم."""
    student_id = me["id"]
    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    week_seconds = db.execute(
        """SELECT
             (SELECT COUNT(id) FROM study_heartbeats WHERE student_id = ? AND created_at >= ?) * 60 +
             (SELECT COALESCE(SUM(seconds), 0) FROM video_watch WHERE student_id = ? AND updated_at >= ?) AS total""",
        (student_id, week_ago, student_id, week_ago),
    ).fetchone()["total"] or 0
    purchased = db.execute(
        "SELECT COUNT(*) c FROM purchases WHERE student_id = ?", (student_id,)
    ).fetchone()["c"]
    done = 0
    for p in db.execute("SELECT material_id FROM purchases WHERE student_id = ?", (student_id,)).fetchall():
        if lesson_completed(db, p["material_id"], student_id):
            done += 1

    hours = int(round(week_seconds / 3600.0, 1))
    support = _support_phone(db)
    return (
        f"🎓 SENIORS | منصة الثانوية العامة\n"
        f"━━━━━━━━━━━━━━━\n"
        f"📋 تقرير {me['name']} الأسبوعي:\n"
        f"🕐 مذاكرة هذا الأسبوع: {hours} ساعة\n"
        f"📚 حصص مشترك فيها: {purchased}\n"
        f"✅ حصص مخلصة: {done}\n"
        f"━━━━━━━━━━━━━━━\n"
        f"لأي استفسار تواصل مع الدعم:\n"
        f"📞 {support}\n"
        f"🎓 SENIORS"
    )


@app.route("/parent/dashboard/report", methods=["POST"])
def parent_send_report():
    """بيطلب تقرير الأسبوع: التقرير بيوصل الإدارة كإشعار (بادج)، والإدارة
    هي اللي بتبعته على الواتساب لرقم ولي الأمر. ولي الأمر بيشوف بادج على
    لوجو المنصة إن الطلب اتسلم، ومعاه رقم الدعم."""
    if "parent_student_id" not in session:
        return redirect(url_for("parent_login"))
    db = get_db()
    student_id = session["parent_student_id"]
    me = db.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if not me:
        return redirect(url_for("parent_login"))

    report_text = _build_parent_report(db, me)
    db.execute(
        """INSERT INTO admin_notifications
           (kind, student_id, student_name, report_text, phone, is_read, status, created_at)
           VALUES ('parent_report', ?, ?, ?, ?, 0, 'pending', ?)""",
        (student_id, me["name"], report_text, me["parent_phone"] or "", datetime.utcnow().isoformat()),
    )
    db.commit()
    # بادج على لوجو المنصة لولي الأمر إن التقرير اتسلم للإدارة.
    session["parent_report_requested"] = True
    session["parent_report_flash"] = (True, "تم استلام طلب التقرير")
    return redirect(url_for("parent_dashboard"))


@app.route("/admin/student-report/<int:student_id>/pdf")
def admin_student_report_pdf(student_id):
    """ورقة تقرير رسمية (A4) قابلة للطباعة/الحفظ PDF — للأدمن فقط.
    بتُطبع لأي طالب في المنصة (تقرير المتابعة الشامل بتاع ولي الأمر)."""
    if session.get("admin_id") is None:
        return redirect(url_for("admin_login"))
    db = get_db()
    me = db.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if not me:
        flash("الطالب مش موجود.", "error")
        return redirect(url_for("admin_dashboard", tab="reports"))

    now = datetime.utcnow().isoformat()
    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    total_seconds = db.execute(
        """SELECT
             (SELECT COUNT(id) FROM study_heartbeats WHERE student_id = ?) * 60 +
             (SELECT COALESCE(SUM(seconds), 0) FROM video_watch WHERE student_id = ?) AS total""",
        (student_id, student_id),
    ).fetchone()["total"] or 0
    week_seconds = db.execute(
        """SELECT
             (SELECT COUNT(id) FROM study_heartbeats WHERE student_id = ? AND created_at >= ?) * 60 +
             (SELECT COALESCE(SUM(seconds), 0) FROM video_watch WHERE student_id = ? AND updated_at >= ?) AS total""",
        (student_id, week_ago, student_id, week_ago),
    ).fetchone()["total"] or 0

    last_studied_at = db.execute(
        """SELECT MAX(ts) ts FROM (
             SELECT viewed_at ts FROM lesson_views WHERE student_id = ?
             UNION ALL
             SELECT updated_at ts FROM video_watch WHERE student_id = ?
             UNION ALL
             SELECT created_at ts FROM study_heartbeats WHERE student_id = ?
           )""",
        (student_id, student_id, student_id),
    ).fetchone()["ts"]

    purchases = db.execute(
        """SELECT p.material_id, p.purchased_at, p.amount, p.source_type, m.title material_title,
                  t.name teacher_name, m.kind
           FROM purchases p
           JOIN materials m ON m.id = p.material_id
           JOIN teachers t ON t.id = m.teacher_id
           WHERE p.student_id = ? ORDER BY p.purchased_at DESC""",
        (student_id,),
    ).fetchall()
    total_spent = sum((p["amount"] or 0) for p in purchases)
    subscribed_teachers = db.execute(
        "SELECT COUNT(DISTINCT m.teacher_id) c FROM purchases p "
        "JOIN materials m ON m.id = p.material_id WHERE p.student_id = ?",
        (student_id,),
    ).fetchone()["c"]

    completed = 0
    for p in purchases:
        if lesson_completed(db, p["material_id"], student_id):
            completed += 1

    study_by_teacher = db.execute(
        """SELECT t.name teacher_name,
             COALESCE(hb.minutes, 0) + COALESCE(vw.minutes, 0) minutes
           FROM teachers t
           LEFT JOIN (
             SELECT teacher_id, COUNT(id) minutes FROM study_heartbeats
             WHERE student_id = ? GROUP BY teacher_id
           ) hb ON hb.teacher_id = t.id
           LEFT JOIN (
             SELECT m.teacher_id, SUM(v.seconds) / 60.0 minutes FROM video_watch v
             JOIN materials m ON m.id = v.material_id
             WHERE v.student_id = ? GROUP BY m.teacher_id
           ) vw ON vw.teacher_id = t.id
           WHERE COALESCE(hb.minutes, 0) + COALESCE(vw.minutes, 0) > 0
           ORDER BY minutes DESC""",
        (student_id, student_id),
    ).fetchall()

    assessment_results = db.execute(
        """SELECT a.title, m.title material_title, att.score, att.correct_count,
                  att.total_count, att.submitted_at
           FROM assessment_attempts att
           JOIN assessments a ON a.id = att.assessment_id
           JOIN materials m ON m.id = a.material_id
           WHERE att.student_id = ? ORDER BY att.submitted_at DESC""",
        (student_id,),
    ).fetchall()
    graded_homework = db.execute(
        """SELECT s.grade, s.feedback, s.submitted_at, m.title material_title,
                  t.name teacher_name
           FROM submissions s
           JOIN materials m ON m.id = s.material_id
           JOIN teachers t ON t.id = m.teacher_id
           WHERE s.student_id = ? AND s.graded_at IS NOT NULL
           ORDER BY s.graded_at DESC""",
        (student_id,),
    ).fetchall()
    graded_exams = db.execute(
        """SELECT s.grade, s.feedback, s.submitted_at, m.title material_title,
                  t.name teacher_name
           FROM exam_submissions s
           JOIN materials m ON m.id = s.material_id
           JOIN teachers t ON t.id = m.teacher_id
           WHERE s.student_id = ? AND s.graded_at IS NOT NULL
           ORDER BY s.graded_at DESC""",
        (student_id,),
    ).fetchall()

    return render_template(
        "parent_report_print.html", me=me,
        total_hours=total_seconds / 3600.0, week_hours=week_seconds / 3600.0,
        last_studied_at=last_studied_at,
        purchases=purchases, total_spent=total_spent,
        subscribed_teachers=subscribed_teachers, completed=completed,
        study_by_teacher=study_by_teacher,
        assessment_results=assessment_results,
        graded_homework=graded_homework, graded_exams=graded_exams,
        support_phone=_support_phone(db),
        today=datetime.utcnow().strftime("%Y-%m-%d"),
    )


# ---------------------------------------------------------------------------
# Routes - teacher side
# ---------------------------------------------------------------------------

@app.route("/teacher", methods=["GET", "POST"])
def teacher_pick():
    # الواجهة القديمة — كل حاجة بقت على صفحة الدخول الموحدة /login.
    return redirect(url_for("login"))


@app.route("/teacher/logout", methods=["POST"])
def teacher_logout():
    session.pop("teacher_id", None)
    session.pop("teacher_name", None)
    return redirect(url_for("teacher_pick"))


@app.route("/teacher/<int:teacher_id>/photo", methods=["POST"])
def teacher_update_photo(teacher_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    photo = save_uploaded_photo(request.files.get("photo"))
    if photo:
        db = get_db()
        db.execute("UPDATE teachers SET photo = ? WHERE id = ?", (photo, teacher_id))
        db.commit()
    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))


@app.route("/teacher/<int:teacher_id>", methods=["GET"])
def teacher_dashboard(teacher_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    if not teacher or teacher["is_blocked"]:
        session.pop("teacher_id", None)
        session.pop("teacher_name", None)
        return redirect(url_for("teacher_pick"))
    if session.get("must_change_password") or teacher["must_change_password"]:
        session["must_change_password"] = True
        return redirect(url_for("teacher_force_change_password"))
    materials = db.execute(
        "SELECT m.*, c.name curriculum_name, s.name stage_name, "
        "  (SELECT AVG(rating) FROM reviews r WHERE r.material_id = m.id) avg_rating, "
        "  (SELECT COUNT(*) FROM reviews r WHERE r.material_id = m.id) review_count, "
        "  (SELECT COUNT(*) FROM purchases p WHERE p.material_id = m.id) purchase_count, "
        "  (SELECT COUNT(*) FROM lesson_videos lv WHERE lv.material_id = m.id) video_count, "
        "  (SELECT COUNT(*) FROM chapters ch WHERE ch.material_id = m.id) chapter_count, "
        "  (SELECT COUNT(*) FROM assessments a WHERE a.material_id = m.id) assessment_count "
        "FROM materials m "
        "LEFT JOIN curricula c ON c.id = m.curriculum_id "
        "LEFT JOIN stages s ON s.id = m.stage_id "
        "WHERE m.teacher_id = ? ORDER BY m.id DESC",
        (teacher_id,),
    ).fetchall()
    chapters = db.execute(
        "SELECT c.* FROM chapters c JOIN materials m ON m.id = c.material_id "
        "WHERE m.teacher_id = ? ORDER BY c.material_id, c.sort_order, c.id",
        (teacher_id,),
    ).fetchall()
    docs = db.execute(
        "SELECT * FROM generated_docs WHERE teacher_id = ? ORDER BY id DESC", (teacher_id,)
    ).fetchall()
    chat_count = db.execute(
        "SELECT COUNT(DISTINCT student_id) c FROM chat_messages WHERE teacher_id = ? AND student_id IS NOT NULL", (teacher_id,)
    ).fetchone()["c"]
    recent_reviews = db.execute(
        "SELECT r.*, m.title material_title FROM reviews r "
        "JOIN materials m ON m.id = r.material_id "
        "WHERE m.teacher_id = ? ORDER BY r.id DESC LIMIT 10",
        (teacher_id,),
    ).fetchall()
    offerings = db.execute(
        "SELECT o.*, c.name curriculum_name, s.name stage_name FROM teacher_offerings o "
        "JOIN curricula c ON c.id = o.curriculum_id JOIN stages s ON s.id = o.stage_id "
        "WHERE o.teacher_id = ? ORDER BY s.sort_order",
        (teacher_id,),
    ).fetchall()
    stages = db.execute("SELECT * FROM stages ORDER BY sort_order").fetchall()
    curricula = db.execute("SELECT * FROM curricula ORDER BY name").fetchall()

    stats = db.execute(
        "SELECT "
        "  COUNT(DISTINCT m.id) lesson_count, "
        "  (SELECT COUNT(*) FROM purchases p JOIN materials m2 ON m2.id = p.material_id WHERE m2.teacher_id = ?) purchase_count, "
        "  (SELECT COALESCE(SUM(m3.price), 0) FROM purchases p JOIN materials m3 ON m3.id = p.material_id WHERE m3.teacher_id = ?) total_revenue, "
        "  (SELECT AVG(r.rating) FROM reviews r JOIN materials m4 ON m4.id = r.material_id WHERE m4.teacher_id = ?) avg_rating "
        "FROM materials m WHERE m.teacher_id = ?",
        (teacher_id, teacher_id, teacher_id, teacher_id),
    ).fetchone()

    homework_submissions = db.execute(
        "SELECT s.*, m.title material_title FROM submissions s "
        "JOIN materials m ON m.id = s.material_id "
        "WHERE m.teacher_id = ? ORDER BY (s.graded_at IS NOT NULL), s.submitted_at DESC",
        (teacher_id,),
    ).fetchall()

    exam_submissions = db.execute(
        "SELECT s.*, m.title material_title FROM exam_submissions s "
        "JOIN materials m ON m.id = s.material_id "
        "WHERE m.teacher_id = ? ORDER BY (s.graded_at IS NOT NULL), s.submitted_at DESC",
        (teacher_id,),
    ).fetchall()

    lesson_view_counts = db.execute(
        "SELECT m.title, COUNT(v.id) view_count FROM materials m "
        "LEFT JOIN lesson_views v ON v.material_id = m.id "
        "WHERE m.teacher_id = ? GROUP BY m.id ORDER BY view_count DESC",
        (teacher_id,),
    ).fetchall()

    # أرباح المدرس: إجمالي المبيعات اللي حصلت على دروسه، حصة المنصة (العمولة %)،
    # وحصة المدرس. ومستحقاته = حصته - اللي اتصرف له لحد دلوقتي.
    earnings = db.execute(
        """SELECT COALESCE(SUM(p.amount), 0) gross FROM purchases p
           JOIN materials m ON m.id = p.material_id WHERE m.teacher_id = ?""",
        (teacher_id,),
    ).fetchone()["gross"]
    platform_cut = round(earnings * (teacher["commission_percent"] or 0) / 100.0, 2)
    teacher_share = round(earnings - platform_cut, 2)
    paid_total = db.execute(
        "SELECT COALESCE(SUM(amount), 0) r FROM payouts WHERE teacher_id = ?", (teacher_id,)
    ).fetchone()["r"]
    pending_earnings = round(teacher_share - paid_total, 2)
    payout_history = db.execute(
        "SELECT * FROM payouts WHERE teacher_id = ? ORDER BY id DESC", (teacher_id,)
    ).fetchall()

    ai_expires_at = teacher_ai_expiry(teacher)
    ai_is_active = teacher_ai_active(db, teacher)
    ai_days_left = teacher_ai_days_left(db, teacher)
    ai_cfg = ai_subscription_config(db)
    ai_payment_history = db.execute(
        "SELECT * FROM teacher_ai_payments WHERE teacher_id = ? ORDER BY id DESC", (teacher_id,)
    ).fetchall()

    # طلاب المدرس: اللي تواصلوا معاه أو اشتروا منه أو سلّموا واجب/امتحان أو فتحوا
    # حصة — جوا وبعضهم عشان تظهر ليه لائحة يوقف منها الطالب.
    my_students = db.execute(
        """SELECT s.id, s.name, s.account_code, s.student_phone,
                  (SELECT reason FROM teacher_student_blocks b
                   WHERE b.teacher_id = ? AND b.student_id = s.id) block_reason
           FROM students s
           WHERE s.id IN (
               SELECT DISTINCT cm.student_id FROM chat_messages cm WHERE cm.teacher_id = ?
               UNION
               SELECT DISTINCT p.student_id FROM purchases p
                 JOIN materials m ON m.id = p.material_id AND m.teacher_id = ?
               UNION
               SELECT DISTINCT su.student_id FROM submissions su
                 JOIN materials m2 ON m2.id = su.material_id AND m2.teacher_id = ?
               UNION
               SELECT DISTINCT es.student_id FROM exam_submissions es
                 JOIN materials m3 ON m3.id = es.material_id AND m3.teacher_id = ?
               UNION
               SELECT DISTINCT lv.student_id FROM lesson_views lv
                 JOIN materials m4 ON m4.id = lv.material_id AND m4.teacher_id = ?
           )
           ORDER BY s.name""",
        (teacher_id, teacher_id, teacher_id, teacher_id, teacher_id, teacher_id),
    ).fetchall()
    blocked_count = db.execute(
        "SELECT COUNT(*) c FROM teacher_student_blocks WHERE teacher_id = ?", (teacher_id,)
    ).fetchone()["c"]

    notifications = db.execute(
        "SELECT * FROM notifications WHERE teacher_id = ? ORDER BY id DESC LIMIT 30",
        (teacher_id,),
    ).fetchall()
    unread_notifications = db.execute(
        "SELECT COUNT(*) c FROM notifications WHERE teacher_id = ? AND is_read = 0",
        (teacher_id,),
    ).fetchone()["c"]

    return render_template(
        "teacher_dashboard.html", teacher=teacher, materials=materials, stats=stats,
        lesson_view_counts=lesson_view_counts,
        docs=docs, chat_count=chat_count, recent_reviews=recent_reviews,
        offerings=offerings, stages=stages, curricula=curricula,
        homework_submissions=homework_submissions, exam_submissions=exam_submissions,
        chapters=chapters,
        earnings=earnings, platform_cut=platform_cut, teacher_share=teacher_share,
        paid_total=paid_total, pending_earnings=pending_earnings, payout_history=payout_history,
        ai_expires_at=ai_expires_at, ai_is_active=ai_is_active, ai_days_left=ai_days_left,
        ai_cfg=ai_cfg, ai_payment_history=ai_payment_history,
        my_students=my_students, blocked_count=blocked_count,
        notifications=notifications, unread_notifications=unread_notifications,
    )


@app.route("/teacher/<int:teacher_id>/notifications/read", methods=["POST"])
def teacher_notifications_read(teacher_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    db = get_db()
    db.execute(
        "UPDATE notifications SET is_read = 1 WHERE teacher_id = ? AND is_read = 0",
        (teacher_id,),
    )
    db.commit()
    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))


@app.route("/teacher/force-change-password", methods=["GET"])
def teacher_force_change_password():
    """أول دخول بباسورد افتراضي/مؤقت: المدرس لازم يغيّر الباسورد قبل ما يستخدم
    أي حاجة. مفيش طريقة يتخطى الصفحة دي غير بتغيير الباسورد فعلًا."""
    if not session.get("teacher_id"):
        return redirect(url_for("teacher_pick"))
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (session["teacher_id"],)).fetchone()
    if not teacher or teacher["is_blocked"]:
        return redirect(url_for("teacher_pick"))
    if not (session.get("must_change_password") or teacher["must_change_password"]):
        return redirect(url_for("teacher_dashboard", teacher_id=teacher["id"]))
    return render_template("teacher_force_change_password.html", teacher=teacher)


@app.route("/teacher/force-change-password", methods=["POST"])
def teacher_force_change_password_submit():
    if not session.get("teacher_id"):
        return redirect(url_for("teacher_pick"))
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (session["teacher_id"],)).fetchone()
    if not teacher or teacher["is_blocked"]:
        return redirect(url_for("teacher_pick"))
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    error = None
    if len(new_password) < 8 or not any(c.isdigit() for c in new_password) or not any(c.isalpha() for c in new_password):
        error = "new_password_too_weak"
    elif new_password != confirm_password:
        error = "password_mismatch"
    else:
        db.execute(
            "UPDATE teachers SET password_hash = ?, must_change_password = 0 WHERE id = ?",
            (generate_password_hash(new_password), teacher["id"]),
        )
        db.commit()
        log_security_event("teacher_password_changed", f"teacher_id={teacher['id']} name={teacher['name']}")
        session.pop("must_change_password", None)
        return redirect(url_for("teacher_dashboard", teacher_id=teacher["id"]))
    return render_template(
        "teacher_force_change_password.html", teacher=teacher, error=error,
    )


@app.route("/teacher/<int:teacher_id>/students/block", methods=["POST"])
def teacher_block_student(teacher_id):
    """المدرس بيوقف طالب من حصصه ومحتواه وشراء الدروس — الطالب مبيتفتحش
    غير لما الإدارة/الدعم الفني يشيل البلوك. المدرس نفسه ميقدرش يشيله."""
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    if not teacher or teacher["is_blocked"]:
        return redirect(url_for("teacher_pick"))
    student_id = request.form.get("student_id", type=int)
    student_code = request.form.get("student_code", "").strip().upper()
    reason = request.form.get("reason", "").strip()[:200]
    if not student_id and student_code:
        row = db.execute(
            "SELECT id FROM students WHERE account_code = ?", (student_code,)
        ).fetchone()
        if row:
            student_id = row["id"]
    if not student_id:
        flash("اختار طالب من اللائحة أو اكتب كود صحيح.", "danger")
        return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))
    student = db.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if not student:
        flash("الطالب ده مش موجود.", "danger")
        return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))
    db.execute(
        """INSERT INTO teacher_student_blocks (teacher_id, student_id, reason, created_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(teacher_id, student_id) DO UPDATE SET reason = excluded.reason""",
        (teacher_id, student_id, reason, datetime.utcnow().isoformat()),
    )
    db.commit()
    flash(f"تم إيقاف الطالب {student['name']} — ليك إزالة الإيقاف غير عن طريق الدعم الفني.", "success")
    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))


@app.route("/teacher/<int:teacher_id>/offerings", methods=["POST"])
def teacher_add_offering(teacher_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    curriculum_id = request.form.get("curriculum_id", type=int)
    stage_id = request.form.get("stage_id", type=int)
    subject = request.form.get("subject", "").strip()
    if curriculum_id and stage_id and subject:
        db = get_db()
        db.execute(
            "INSERT OR IGNORE INTO teacher_offerings (teacher_id, curriculum_id, stage_id, subject) VALUES (?, ?, ?, ?)",
            (teacher_id, curriculum_id, stage_id, subject),
        )
        db.commit()
    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))


@app.route("/teacher/<int:teacher_id>/materials", methods=["POST"])
def teacher_add_material(teacher_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    kind = request.form.get("kind", "نص").strip()
    video_url = request.form.get("video_url", "").strip()
    offering_id = request.form.get("offering_id", type=int)
    stream = request.form.get("stream", "").strip()
    if stream not in SECONDARY_STREAMS and stream not in BAC_STREAMS:
        stream = ""  # عام - يظهر للجميع
    try:
        price = max(0.0, float(request.form.get("price", 0) or 0))
    except ValueError:
        price = 0.0

    if kind not in {"نص", "فيديو", "امتحان", "واجب"}:
        kind = "نص"

    # مدة إتاحة المشاهدة بالأيام (اختياري) - المدرس بيحددها من 3 لـ 14 يوم.
    # لو مبعوتة برة النطاق ده أو فاضية، بتتسجل "من غير حد" (وصول دائم).
    access_days_raw = request.form.get("access_days", "").strip()
    access_days = None
    if access_days_raw:
        try:
            access_days = int(access_days_raw)
            if not (3 <= access_days <= 14):
                access_days = None
        except ValueError:
            access_days = None

    # فيديو واحد قديم (خلفية للدروس القديمة) + فيديوهات متعددة جديدة:
    # كل فيديو من الفورم ممكن يبقى ملف مرفوع أو رابط خارجي، مع عنوان خاص بيه.
    single_video_filename = save_uploaded_video(request.files.get("video_file")) if kind == "فيديو" else None

    # الشبترات: كل شبتر اسم بيختاره المدرس، وفيه الفيديوهات اللي عايزها.
    # أقصى عدد شبترات في الدرس الواحد = MAX_CHAPTERS_PER_LESSON.
    chapter_titles = request.form.getlist("chapter_titles")
    video_chapters = request.form.getlist("video_chapter")

    # الفيديوهات المتعددة: كل صف (عنوان + ملف + رابط اختياري + رقم شبتر + وصف).
    video_titles = request.form.getlist("video_titles")
    video_urls = request.form.getlist("video_urls")
    video_files = request.files.getlist("video_files")
    video_descriptions = request.form.getlist("video_descriptions")

    if title and content and offering_id:
        db = get_db()
        offering = db.execute(
            "SELECT * FROM teacher_offerings WHERE id = ? AND teacher_id = ?",
            (offering_id, teacher_id),
        ).fetchone()
        if offering:
            cur = db.execute(
                "INSERT INTO materials (teacher_id, curriculum_id, stage_id, subject, title, content, "
                " kind, video_url, video_filename, access_days, price, stream, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (teacher_id, offering["curriculum_id"], offering["stage_id"], offering["subject"],
                 title, content, kind, video_url, single_video_filename, access_days, price, stream,
                 datetime.utcnow().isoformat()),
            )
            material_id = cur.lastrowid

            # نجمع الفيديوهات: كل واحد (عنوان, رابط, ملف, رقم شبتر, وصف).
            rows = []
            if single_video_filename or video_url:
                rows.append((title, video_url or "", single_video_filename or "", 0, ""))
            for i in range(max(len(video_titles), len(video_urls), len(video_files))):
                v_title = video_titles[i].strip() if i < len(video_titles) else ""
                v_url = video_urls[i].strip() if i < len(video_urls) else ""
                v_desc = video_descriptions[i].strip() if i < len(video_descriptions) else ""
                f = video_files[i] if i < len(video_files) else None
                if not (f and f.filename) and not v_url:
                    continue  # صف فاضي - نتجاهله
                if f and f.filename:
                    v_file = save_uploaded_video(f)
                else:
                    v_file = ""
                c_idx = 0
                if i < len(video_chapters):
                    try:
                        c_idx = int(video_chapters[i])
                    except (TypeError, ValueError):
                        c_idx = 0
                if v_url or v_file:
                    rows.append((v_title or f"فيديو {i + 1}", v_url, v_file or "", c_idx, v_desc))

            if not rows:
                rows.append((title, video_url or "", single_video_filename or "", 0, ""))

            # الشبترات بتتسجل بس لو فيه فيديوهات فعلية، وحد أقصى 10 شبترات.
            chapter_ids = []
            if rows and chapter_titles:
                for ci in range(min(len(chapter_titles), MAX_CHAPTERS_PER_LESSON)):
                    c_title = chapter_titles[ci].strip() or f"شابتر {ci + 1}"
                    c_cur = db.execute(
                        "INSERT INTO chapters (material_id, title, sort_order, created_at) "
                        "VALUES (?, ?, ?, ?)",
                        (material_id, c_title, ci, datetime.utcnow().isoformat()),
                    )
                    chapter_ids.append(c_cur.lastrowid)

            for order, (v_title, v_url, v_file, c_idx, v_desc) in enumerate(rows):
                chapter_id = None
                if chapter_ids:
                    chapter_id = chapter_ids[max(0, min(c_idx, len(chapter_ids) - 1))]
                db.execute(
                    "INSERT INTO lesson_videos (material_id, title, video_url, video_filename, chapter_id, sort_order, description, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (material_id, v_title, v_url, v_file, chapter_id, order, v_desc, datetime.utcnow().isoformat()),
                )

            # امتحان و/أو واجب إلكتروني (اختيار من متعدد) بيتحطوا مع الحصة:
            # المدرس بيحدد الأسئلة + الإجابات الصحيحة، والتصحيح بيعمل فوري.
            # كل واحد سيناريو مستقل — بيظهر للطالب في شاشة لوحده.
            exam_rows = parse_question_rows("exam")
            if exam_rows:
                insert_assessment_rows(
                    db, material_id, "امتحان",
                    request.form.get("exam_title", "").strip() or f"امتحان - {title}",
                    exam_rows,
                )
            hw_rows = parse_question_rows("hw")
            if hw_rows:
                insert_assessment_rows(
                    db, material_id, "واجب",
                    request.form.get("hw_title", "").strip() or f"واجب - {title}",
                    hw_rows,
                )
            db.commit()
    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))


@app.route("/teacher/<int:teacher_id>/lessons/<int:material_id>/videos", methods=["POST"])
def teacher_add_lesson_videos(teacher_id, material_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    db = get_db()
    material = db.execute(
        "SELECT * FROM materials WHERE id = ? AND teacher_id = ?", (material_id, teacher_id)
    ).fetchone()
    if not material:
        return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))

    video_titles = request.form.getlist("video_titles")
    video_urls = request.form.getlist("video_urls")
    video_files = request.files.getlist("video_files")
    video_descriptions = request.form.getlist("video_descriptions")
    video_chapter_ids = request.form.getlist("video_chapter_ids")
    new_chapter_titles = request.form.getlist("new_chapter_titles")

    existing = db.execute(
        "SELECT id FROM chapters WHERE material_id = ? ORDER BY sort_order, id", (material_id,)
    ).fetchall()
    existing_ids = [c["id"] for c in existing]
    chapters_count = len(existing_ids)

    next_order = db.execute(
        "SELECT COALESCE(MAX(sort_order), -1) + 1 o FROM lesson_videos WHERE material_id = ?", (material_id,)
    ).fetchone()["o"]

    added = 0
    for i in range(max(len(video_titles), len(video_urls), len(video_files))):
        v_title = video_titles[i].strip() if i < len(video_titles) else ""
        v_url = video_urls[i].strip() if i < len(video_urls) else ""
        v_desc = video_descriptions[i].strip() if i < len(video_descriptions) else ""
        f = video_files[i] if i < len(video_files) else None
        v_file = save_uploaded_video(f) if f and f.filename else ""
        if not v_url and not v_file:
            continue

        cid_raw = video_chapter_ids[i].strip() if i < len(video_chapter_ids) else "0"
        try:
            cid = int(cid_raw)
        except (TypeError, ValueError):
            cid = 0

        # لو الشبتر المختار مش موجود (رقم جديد)، ننشئ شبتر جديد باسم المدرس.
        if cid not in existing_ids:
            if chapters_count >= MAX_CHAPTERS_PER_LESSON:
                if existing_ids:
                    cid = existing_ids[-1]
                else:
                    flash("وصلت لأقصى عدد شبترات (10) في الدرس - حط الفيديو في شبتر موجود", "danger")
                    continue
            else:
                c_title = (new_chapter_titles[i].strip() if i < len(new_chapter_titles) else "") \
                    or f"شابتر {chapters_count + 1}"
                c_cur = db.execute(
                    "INSERT INTO chapters (material_id, title, sort_order, created_at) VALUES (?, ?, ?, ?)",
                    (material_id, c_title, chapters_count, datetime.utcnow().isoformat()),
                )
                cid = c_cur.lastrowid
                existing_ids.append(cid)
                chapters_count += 1

        db.execute(
            "INSERT INTO lesson_videos (material_id, title, video_url, video_filename, chapter_id, sort_order, description, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (material_id, v_title or f"فيديو {next_order + added + 1}", v_url, v_file, cid, next_order + added,
             v_desc, datetime.utcnow().isoformat()),
        )
        added += 1
    db.commit()
    flash(f"تمت إضافة {added} فيديو للدرس.", "success" if added else "danger")
    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))


@app.route("/teacher/<int:teacher_id>/assessments/<int:material_id>", methods=["GET"])
def teacher_assessments(teacher_id, material_id):
    """شاشة لوحده للمدرس: بيعرض ويضيف امتحانات/واجبات الدرس بأسئلتها."""
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    material = db.execute(
        "SELECT * FROM materials WHERE id = ? AND teacher_id = ?", (material_id, teacher_id)
    ).fetchone()
    if not material:
        return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))
    assessments = db.execute(
        """SELECT a.*,
                  (SELECT COUNT(*) FROM assessment_questions q WHERE q.assessment_id = a.id) question_count,
                  (SELECT COUNT(*) FROM assessment_attempts at WHERE at.assessment_id = a.id) attempt_count,
                  (SELECT AVG(at.score) FROM assessment_attempts at WHERE at.assessment_id = a.id) avg_score
           FROM assessments a WHERE a.material_id = ? ORDER BY a.id""",
        (material_id,),
    ).fetchall()
    questions = db.execute(
        "SELECT q.*, a.kind, a.title assessment_title FROM assessment_questions q "
        "JOIN assessments a ON a.id = q.assessment_id "
        "WHERE a.material_id = ? ORDER BY q.assessment_id, q.sort_order, q.id",
        (material_id,),
    ).fetchall()
    return render_template(
        "teacher_assessment.html", teacher=teacher, material=material,
        assessments=assessments, questions=questions,
    )


@app.route("/teacher/<int:teacher_id>/assessments/<int:material_id>/send-grades", methods=["POST"])
def teacher_send_grades(teacher_id, material_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    assessment_id = request.form.get("assessment_id", type=int)
    db = get_db()
    material = db.execute(
        "SELECT * FROM materials WHERE id = ? AND teacher_id = ?", (material_id, teacher_id)
    ).fetchone()
    if not material:
        return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))
    assessment = db.execute(
        "SELECT * FROM assessments WHERE id = ? AND material_id = ?", (assessment_id, material_id)
    ).fetchone()
    if not assessment:
        return redirect(url_for("teacher_assessments", teacher_id=teacher_id, material_id=material_id))

    attempts = db.execute(
        "SELECT * FROM assessment_attempts WHERE assessment_id = ? ORDER BY submitted_at",
        (assessment_id,),
    ).fetchall()
    if not attempts:
        flash(f"مفيش نتائج لـ {assessment['title']} — لسه مفيش طلاب حلّوا السيناريو ده.", "danger")
        return redirect(url_for("teacher_assessments", teacher_id=teacher_id, material_id=material_id))

    cfg = _whatsapp_config()
    ready = _whatsapp_ready(cfg)
    sent, no_phone = 0, 0
    for att in attempts:
        student = db.execute(
            "SELECT name, parent_phone, student_phone FROM students WHERE id = ?",
            (att["student_id"],),
        ).fetchone()
        phone = ""
        if student:
            phone = student["parent_phone"] or student["student_phone"] or ""
        if not phone:
            no_phone += 1
            print(f"[نتايج - مفيش رقم] {att['student_name']}")
            continue
        msg = (
            f"نتيجة {att['student_name']} في {assessment['title']} ({material['title']}): "
            f"{att['score']:.0f}% - صحيح {att['correct_count']} من {att['total_count']}"
        )
        if cfg.get("grade_template"):
            params = [
                att["student_name"],
                f"{material['title']} - {assessment['title']}",
                f"{att['score']:.0f}%",
                str(att["correct_count"]),
                str(att["total_count"]),
            ]
            ok, _ = whatsapp_send(phone, msg, template_name=cfg["grade_template"], template_params=params)
        else:
            ok, _ = whatsapp_send(phone, msg)
        if ok:
            sent += 1

    if not ready:
        flash(
            f"⚠️ الواتساب لسه مش مفعّل — كل الرسايل اتحوّلت لمحاكاة في اللوج. "
            f"نتيجة {assessment['title']}: {len(attempts)} طالب، {no_phone} بدون رقم.",
            "danger",
        )
    elif sent:
        flash(f"تم إرسال نتائج {assessment['title']}: {sent} رسالة نجحت، {no_phone} بدون رقم.", "success")
    else:
        flash(f"فشل إرسال نتائج {assessment['title']} — راجع اللوج. ({no_phone} بدون رقم)", "danger")
    return redirect(url_for("teacher_assessments", teacher_id=teacher_id, material_id=material_id))


@app.route("/teacher/<int:teacher_id>/assessments/<int:material_id>/add", methods=["POST"])
def teacher_add_assessment(teacher_id, material_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    db = get_db()
    material = db.execute(
        "SELECT * FROM materials WHERE id = ? AND teacher_id = ?", (material_id, teacher_id)
    ).fetchone()
    if not material:
        return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))
    kind = request.form.get("kind", "امتحان")
    if kind not in {"امتحان", "واجب"}:
        kind = "امتحان"
    title = request.form.get("title", "").strip() or f"{'امتحان' if kind == 'امتحان' else 'واجب'} - {material['title']}"
    rows = parse_question_rows("add")
    if rows:
        insert_assessment_rows(db, material_id, kind, title, rows)
        db.commit()
        flash(f"تمت إضافة {len(rows)} سؤال في «{title}».", "success")
    else:
        flash("ضيف سؤال واحد على الأقل قبل الحفظ.", "danger")
    return redirect(url_for("teacher_assessments", teacher_id=teacher_id, material_id=material_id))


@app.route("/teacher/<int:teacher_id>/assessments/<int:material_id>/questions", methods=["POST"])
def teacher_add_assessment_questions(teacher_id, material_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    db = get_db()
    material = db.execute(
        "SELECT * FROM materials WHERE id = ? AND teacher_id = ?", (material_id, teacher_id)
    ).fetchone()
    if not material:
        return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))
    try:
        assessment_id = int(request.form.get("assessment_id", 0) or 0)
    except (TypeError, ValueError):
        assessment_id = 0
    assessment = db.execute(
        "SELECT * FROM assessments WHERE id = ? AND material_id = ?", (assessment_id, material_id)
    ).fetchone()
    if not assessment:
        return redirect(url_for("teacher_assessments", teacher_id=teacher_id, material_id=material_id))
    rows = parse_question_rows("aq")
    if rows:
        next_order = db.execute(
            "SELECT COALESCE(MAX(sort_order), -1) + 1 o FROM assessment_questions WHERE assessment_id = ?",
            (assessment_id,),
        ).fetchone()["o"]
        for order, q in enumerate(rows):
            db.execute(
                "INSERT INTO assessment_questions "
                " (assessment_id, question_text, option_a, option_b, option_c, option_d, "
                "  correct_index, explain_video, explain_url, sort_order) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (assessment_id, q["text"], q["options"][0], q["options"][1], q["options"][2],
                 q["options"][3], q["correct"], q["vfile"], q["vurl"], next_order + order),
            )
        db.commit()
        flash(f"تمت إضافة {len(rows)} سؤال للامتحان/الواجب.", "success")
    else:
        flash("مفيش أسئلة صحيحة تُضاف.", "danger")
    return redirect(url_for("teacher_assessments", teacher_id=teacher_id, material_id=material_id))


@app.route("/teacher/<int:teacher_id>/generate", methods=["POST"])
def teacher_generate(teacher_id):
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    kind = request.form.get("kind")  # 'exam' or 'summary'
    material_id = request.form.get("material_id")
    extra = request.form.get("extra", "").strip()

    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    material = db.execute("SELECT * FROM materials WHERE id = ?", (material_id,)).fetchone()

    if not teacher_ai_active(db, teacher):
        cfg = ai_subscription_config(db)
        flash(
            f"🤖 مساعد الذكاء الاصطناعي محتاج اشتراك (بتبدأ من {int(cfg['price'])} ج لكل "
            f"{cfg['days']} يوم) — فعّله من تبويب مساعدي الذكي قبل ما تولّد.",
            "danger",
        )
        return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))

    if kind == "exam":
        system_prompt = (
            f"أنت مساعد تربوي يساعد المدرس {teacher['name']} في إعداد امتحانات لمادة {teacher['subject']} "
            f"لطلاب الثانوية العامة. جهّز امتحانًا قصيرًا (5 أسئلة متنوعة: اختيار من متعدد ومقالي) "
            f"مبني على الدرس التالي، مع نموذج الإجابة في النهاية."
        )
        title = f"امتحان - {material['title']}"
    else:
        system_prompt = (
            f"أنت مساعد تربوي يساعد المدرس {teacher['name']} في تلخيص الدروس لمادة {teacher['subject']}. "
            f"لخّص الدرس التالي في نقاط واضحة ومركزة تساعد الطالب على المذاكرة السريعة."
        )
        title = f"ملخص - {material['title']}"

    user_prompt = f"عنوان الدرس: {material['title']}\n\nمحتوى الدرس:\n{material['content']}"
    if extra:
        user_prompt += f"\n\nملاحظات إضافية من المدرس: {extra}"

    result = call_claude(system_prompt, user_prompt, max_tokens=1500)

    db.execute(
        "INSERT INTO generated_docs (teacher_id, kind, title, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (teacher_id, kind, title, result, datetime.utcnow().isoformat()),
    )
    db.commit()

    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id))


@app.route("/teacher/<int:teacher_id>/ai/subscribe", methods=["POST"])
def teacher_ai_subscribe(teacher_id):
    """المدرس بيفعّل اشتراك الذكاء الاصطناعي بإحدى طريقتين:
    - كود شحن من السنتر (الكود بيقفل وقيمته بتتحول لأيام اشتراك فورًا)
    - شحن يدوي: بيحوّل المبلغ ويرفع سكرين، والإدارة بتعتمده من لوحة التحكم"""
    if session.get("teacher_id") != teacher_id:
        return redirect(url_for("teacher_pick"))
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    if not teacher or teacher["is_blocked"]:
        return redirect(url_for("teacher_pick"))
    mode = request.form.get("mode", "").strip()
    cfg = ai_subscription_config(db)

    if mode == "code":
        code = request.form.get("code", "").strip()
        if not code:
            flash("اكتب كود الشحن الأول.", "danger")
        else:
            ok, msg = redeem_recharge_code_for_teacher(db, teacher_id, teacher["name"], code)
            flash(msg, "success" if ok else "danger")
    elif mode == "manual":
        method = request.form.get("method", "").strip()
        try:
            amount = float(request.form.get("amount", 0) or 0)
        except ValueError:
            amount = 0
        if not method or amount <= 0:
            flash("اختار الطريقة واكتب مبلغ صح.", "danger")
        else:
            proof = save_uploaded_photo(request.files.get("proof_photo"))
            db.execute(
                "INSERT INTO payment_orders "
                "(student_name, kind, amount, status, method, proof_photo, created_at, payer_role) "
                "VALUES (?, 'teacher_ai', ?, 'manual', ?, ?, ?, 'teacher')",
                (teacher["name"], amount, method, proof or "", datetime.utcnow().isoformat()),
            )
            db.commit()
            flash(
                f"حلو! ابعت {int(amount)} ج على {method}، وارفع سكرين التحويل — "
                "الإدارة هتتأكد وتفعّل اشتراك الذكاء الاصطناعي ليك (حوالي "
                f"{max(1, int(round(amount / cfg['price'] * cfg['days'])))} يوم).",
                "success",
            )
    return redirect(url_for("teacher_dashboard", teacher_id=teacher_id) + "#ai")


# ---------------------------------------------------------------------------
# Routes - admin (لوحة تحكم الإدارة)
# ---------------------------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        ip = request.remote_addr or ""
        blocked = login_blocked(db, "admin", username, ip)
        if blocked:
            error = blocked
        else:
            admin = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
            if admin and check_password_hash(admin["password_hash"], password):
                if admin["login_start_hour"] is not None and admin["login_end_hour"] is not None:
                    current_hour = datetime.now().hour
                    start, end = admin["login_start_hour"], admin["login_end_hour"]
                    # بيتعامل مع الفترة العادية (مثلاً 9 لـ 17) وكمان اللي بتعدي
                    # نص الليل (مثلاً 22 لـ 6).
                    if start <= end:
                        allowed = start <= current_hour < end
                    else:
                        allowed = current_hour >= start or current_hour < end
                    if not allowed:
                        error = f"مسموح لحسابك تدخل بس من الساعة {start}:00 لحد {end}:00."
                        return render_template("admin_login.html", error=error)
                clear_login_attempts(db, "admin", username, ip)
                session.clear()
                session["admin_id"] = admin["id"]
                session["admin_username"] = admin["username"]
                session["admin_role"] = admin["role"]
                log_security_event("admin_login", f"{admin['username']} ({admin['role']}) من {ip}")
                return redirect(url_for("admin_dashboard"))
            record_login_attempt(db, "admin", username, ip)
            log_security_event("admin_login_failed", f"{username} من {ip}")
            error = "اسم المستخدم أو كلمة المرور غلط."
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin_id", None)
    session.pop("admin_username", None)
    session.pop("admin_role", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
def admin_dashboard():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))

    db = get_db()
    teacher_count = db.execute("SELECT COUNT(*) c FROM teachers").fetchone()["c"]
    lesson_count = db.execute("SELECT COUNT(*) c FROM materials").fetchone()["c"]

    search_code = request.args.get("search_code", "").strip()
    search_results = []
    if search_code:
        code_upper = search_code.upper()
        for s in db.execute("SELECT * FROM students WHERE account_code = ?", (code_upper,)).fetchall():
            search_results.append({"type": "طالب", "row": dict(s)})
        for t in db.execute("SELECT * FROM teachers WHERE account_code = ?", (code_upper,)).fetchall():
            search_results.append({"type": "مدرس", "row": dict(t)})
        for a in db.execute("SELECT * FROM admins WHERE username = ?", (search_code,)).fetchall():
            search_results.append({"type": "إداري" if a["role"] == "اداري" else "رئيس", "row": dict(a)})

    # "طالب نشط" = ظهر في شات أو عملية شراء على الأقل مرة.
    active_students = db.execute(
        """SELECT COUNT(*) c FROM (
            SELECT student_name FROM chat_messages
            UNION
            SELECT student_name FROM purchases
        )"""
    ).fetchone()["c"]

    total_revenue = db.execute(
        "SELECT COALESCE(SUM(amount), 0) r FROM purchases"
    ).fetchone()["r"]

    # كل إيراد المنصة بيدخل على فيزا الرئيس تلقائيًا (محاكاة). التقرير اليومي
    # بيجمع المشتريات على أساس اليوم اللي حصل فيه الشراء.
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    today_income = db.execute(
        "SELECT COALESCE(SUM(amount), 0) r FROM purchases WHERE substr(purchased_at, 1, 10) = ?",
        (today_str,),
    ).fetchone()["r"]
    daily_income = db.execute(
        """SELECT substr(purchased_at, 1, 10) d, SUM(amount) s
           FROM purchases WHERE amount > 0
           GROUP BY substr(purchased_at, 1, 10)
           ORDER BY d DESC LIMIT 15"""
    ).fetchall()

    payment_orders = db.execute(
        """SELECT * FROM payment_orders
           ORDER BY id DESC LIMIT 50"""
    ).fetchall()

    manual_orders = db.execute(
        """SELECT * FROM payment_orders
           WHERE status = 'manual'
           ORDER BY id ASC"""
    ).fetchall()

    recharge_stats = db.execute(
        """SELECT status, COUNT(*) c, COALESCE(SUM(amount), 0) s
           FROM recharge_codes GROUP BY status"""
    ).fetchall()
    recent_codes = db.execute(
        """SELECT * FROM recharge_codes ORDER BY id DESC LIMIT 30"""
    ).fetchall()
    last_codes = session.pop("last_codes", None)

    staff = None
    teachers = None
    visa = None
    commissions = None
    payouts = None
    settings_dict = None
    teacher_ai_subs = None
    if session.get("admin_role") == "رئيس":
        staff = db.execute("SELECT id, username, role, photo, created_at, password_plain FROM admins ORDER BY id").fetchall()
        teachers = db.execute(
            "SELECT id, name, subject, workplace, commission_percent, account_code, photo FROM teachers ORDER BY id"
        ).fetchall()
        visa = db.execute("SELECT * FROM visa_settings WHERE id = 1").fetchone()

        teacher_ai_subs = []
        for row in db.execute(
            "SELECT id, name, subject, ai_subscription_expires_at FROM teachers ORDER BY id"
        ).fetchall():
            expires = teacher_ai_expiry(row)
            teacher_ai_subs.append({
                "id": row["id"], "name": row["name"], "subject": row["subject"],
                "expires_at": expires,
                "is_active": bool(expires) and teacher_ai_active(db, row),
                "days_left": teacher_ai_days_left(db, row),
            })

        # عمولات المدرسين: لكل مدرس إجمالي مبيعاته على دروسه، حصة المنصة
        # (العمولة %)، حصته، اللي اتصرف له، والمتبقي.
        commissions = []
        for t in teachers:
            gross = db.execute(
                """SELECT COALESCE(SUM(p.amount), 0) r FROM purchases p
                   JOIN materials m ON m.id = p.material_id WHERE m.teacher_id = ?""",
                (t["id"],),
            ).fetchone()["r"]
            cut = round(gross * (t["commission_percent"] or 0) / 100.0, 2)
            share = round(gross - cut, 2)
            paid = db.execute(
                "SELECT COALESCE(SUM(amount), 0) r FROM payouts WHERE teacher_id = ?", (t["id"],)
            ).fetchone()["r"]
            commissions.append({
                "teacher": t, "gross": gross, "cut": cut,
                "share": share, "paid": paid, "pending": round(share - paid, 2),
            })
        payouts = db.execute(
            "SELECT * FROM payouts ORDER BY id DESC LIMIT 20"
        ).fetchall()
        settings_dict = {r["key"]: r["value"] for r in db.execute("SELECT * FROM settings")}

    # متاحة للرئيس والإداري مع بعض - عشان أي حد في فريق الإدارة يقدر يوقف
    # حساب مشبوه أو مخالف.
    all_students = db.execute(
        "SELECT id, name, account_code, student_phone, parent_phone, is_blocked FROM students ORDER BY id DESC"
    ).fetchall()
    all_teachers = db.execute(
        "SELECT id, name, subject, account_code, phone, is_blocked FROM teachers ORDER BY id DESC"
    ).fetchall()

    me = db.execute("SELECT * FROM admins WHERE id = ?", (session["admin_id"],)).fetchone()
    last_created_teacher = session.pop("last_created_teacher", None)
    announcements = db.execute("SELECT * FROM announcements ORDER BY id DESC").fetchall()

    support_pending_count = db.execute(
        "SELECT COUNT(*) c FROM support_requests WHERE status = 'pending'"
    ).fetchone()["c"]

    contract_count = db.execute(
        "SELECT COUNT(*) c FROM teacher_contracts WHERE status = 'نشط'"
    ).fetchone()["c"]
    block_count = db.execute(
        "SELECT COUNT(*) c FROM teacher_student_blocks"
    ).fetchone()["c"]

    # طلبات تقارير ولي الأمر (بتحتاج إدارة الإدارة وتبعتها واتساب).
    admin_reports = db.execute(
        """SELECT an.*, s.account_code, s.name student_name_full
           FROM admin_notifications an
           LEFT JOIN students s ON s.id = an.student_id
           ORDER BY an.id DESC LIMIT 40"""
    ).fetchall()
    admin_reports_pending = db.execute(
        "SELECT COUNT(*) c FROM admin_notifications WHERE status = 'pending'"
    ).fetchone()["c"]

    return render_template(
        "admin_dashboard.html",
        admin_username=session.get("admin_username"), admin_role=session.get("admin_role"), me=me,
        teacher_count=teacher_count, lesson_count=lesson_count, teachers=teachers,
        all_students=all_students, all_teachers=all_teachers, announcements=announcements,
        last_created_teacher=last_created_teacher, search_code=search_code, search_results=search_results,
        active_students=active_students, total_revenue=total_revenue, staff=staff,
        today_income=today_income, daily_income=daily_income, visa=visa, today_str=today_str,
        commissions=commissions, payouts=payouts, settings_dict=settings_dict,
        payment_orders=payment_orders, manual_orders=manual_orders,
        recharge_stats=recharge_stats, recent_codes=recent_codes, last_codes=last_codes,
        teacher_ai_subs=teacher_ai_subs, ai_cfg=ai_subscription_config(db),
        support_pending_count=support_pending_count,
        contract_count=contract_count, block_count=block_count,
        admin_reports=admin_reports, admin_reports_pending=admin_reports_pending,
        support_phone=_support_phone(db),
    )


@app.route("/admin/parent-report/<int:report_id>/send", methods=["POST"])
def admin_send_parent_report(report_id):
    """الإدارة بتبع التقرير على واتساب لرقم ولي الأمر (الرقم اللي في الطلب)."""
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    report = db.execute(
        "SELECT * FROM admin_notifications WHERE id = ?", (report_id,)
    ).fetchone()
    if not report:
        flash("التقرير مش موجود.", "danger")
        return redirect(url_for("admin_dashboard", tab="reports"))
    if report["status"] == "sent":
        flash("التقرير ده اتبعت قبل كده.", "info")
        return redirect(url_for("admin_dashboard", tab="reports"))

    ok, status = whatsapp_send(report["phone"], report["report_text"])
    db.execute(
        """UPDATE admin_notifications SET status = ?, is_read = 1, sent_at = ?
           WHERE id = ?""",
        ("sent" if ok else "failed", datetime.utcnow().isoformat(), report_id),
    )
    db.commit()
    if ok:
        flash("التقرير اتبعت واتساب لولي الأمر ✅", "success")
    else:
        flash(f"الواتساب مش متاح حاليًا ({status}) — التقرير محفوظ.", "danger")
    return redirect(url_for("admin_dashboard", tab="reports"))


@app.route("/admin/support-requests")
def admin_support_requests():
    """طلبات الدعم الاجتماعي: تكفل الأيتام + عدم المقدرة على الدفع."""
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    status = request.args.get("status", "pending")
    if status not in ("pending", "approved", "rejected", "all"):
        status = "pending"
    if status == "all":
        rows = db.execute(
            "SELECT * FROM support_requests ORDER BY id DESC"
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM support_requests WHERE status = ? ORDER BY id DESC",
            (status,),
        ).fetchall()
    counts = {r["status"]: r["c"] for r in db.execute(
        "SELECT status, COUNT(*) c FROM support_requests GROUP BY status"
    ).fetchall()}
    return render_template(
        "admin_support_requests.html", rows=rows, status=status, counts=counts,
        admin_username=session.get("admin_username"), admin_role=session.get("admin_role"),
    )


@app.route("/admin/support-requests/<int:req_id>/update", methods=["POST"])
def admin_update_support_request(req_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    new_status = request.form.get("status", "")
    note = request.form.get("admin_note", "").strip()[:300]
    if new_status in ("approved", "rejected"):
        db.execute(
            "UPDATE support_requests SET status = ?, admin_note = ?, resolved_at = ? WHERE id = ?",
            (new_status, note, datetime.utcnow().isoformat(), req_id),
        )
        db.commit()
        flash("تم تحديث حالة الطلب.", "success")
    return redirect(url_for("admin_support_requests", status=request.args.get("status", "pending")))


@app.route("/admin/contracts", methods=["GET", "POST"])
def admin_contracts():
    """تسجيل عقود المدرسين: نوع العقد (عمولة / ثابت شهري / حساب لكل حصة)،
    المبلغ، المدة، والملاحظات. ليها صفحة مستقلة زي طلبات الدعم."""
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    if request.method == "POST":
        teacher_id = request.form.get("teacher_id", type=int)
        contract_type = request.form.get("contract_type", "").strip()
        amount = request.form.get("amount", "0").strip().replace(",", "")
        try:
            amount = max(0.0, float(amount))
        except ValueError:
            amount = 0.0
        start_date = request.form.get("start_date", "").strip()
        end_date = request.form.get("end_date", "").strip()
        notes = request.form.get("notes", "").strip()[:300]
        if teacher_id and contract_type:
            db.execute(
                """INSERT INTO teacher_contracts
                   (teacher_id, contract_type, amount, start_date, end_date, notes, status,
                    created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'نشط', ?, ?)""",
                (teacher_id, contract_type, amount, start_date, end_date, notes,
                 session.get("admin_username", ""), datetime.utcnow().isoformat()),
            )
            db.commit()
            teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
            flash(f"تم تسجيل العقد {'بنسبة ' + contract_type + ' ' + str(int(amount)) + '%' if contract_type == 'عمولة' else 'بقيمة ' + str(int(amount)) + ' جنيه'} للمدرس {teacher['name'] if teacher else ''}.", "success")
        else:
            flash("اختار المدرس ونوع العقد.", "danger")
        return redirect(url_for("admin_contracts"))
    contracts = db.execute(
        """SELECT c.*, t.name teacher_name, t.subject teacher_subject
           FROM teacher_contracts c JOIN teachers t ON t.id = c.teacher_id
           ORDER BY c.id DESC"""
    ).fetchall()
    teachers = db.execute(
        "SELECT id, name, subject, commission_percent FROM teachers ORDER BY name"
    ).fetchall()
    return render_template(
        "admin_contracts.html", contracts=contracts, teachers=teachers,
        admin_username=session.get("admin_username"), admin_role=session.get("admin_role"),
    )


@app.route("/admin/contracts/<int:contract_id>/toggle", methods=["POST"])
def admin_toggle_contract(contract_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    row = db.execute("SELECT status FROM teacher_contracts WHERE id = ?", (contract_id,)).fetchone()
    if row:
        new_status = "منتهي" if row["status"] == "نشط" else "نشط"
        db.execute("UPDATE teacher_contracts SET status = ? WHERE id = ?", (new_status, contract_id))
        db.commit()
        flash("تم تغيير حالة العقد.", "success")
    return redirect(url_for("admin_contracts"))


@app.route("/admin/blocks")
def admin_blocks():
    """إيقاف الطلاب من عند المدرسين — هنا بتتشال الإيقافات (الدعم الفني/
    الإدارة هي اللي فاكتها بعد ما يتم الاتفاق مع الطالب)."""
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    blocks = db.execute(
        """SELECT b.*, t.name teacher_name, s.name student_name, s.account_code student_code
           FROM teacher_student_blocks b
           JOIN teachers t ON t.id = b.teacher_id
           JOIN students s ON s.id = b.student_id
           ORDER BY b.id DESC"""
    ).fetchall()
    return render_template(
        "admin_blocks.html", blocks=blocks,
        admin_username=session.get("admin_username"), admin_role=session.get("admin_role"),
    )


@app.route("/admin/blocks/<int:block_id>/remove", methods=["POST"])
def admin_remove_block(block_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    block = db.execute(
        """SELECT b.*, s.name student_name FROM teacher_student_blocks b
           JOIN students s ON s.id = b.student_id WHERE b.id = ?""",
        (block_id,),
    ).fetchone()
    if block:
        db.execute("DELETE FROM teacher_student_blocks WHERE id = ?", (block_id,))
        db.commit()
        flash(f"تم شيل الإيقاف عن الطالب {block['student_name']} — يقدر يرجع يذاكر ويشتري.", "success")
    return redirect(url_for("admin_blocks"))


@app.route("/admin/visa-settings", methods=["POST"])
def admin_visa_settings():
    # بيانات الفيزا بتتعدل من الرئيس بس.
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))

    holder_name = request.form.get("holder_name", "").strip()
    card_number = "".join(ch for ch in request.form.get("card_number", "") if ch.isdigit())
    bank_name = request.form.get("bank_name", "").strip()

    if not holder_name:
        flash("اكتب اسم صاحب الفيزا.", "danger")
        return redirect(url_for("admin_dashboard", tab="visa"))
    if len(card_number) < 12:
        flash("اكتب رقم الفيزا صح (من 12 لـ 19 رقم).", "danger")
        return redirect(url_for("admin_dashboard", tab="visa"))

    db = get_db()
    db.execute(
        """UPDATE visa_settings SET holder_name = ?, card_number = ?, bank_name = ? WHERE id = 1""",
        (holder_name, card_number, bank_name),
    )
    db.commit()
    flash("تم حفظ بيانات الفيزا — كل الإيرادات الجاية هتتحول عليها تلقائيًا.", "success")
    return redirect(url_for("admin_dashboard", tab="visa"))


@app.route("/admin/settings", methods=["POST"])
def admin_settings():
    # إعدادات المنصة العامة - من الرئيس بس.
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))

    anthropic_key = request.form.get("anthropic_key", "").strip()
    site_url = request.form.get("site_url", "").strip().rstrip("/")
    payment_mode = request.form.get("payment_mode", "محاكاة").strip()
    backup_enabled = "1" if request.form.get("backup_enabled") else "0"
    backup_retention = request.form.get("backup_retention", "14").strip()
    ai_price = request.form.get("ai_subscription_price", "300").strip()
    ai_days = request.form.get("ai_subscription_days", "30").strip()

    if payment_mode not in {"محاكاة", "حقيقي"}:
        payment_mode = "محاكاة"
    try:
        retention = int(backup_retention)
        if not (1 <= retention <= 90):
            retention = 14
    except ValueError:
        retention = 14
    try:
        ai_price_f = float(ai_price)
        if ai_price_f <= 0:
            ai_price_f = 300
    except ValueError:
        ai_price_f = 300
    try:
        ai_days_i = int(ai_days)
        if not (1 <= ai_days_i <= 3650):
            ai_days_i = 30
    except ValueError:
        ai_days_i = 30

    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('anthropic_key', ?)", (anthropic_key,))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('site_url', ?)", (site_url,))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('payment_mode', ?)", (payment_mode,))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('backup_enabled', ?)", (backup_enabled,))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('backup_retention', ?)", (str(retention),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ai_subscription_price', ?)", (str(ai_price_f),))
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('ai_subscription_days', ?)", (str(ai_days_i),))
    db.commit()
    log_security_event("admin_settings_changed", f"payment_mode={payment_mode} backup_enabled={backup_enabled}")
    flash("تم حفظ الإعدادات.", "success")
    return redirect(url_for("admin_dashboard", tab="settings"))


@app.route("/admin/change-password", methods=["POST"])
def admin_change_password():
    """تغيير باسورد حسابي الحالي (أي أدمن). بيتطلب الباسورد القديم قبل ما يغيّر —
    عشان لو السشن اتسرق/حساب فاتح على جهاز، حد غريب ميقدرش يغيّر الباسورد.
    والحد الأدنى 8 خانات + لازم فيه رقم وحرف عشان الباسورد يبقى قوي فعلًا."""
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    current = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    db = get_db()
    me = db.execute("SELECT * FROM admins WHERE id = ?", (session["admin_id"],)).fetchone()
    if not me:
        session.clear()
        return redirect(url_for("admin_login"))
    if not check_password_hash(me["password_hash"], current):
        flash("الباسورد الحالي غلط.", "danger")
        return redirect(url_for("admin_dashboard", tab="profile"))
    if len(new_password) < 8 or not any(c.isdigit() for c in new_password) or not any(c.isalpha() for c in new_password):
        flash("الباسورد الجديد لازم يكون 8 خانات على الأقل وفيه رقم وحرف.", "danger")
        return redirect(url_for("admin_dashboard", tab="profile"))
    if new_password == current:
        flash("الباسورد الجديد لازم يختلف عن القديم.", "danger")
        return redirect(url_for("admin_dashboard", tab="profile"))
    db.execute(
        "UPDATE admins SET password_hash = ?, password_plain = ? WHERE id = ?",
        (generate_password_hash(new_password), new_password, session["admin_id"]),
    )
    db.commit()
    log_security_event("admin_password_changed", f"admin_id={session['admin_id']}")
    # نسخة جديدة من السشن عشان لو حد تاني فاتح بنفس الحساب مايبقاش شغال بعد تغيير الباسورد.
    session.clear()
    flash("تم تغيير الباسورد — سجّل الدخول من جديد بالباسورد الجديد.", "success")
    return redirect(url_for("admin_login"))


@app.route("/admin/whatsapp/settings", methods=["POST"])
def admin_whatsapp_settings():
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))
    db = get_db()
    for key in ["phone_number_id", "access_token", "code_template", "grade_template", "lang"]:
        value = request.form.get(f"whatsapp_{key}", "").strip()
        if key == "lang" and value not in {"ar", "en"}:
            value = "ar"
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (f"whatsapp_{key}", value))
    db.commit()
    flash("تم حفظ إعدادات الواتساب.", "success")
    return redirect(url_for("admin_dashboard", tab="settings"))


@app.route("/admin/whatsapp/test", methods=["POST"])
def admin_whatsapp_test():
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))
    phone = request.form.get("test_number", "").strip()
    cfg = _whatsapp_config()
    if not phone:
        flash("اكتب رقم للتجربة الأول.", "danger")
    elif not _whatsapp_ready(cfg):
        flash("الواتساب لسه مش مفعّل — احفظ الـ phone number ID والـ token الأول.", "danger")
    else:
        msg = "رسالة تجربة من منصة Seniors ✅"
        if cfg.get("code_template"):
            ok, status = whatsapp_send(
                phone, msg,
                template_name=cfg["code_template"],
                template_params=["اسم الطالب", "STU-0000", "كلمة-المرور"],
            )
        else:
            ok, status = whatsapp_send(phone, msg)
        flash(f"نتيجة التجربة: {'تم الإرسال ✅' if ok else status}", "success" if ok else "danger")
    return redirect(url_for("admin_dashboard", tab="settings"))


@app.route("/admin/payment/settings", methods=["POST"])
def admin_payment_settings():
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))
    db = get_db()
    mode = request.form.get("payment_mode", "محاكاة")
    if mode not in {"محاكاة", "حقيقي"}:
        mode = "محاكاة"
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('payment_mode', ?)", (mode,))
    for key in ["api_key", "integration_id", "iframe_id", "hmac_secret"]:
        value = request.form.get(f"paymob_{key}", "").strip()
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (f"paymob_{key}", value))
    manual_details = request.form.get("manual_payment_details", "").strip()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('manual_payment_details', ?)", (manual_details,))
    for skey in ["instapay_number", "vodafone_number", "recharge_whatsapp", "support_phone"]:
        db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (skey, request.form.get(skey, "").strip()),
        )
    db.commit()
    flash("تم حفظ إعدادات الدفع.", "success")
    return redirect(url_for("admin_dashboard", tab="settings"))


@app.route("/admin/manual-payment/<int:order_id>/<action>", methods=["POST"])
def admin_manual_payment(order_id, action):
    # اعتماد / رفض شحنة يدوية (تحويل على محفظة/بنك الإدارة) - من الرئيس بس.
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))
    db = get_db()
    po = db.execute("SELECT * FROM payment_orders WHERE id = ?", (order_id,)).fetchone()
    if po and po["status"] == "manual":
        if action == "confirm":
            if po["kind"] == "teacher_ai":
                # شحنة اشتراك ذكاء اصطناعي لمدرس: المبلغ بيتحول لأيام اشتراك.
                teacher = db.execute("SELECT * FROM teachers WHERE name = ?", (po["student_name"],)).fetchone()
                if teacher:
                    cfg = ai_subscription_config(db)
                    days = max(1, int(round(po["amount"] / cfg["price"] * cfg["days"])))
                    extend_teacher_ai(
                        db, teacher["id"], days, amount=po["amount"],
                        method=po["method"], granted_by=session.get("admin_username", "admin"),
                    )
                    db.execute(
                        "UPDATE payment_orders SET status = 'paid', paid_at = ? WHERE id = ?",
                        (datetime.utcnow().isoformat(), po["id"]),
                    )
                    db.commit()
                    flash(
                        f"تم تفعيل اشتراك الذكاء الاصطناعي لـ {teacher['name']} "
                        f"بمدة {days} يوم ({int(po['amount'])} ج).",
                        "success",
                    )
                else:
                    flash(f"المدرس {po['student_name']} مش موجود في النظام — اتأكد من الطلب.", "danger")
            else:
                _fulfill_payment(db, po, f"يدوي-{po['id']}")
                flash(f"تم اعتماد شحنة {po['student_name']} بقيمة {int(po['amount'])} ج.", "success")
        elif action == "reject":
            db.execute("UPDATE payment_orders SET status = 'failed' WHERE id = ?", (order_id,))
            db.commit()
            who = po["student_name"]
            flash(f"تم رفض شحنة {who} — اتأكد إن التحويل وصل فعلًا قبل الرفض.", "danger")
    return redirect(url_for("admin_dashboard", tab="withdraw"))


@app.route("/admin/generate-codes", methods=["POST"])
def admin_generate_codes():
    # توليد أكواد شحن للسنترات - من الرئيس بس.
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))
    try:
        count = int(request.form.get("count", 0))
        amount = float(request.form.get("amount", 0) or 0)
    except ValueError:
        count = 0
        amount = 0
    if not (1 <= count <= 200) or amount <= 0:
        flash("اكتب عدد صحيح (1-200) وقيمة أكتر من صفر.", "danger")
        return redirect(url_for("admin_dashboard", tab="withdraw"))
    center = request.form.get("center_name", "").strip()
    db = get_db()
    codes = []
    for _ in range(count):
        code = generate_recharge_code()
        db.execute(
            "INSERT INTO recharge_codes (code, amount, status, center_name, created_by, created_at) "
            "VALUES (?, ?, 'available', ?, ?, ?)",
            (code, amount, center, session.get("admin_username", ""), datetime.utcnow().isoformat()),
        )
        codes.append(code)
    db.commit()
    session["last_codes"] = codes
    flash(f"تم توليد {count} كود بقيمة {int(amount)} ج لكل كود — شوفهم في لوحة الإدارة.", "success")
    return redirect(url_for("admin_dashboard", tab="withdraw"))


@app.route("/admin/teacher-ai/grant", methods=["POST"])
def admin_teacher_ai_grant():
    # إضافة أيام اشتراك AI لمدرس (هدية / تصحيح يدوي) - من الرئيس بس.
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))
    teacher_id = request.form.get("teacher_id", type=int)
    try:
        days = int(request.form.get("days", 0) or 0)
    except ValueError:
        days = 0
    if teacher_id and 1 <= days <= 3650:
        db = get_db()
        teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
        if teacher:
            extend_teacher_ai(
                db, teacher_id, days, amount=0.0, method="إضافة يدوية من الإدارة",
                granted_by=session.get("admin_username", "admin"),
            )
            flash(f"تم إضافة {days} يوم اشتراك AI لـ {teacher['name']}.", "success")
        else:
            flash("المدرس مش موجود.", "danger")
    else:
        flash("اكتب عدد أيام صحيح (1-3650).", "danger")
    return redirect(url_for("admin_dashboard", tab="withdraw"))


@app.route("/admin/backup", methods=["POST"])
def admin_backup_now():
    # نسخة احتياطية يدوية دلوقتي - من الرئيس بس.
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))
    try:
        path = create_backup()
        flash(f"تم إنشاء نسخة احتياطية: {os.path.basename(path)} — موجودة في مجلد backups/ داخل السيرفر.", "success")
    except Exception as exc:
        flash(f"فشل إنشاء النسخة الاحتياطية: {exc}", "danger")
    return redirect(url_for("admin_dashboard", tab="settings"))


@app.route("/admin/teachers/<int:teacher_id>/payout", methods=["POST"])
def admin_teacher_payout(teacher_id):
    # صرف مستحقات المدرس الحالية (دفعة واحدة) وتسجيلها - من الرئيس بس.
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id = ?", (teacher_id,)).fetchone()
    if not teacher:
        return redirect(url_for("admin_dashboard", tab="commissions"))

    gross = db.execute(
        """SELECT COALESCE(SUM(p.amount), 0) r FROM purchases p
           JOIN materials m ON m.id = p.material_id WHERE m.teacher_id = ?""",
        (teacher_id,),
    ).fetchone()["r"]
    cut = round(gross * (teacher["commission_percent"] or 0) / 100.0, 2)
    share = round(gross - cut, 2)
    paid = db.execute(
        "SELECT COALESCE(SUM(amount), 0) r FROM payouts WHERE teacher_id = ?", (teacher_id,)
    ).fetchone()["r"]
    pending = round(share - paid, 2)

    if pending <= 0:
        flash("مفيش مستحقات لصرفها لهذا المدرس حاليًا.", "danger")
        return redirect(url_for("admin_dashboard", tab="commissions"))

    db.execute(
        "INSERT INTO payouts (teacher_id, teacher_name, amount, period, paid_at) VALUES (?, ?, ?, ?, ?)",
        (teacher_id, teacher["name"], pending, datetime.utcnow().strftime("%Y-%m-%d"), datetime.utcnow().isoformat()),
    )
    db.commit()
    flash(f"تم صرف {pending:,.2f} جنيه لـ {teacher['name']}.", "success")
    return redirect(url_for("admin_dashboard", tab="commissions"))


@app.route("/admin/students/<int:student_id>/toggle-block", methods=["POST"])
def admin_toggle_student_block(student_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    db.execute("UPDATE students SET is_blocked = NOT is_blocked WHERE id = ?", (student_id,))
    db.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/students/<int:student_id>/reset-password", methods=["POST"])
def admin_reset_student_password(student_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    new_password = request.form.get("new_password", "")
    if _is_strong_enough_password(new_password):
        db = get_db()
        db.execute(
            "UPDATE students SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), student_id),
        )
        db.commit()
    return redirect(url_for("admin_dashboard"))


def _since_label(iso_str: str) -> str | None:
    """مدة مرت على توقيت معين بصيغة عربية موجزة (منذ ساعات/أيام/أسابيع...)."""
    if not iso_str:
        return None
    try:
        then = datetime.fromisoformat(iso_str)
    except (TypeError, ValueError):
        return None
    days = (datetime.utcnow() - then).total_seconds() / 86400.0
    if days < 0:
        days = 0
    if days < 1:
        return "منذ ساعات"
    if days < 2:
        return "منذ يوم"
    if days < 30:
        n = int(days)
        return f"منذ {n} يوم" if n == 1 else f"منذ {n} أيام"
    months = int(days // 30)
    if months < 12:
        return f"منذ {months} شهر" if months == 1 else f"منذ {months} أشهر"
    years = int(days // 365)
    return f"منذ {years} سنة" if years == 1 else f"منذ {years} سنوات"


@app.route("/admin/students/<int:student_id>/exemptions", methods=["GET"])
def admin_student_exemptions(student_id):
    """استثناءات الإدارة: بيخلي الإدارة تفتح حصة معينة لطالب من غير التسلسل
    (من غير ما يخلص اللي قبلها)، وبتتحسب الحصة دي مخلصة في التسلسل. الصفحة
    بتعرض بس المدرسين اللي الطالب مشترك معاهم فعلًا، وبكل حصة بيبان لو هو
    شاريها وإمتى، وآخر مرة مذاكر فيها."""
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
    if not student:
        return redirect(url_for("admin_dashboard"))
    groups = []
    subscribed = db.execute(
        """SELECT DISTINCT t.* FROM teachers t
           JOIN materials m ON m.teacher_id = t.id
           JOIN purchases p ON p.material_id = m.id
           WHERE p.student_id = ?
           ORDER BY t.name""",
        (student_id,),
    ).fetchall()
    for t in subscribed:
        mats = db.execute(
            """SELECT m.id, m.title, m.kind,
                      (SELECT 1 FROM admin_exemptions e
                       WHERE e.material_id = m.id AND e.student_id = ?) AS exempt,
                      (SELECT p.purchased_at FROM purchases p
                       WHERE p.material_id = m.id AND p.student_id = ?) AS purchased_at,
                      (SELECT MAX(a.ts) FROM (
                          SELECT v.viewed_at ts FROM lesson_views v
                           WHERE v.material_id = m.id AND v.student_id = ?
                         UNION ALL
                          SELECT w.updated_at ts FROM video_watch w
                           WHERE w.material_id = m.id AND w.student_id = ?
                       ) a) AS last_studied_at
               FROM materials m WHERE m.teacher_id = ? ORDER BY m.id""",
            (student_id, student_id, student_id, student_id, t["id"]),
        ).fetchall()
        if mats:
            material_rows = []
            for m in mats:
                m = dict(m)
                m["since_label"] = _since_label(m["last_studied_at"])
                material_rows.append(m)
            last_heartbeat = db.execute(
                "SELECT MAX(created_at) ts FROM study_heartbeats WHERE student_id = ? AND teacher_id = ?",
                (student_id, t["id"]),
            ).fetchone()["ts"]
            groups.append({
                "teacher": t,
                "materials": material_rows,
                "last_study_label": _since_label(last_heartbeat),
            })
    return render_template(
        "admin_student_exemptions.html", student=student, groups=groups,
        admin_name=session.get("admin_username", ""), admin_role=session.get("admin_role", ""),
    )


@app.route("/admin/students/<int:student_id>/exemptions/toggle", methods=["POST"])
def admin_toggle_student_exemption(student_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    student = db.execute("SELECT id, name FROM students WHERE id = ?", (student_id,)).fetchone()
    if not student:
        return redirect(url_for("admin_dashboard"))
    material_id = request.form.get("material_id", type=int)
    action = request.form.get("action", "")
    reason = request.form.get("reason", "").strip()
    material = db.execute("SELECT id FROM materials WHERE id = ?", (material_id,)).fetchone() if material_id else None
    if material:
        if action == "add":
            db.execute(
                "INSERT OR IGNORE INTO admin_exemptions "
                "(student_id, student_name, material_id, reason, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (student_id, student["name"], material_id, reason,
                 session.get("admin_username", ""), datetime.utcnow().isoformat()),
            )
        elif action == "remove":
            db.execute(
                "DELETE FROM admin_exemptions WHERE student_id = ? AND material_id = ?",
                (student_id, material_id),
            )
        db.commit()
    return redirect(url_for("admin_student_exemptions", student_id=student_id))


@app.route("/admin/teachers/<int:teacher_id>/reset-password", methods=["POST"])
def admin_reset_teacher_password(teacher_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    new_password = request.form.get("new_password", "")
    if _is_strong_enough_password(new_password):
        db = get_db()
        db.execute(
            "UPDATE teachers SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), teacher_id),
        )
        db.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/staff/<int:staff_id>/reset-password", methods=["POST"])
def admin_reset_admin_password(staff_id):
    """الرئيس يقدر يعيّن باسورد جديد لأي إداري (وبالتالي يظهر له في القائمة)."""
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))
    new_password = request.form.get("new_password", "")
    if _is_strong_enough_password(new_password):
        db = get_db()
        db.execute(
            "UPDATE admins SET password_hash = ?, password_plain = ? WHERE id = ?",
            (generate_password_hash(new_password), new_password, staff_id),
        )
        db.commit()
        log_security_event("admin_password_reset", f"admin_id={staff_id} by {session.get('admin_username')}")
    return redirect(url_for("admin_dashboard", tab="staff"))


@app.route("/admin/teachers/<int:teacher_id>/toggle-block", methods=["POST"])
def admin_toggle_teacher_block(teacher_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    db.execute("UPDATE teachers SET is_blocked = NOT is_blocked WHERE id = ?", (teacher_id,))
    db.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/staff", methods=["POST"])
def admin_add_staff():
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "اداري").strip()
    if role not in {"رئيس", "اداري"}:
        role = "اداري"

    def parse_hour(val):
        try:
            h = int(val)
            return h if 0 <= h <= 23 else None
        except (TypeError, ValueError):
            return None

    login_start_hour = parse_hour(request.form.get("login_start_hour"))
    login_end_hour = parse_hour(request.form.get("login_end_hour"))
    # الاتنين لازم يتحطوا مع بعض عشان الشرط يبقى له معنى - لو واحد بس اتحط
    # بنتجاهله بدل ما نعمل قيد نص مظبوط.
    if login_start_hour is None or login_end_hour is None:
        login_start_hour = login_end_hour = None

    if username and password:
        db = get_db()
        existing = db.execute("SELECT 1 FROM admins WHERE username = ?", (username,)).fetchone()
        if not existing:
            photo = save_uploaded_photo(request.files.get("photo"))
            db.execute(
                "INSERT INTO admins (username, password_hash, password_plain, role, photo, login_start_hour, login_end_hour, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (username, generate_password_hash(password), password, role, photo,
                 login_start_hour, login_end_hour, datetime.utcnow().isoformat()),
            )
            db.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/photo", methods=["POST"])
def admin_update_photo():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    photo = save_uploaded_photo(request.files.get("photo"))
    if photo:
        db = get_db()
        db.execute("UPDATE admins SET photo = ? WHERE id = ?", (photo, session["admin_id"]))
        db.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/announcements", methods=["POST"])
def admin_add_announcement():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    message = request.form.get("message", "").strip()
    emoji = request.form.get("emoji", "📢").strip() or "📢"
    if message:
        db = get_db()
        db.execute(
            "INSERT INTO announcements (message, emoji, created_by, created_at) VALUES (?, ?, ?, ?)",
            (message, emoji, session.get("admin_username", ""), datetime.utcnow().isoformat()),
        )
        db.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/announcements/<int:announcement_id>/toggle", methods=["POST"])
def admin_toggle_announcement(announcement_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    db.execute("UPDATE announcements SET is_active = NOT is_active WHERE id = ?", (announcement_id,))
    db.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/teachers", methods=["POST"])
def admin_add_teacher():
    if session.get("admin_role") != "رئيس":
        return redirect(url_for("admin_dashboard"))

    name = request.form.get("name", "").strip()
    subject = request.form.get("subject", "").strip()
    workplace = request.form.get("workplace", "").strip()
    phone = request.form.get("phone", "").strip()
    try:
        commission_percent = max(0.0, min(100.0, float(request.form.get("commission_percent", 0) or 0)))
    except ValueError:
        commission_percent = 0.0

    if name and subject:
        db = get_db()
        photo = save_uploaded_photo(request.files.get("photo"))
        account_code = generate_account_code_for(db, "teachers", "TCH")
        password = generate_password()
        db.execute(
            "INSERT INTO teachers (name, subject, bio, account_code, password_hash, phone, photo, "
            " workplace, commission_percent) VALUES (?, ?, '', ?, ?, ?, ?, ?, ?)",
            (name, subject, account_code, generate_password_hash(password), phone, photo,
             workplace, commission_percent),
        )
        db.commit()

        if phone:
            send_whatsapp_code(phone, name, account_code, password)

        # نعرض الكود والباسورد مرة واحدة للرئيس بعد الإضافة (زي شاشة تسجيل
        # الطالب) - عشان لو مفيش رقم موبايل يبعتلهم بيه، يقدر يوصّلهملهم بنفسه.
        session["last_created_teacher"] = {"name": name, "account_code": account_code, "password": password}

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/exam-bank", methods=["GET", "POST"])
def admin_exam_bank():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        if title:
            subject = (request.form.get("subject") or "").strip()
            stage_id = request.form.get("stage_id", type=int)
            stream_id = request.form.get("stream_id", type=int)
            curriculum_id = request.form.get("curriculum_id", type=int)
            term = request.form.get("term", type=int) or 0
            year = request.form.get("year", type=int)
            description = (request.form.get("description") or "").strip()
            file_path = save_exam_file_securely(request.files.get("file"))
            db.execute(
                """INSERT INTO exam_bank
                     (title, subject, stage_id, stream_id, curriculum_id, term, year, description,
                      file_path, is_published, created_by_type, created_by_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'admin', ?, ?)""",
                (title, subject, stage_id, stream_id, curriculum_id, term, year, description,
                 file_path or "", session["admin_id"], datetime.utcnow().isoformat()),
            )
            db.commit()

    exams = db.execute(
        """SELECT e.*, s.name stage_name, st.name stream_name, c.name curriculum_name
           FROM exam_bank e
           LEFT JOIN stages s ON s.id = e.stage_id
           LEFT JOIN streams st ON st.id = e.stream_id
           LEFT JOIN curricula c ON c.id = e.curriculum_id
           ORDER BY e.id DESC"""
    ).fetchall()
    stages = db.execute("SELECT * FROM stages ORDER BY sort_order").fetchall()
    streams = db.execute("SELECT * FROM streams ORDER BY sort_order").fetchall()
    curricula = db.execute("SELECT * FROM curricula ORDER BY id").fetchall()
    subjects = db.execute("SELECT * FROM subjects ORDER BY sort_order").fetchall()
    return render_template(
        "admin_exam_bank.html", exams=exams, stages=stages, streams=streams,
        curricula=curricula, subjects=subjects,
    )


@app.route("/admin/exam-bank/import-url", methods=["POST"])
def admin_exam_bank_import_url():
    """أداة استيراد بالرابط: الأدمن بيلصق رابط مباشر لملف (PDF/Word/Excel) —
    المنصة بتنزّله، بتفحصه بنفس فحوصات الأمان بتاعة الرفع، وبتخزّنه في البنك."""
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    url = (request.form.get("url") or "").strip()
    if not url:
        flash("اكتب رابط الملف الأول.", "danger")
        return redirect(url_for("admin_exam_bank"))

    # نسمح بالـ http/https فقط — منع ملفات محلية (file://) وسكيمات تانية.
    if not url.lower().startswith(("http://", "https://")):
        flash("الرابط لازم يبدأ بـ http:// أو https:// — ملف مباشر.", "danger")
        return redirect(url_for("admin_exam_bank"))

    title = (request.form.get("title") or "").strip()
    subject = (request.form.get("subject") or "").strip()
    stage_id = request.form.get("stage_id", type=int)
    stream_id = request.form.get("stream_id", type=int)
    curriculum_id = request.form.get("curriculum_id", type=int)
    term = request.form.get("term", type=int) or 0
    year = request.form.get("year", type=int)
    description = (request.form.get("description") or "").strip()

    try:
        r = requests.get(url, timeout=45, stream=True)
        r.raise_for_status()
        data = b""
        for chunk in r.iter_content(8192):
            data += chunk
            if len(data) > MAX_EXAM_BYTES:
                flash("الملف أكبر من الحد المسموح (30 ميجا).", "danger")
                return redirect(url_for("admin_exam_bank"))
        if not data:
            flash("الملف فاضي أو الموقع رجّع استجابة فاضية.", "danger")
            return redirect(url_for("admin_exam_bank"))
    except requests.RequestException as e:
        flash(f"ماقدرتش أنزّل الملف: {e}", "danger")
        return redirect(url_for("admin_exam_bank"))

    # نحدد الامتداد من الرابط أولاً، ولو مش واضح نستنتجه من الـ Content-Type.
    ext = ""
    path_ext = url.rsplit("?", 1)[0].rsplit(".", 1)[-1].lower()
    if path_ext in ALLOWED_EXAM_EXTENSIONS:
        ext = path_ext
    if not ext:
        ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        ext_map = {
            "application/pdf": "pdf",
            "application/msword": "doc",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
            "application/vnd.ms-excel": "xls",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
            "application/vnd.ms-powerpoint": "ppt",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
        }
        ext = ext_map.get(ctype, "")

    head = data[:16]
    sniff = _sniff_media_ext(head)
    if ext == "pdf" and sniff != "pdf":
        ext = "pdf"  # نحاول نحسب امتداد صحيح من المحتوى
    if sniff == "pdf" and ext not in ALLOWED_EXAM_EXTENSIONS:
        ext = "pdf"
    if sniff == "zip" and ext not in ALLOWED_EXAM_EXTENSIONS:
        ext = "docx"
    if sniff == "ole2" and ext not in ALLOWED_EXAM_EXTENSIONS:
        ext = "doc"
    if ext not in ALLOWED_EXAM_EXTENSIONS:
        flash("نوع الملف مش مدعوم — المطلوب PDF/Word/Excel/PowerPoint.", "danger")
        return redirect(url_for("admin_exam_bank"))

    # نفس فحوصات الرفع: magic bytes + ماسح الفيروسات.
    if ext == "pdf" and sniff != "pdf":
        flash("الملف مش PDF حقيقي (راجعه لوحده).", "danger")
        return redirect(url_for("admin_exam_bank"))
    hit = scan_file_for_malware(data)
    if hit:
        log_security_event("malware", f"رفضت ملف من رابط: {hit}")
        flash("الملف رُفض — فحص الأمان لقي فيه خطر.", "danger")
        return redirect(url_for("admin_exam_bank"))

    filename = secure_filename(f"{uuid.uuid4().hex}.{ext}")
    with open(os.path.join(UPLOAD_FOLDER, filename), "wb") as f:
        f.write(data)

    if not title:
        # لو مفيش عنوان، نستنتجه من آخر جزء من اسم الملف في الرابط.
        basename = url.rsplit("/", 1)[-1].split("?")[0]
        from urllib.parse import unquote
        title = unquote(basename).replace(f".{ext}", "").replace("_", " ").strip() or "ملف مستورد"
    if not year:
        year = datetime.now().year

    db = get_db()
    db.execute(
        """INSERT INTO exam_bank
             (title, subject, stage_id, stream_id, curriculum_id, term, year, description,
              file_path, is_published, created_by_type, created_by_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'admin', ?, ?)""",
        (title, subject, stage_id, stream_id, curriculum_id, term, year, description,
         filename, session["admin_id"], datetime.utcnow().isoformat()),
    )
    db.commit()
    log_security_event("exam_bank_import", f"استيراد بالرابط: {url[:200]}")
    flash(f"تم استيراد «{title}» بنجاح من الرابط.", "success")
    return redirect(url_for("admin_exam_bank"))


@app.route("/admin/exam-bank/<int:exam_id>/toggle", methods=["POST"])
def admin_exam_bank_toggle(exam_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    db.execute(
        "UPDATE exam_bank SET is_published = 1 - is_published WHERE id = ?", (exam_id,)
    )
    db.commit()
    return redirect(url_for("admin_exam_bank"))


@app.route("/admin/exam-bank/<int:exam_id>/delete", methods=["POST"])
def admin_exam_bank_delete(exam_id):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    row = db.execute("SELECT file_path FROM exam_bank WHERE id = ?", (exam_id,)).fetchone()
    if row and row["file_path"]:
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, row["file_path"]))
        except OSError:
            pass
    db.execute("DELETE FROM exam_bank WHERE id = ?", (exam_id,))
    db.commit()
    return redirect(url_for("admin_exam_bank"))


@app.route("/teacher/exam-bank", methods=["GET", "POST"])
def teacher_exam_bank():
    if "teacher_id" not in session:
        return redirect(url_for("teacher_login"))
    db = get_db()

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        if title:
            subject = (request.form.get("subject") or "").strip()
            stage_id = request.form.get("stage_id", type=int)
            stream_id = request.form.get("stream_id", type=int)
            curriculum_id = request.form.get("curriculum_id", type=int)
            term = request.form.get("term", type=int) or 0
            year = request.form.get("year", type=int)
            description = (request.form.get("description") or "").strip()
            file_path = save_exam_file_securely(request.files.get("file"))
            db.execute(
                """INSERT INTO exam_bank
                     (title, subject, stage_id, stream_id, curriculum_id, term, year, description,
                      file_path, is_published, created_by_type, created_by_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'teacher', ?, ?)""",
                (title, subject, stage_id, stream_id, curriculum_id, term, year, description,
                 file_path or "", session["teacher_id"], datetime.utcnow().isoformat()),
            )
            db.commit()
            flash("تمت إضافة الامتحان لبنك الامتحانات.", "success")
        else:
            flash("اكتب عنوان الامتحان الأول.", "danger")

    exams = db.execute(
        """SELECT e.*, s.name stage_name, st.name stream_name, c.name curriculum_name
           FROM exam_bank e
           LEFT JOIN stages s ON s.id = e.stage_id
           LEFT JOIN streams st ON st.id = e.stream_id
           LEFT JOIN curricula c ON c.id = e.curriculum_id
           ORDER BY e.id DESC"""
    ).fetchall()
    stages = db.execute("SELECT * FROM stages ORDER BY sort_order").fetchall()
    streams = db.execute("SELECT * FROM streams ORDER BY sort_order").fetchall()
    curricula = db.execute("SELECT * FROM curricula ORDER BY id").fetchall()
    subjects = db.execute("SELECT * FROM subjects ORDER BY sort_order").fetchall()
    return render_template(
        "teacher_exam_bank.html", exams=exams, stages=stages, streams=streams,
        curricula=curricula, subjects=subjects,
    )


@app.route("/teacher/exam-bank/<int:exam_id>/delete", methods=["POST"])
def teacher_exam_bank_delete(exam_id):
    if "teacher_id" not in session:
        return redirect(url_for("teacher_login"))
    db = get_db()
    row = db.execute(
        "SELECT * FROM exam_bank WHERE id = ? AND created_by_type = 'teacher' AND created_by_id = ?",
        (exam_id, session["teacher_id"]),
    ).fetchone()
    if row:
        if row["file_path"]:
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, row["file_path"]))
            except OSError:
                pass
        db.execute("DELETE FROM exam_bank WHERE id = ?", (exam_id,))
        db.commit()
        flash("تم حذف الامتحان.", "success")
    return redirect(url_for("teacher_exam_bank"))


@app.route("/admin/questions/paper")
def admin_questions_paper():
    """ورقة مطبوعة (A4) بتجمع كل أسئلة المنصة منظمة بالصف ⇒ المادة ⇒ الامتحان.
    الأسئلة مترقمة تسلسليًا، وكل صفحة فيها عنوان ورقم — تنفع تتحفظ PDF أو تطبع.
    للأدمن فقط."""
    if session.get("admin_id") is None:
        return redirect(url_for("admin_login"))
    db = get_db()

    rows = db.execute(
        """SELECT q.id, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d,
                  q.correct_index, a.title assessment_title, a.kind, m.title material_title, m.subject,
                  m.stage_id, st.name stage_name, m.stream
           FROM assessment_questions q
           JOIN assessments a ON a.id = q.assessment_id
           JOIN materials m ON m.id = a.material_id
           LEFT JOIN stages st ON st.id = m.stage_id
           ORDER BY m.stage_id, m.stream, m.subject, a.id, q.sort_order, q.id"""
    ).fetchall()

    # تجميع هرمي: صف ⇒ شعبة ⇒ مادة ⇒ امتحان ⇒ أسئلة.
    stages_map = {}
    for row in rows:
        r = dict(row)
        stage_key = r["stage_id"] or 0
        stage_name = r["stage_name"] or "عام / غير محدد"
        stages_map.setdefault(stage_key, {"name": stage_name, "streams": {}})
        stream = r["stream"] or "عام / غير محدد"
        subj = r["subject"] or "بدون مادة"
        exam_key = r["assessment_title"] or r["material_title"] or "امتحان"
        exams = stages_map[stage_key]["streams"].setdefault(stream, {}).setdefault(subj, {})
        exams.setdefault(exam_key, []).append(r)

    # ترتيب الصفوف حسب الاسم، والشعب، والمواد، وترقيم تسلسلي لكل الأسئلة.
    stages = sorted(stages_map.items(), key=lambda kv: kv[1]["name"])
    total_questions = 0
    for _, st in stages:
        st["streams"] = dict(sorted(st["streams"].items()))
        for stream in st["streams"]:
            st["streams"][stream] = dict(sorted(st["streams"][stream].items()))
            for subj in st["streams"][stream]:
                st["streams"][stream][subj] = dict(sorted(st["streams"][stream][subj].items()))
                for exam in st["streams"][stream][subj].values():
                    for q in exam:
                        total_questions += 1
                        q["number"] = total_questions

    return render_template(
        "admin_questions_paper.html", stages=stages,
        total_questions=total_questions,
        today=datetime.utcnow().strftime("%Y-%m-%d"),
    )


@app.route("/admin/question-bank", methods=["GET", "POST"])
def admin_question_bank():
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    if request.method == "POST":
        text = (request.form.get("question_text") or "").strip()
        if text:
            db.execute(
                """INSERT INTO question_bank
                     (question_text, option_a, option_b, option_c, option_d, correct_index, explanation,
                      stage_id, stream_id, subject_id, curriculum_id, is_published,
                      created_by_type, created_by_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'admin', ?, ?)""",
                (
                    text,
                    (request.form.get("option_a") or "").strip(),
                    (request.form.get("option_b") or "").strip(),
                    (request.form.get("option_c") or "").strip(),
                    (request.form.get("option_d") or "").strip(),
                    int(request.form.get("correct_index") or 0),
                    (request.form.get("explanation") or "").strip(),
                    int(request.form.get("difficulty") or 1),
                    request.form.get("stage_id", type=int),
                    request.form.get("stream_id", type=int),
                    request.form.get("subject_id", type=int),
                    request.form.get("curriculum_id", type=int),
                    session.get("admin_id"),
                    datetime.utcnow().isoformat(),
                ),
            )
            db.commit()
            flash("تمت إضافة السؤال لبنك الأسئلة.", "success")
        else:
            flash("اكتب نص السؤال الأول.", "danger")
    ctx = _question_bank_context(db, ("admin", session.get("admin_id")))
    ctx["page_title"] = "بنك الأسئلة"
    ctx["page_subtitle"] = "كل أسئلة المنصة منظمة بالصف والشعبة والمادة والنظام."
    return render_template("admin_question_bank.html", **ctx)


def _question_bank_context(db, actor):
    """بيانات مشتركة لصفحة بنك الأسئلة: الفلاتر + القايمات + الأسئلة.
    actor = 'admin' أو 'teacher' مع معرف الحساب عشان العرض/الفلاتر."""
    role, actor_id = actor
    q_subject = request.args.get("subject_id", type=int)
    q_stage = request.args.get("stage_id", type=int)
    q_stream = request.args.get("stream_id", type=int)
    q_curriculum = request.args.get("curriculum_id", type=int)
    q_difficulty = request.args.get("difficulty", type=int)

    stages = db.execute("SELECT * FROM stages ORDER BY sort_order").fetchall()
    streams = db.execute("SELECT * FROM streams ORDER BY sort_order").fetchall()
    curricula = db.execute("SELECT * FROM curricula ORDER BY id").fetchall()
    subjects = db.execute("SELECT * FROM subjects ORDER BY sort_order").fetchall()

    query = """SELECT q.*, st.name stage_name, sm.name stream_name,
                      su.name subject_name, c.name curriculum_name
               FROM question_bank q
               LEFT JOIN stages st ON st.id = q.stage_id
               LEFT JOIN streams sm ON sm.id = q.stream_id
               LEFT JOIN subjects su ON su.id = q.subject_id
               LEFT JOIN curricula c ON c.id = q.curriculum_id
               WHERE 1=1"""
    params = []
    if q_subject:
        query += " AND q.subject_id = ?"
        params.append(q_subject)
    if q_stage:
        query += " AND q.stage_id = ?"
        params.append(q_stage)
    if q_stream:
        query += " AND q.stream_id = ?"
        params.append(q_stream)
    if q_curriculum:
        query += " AND q.curriculum_id = ?"
        params.append(q_curriculum)
    if q_difficulty:
        query += " AND q.difficulty = ?"
        params.append(q_difficulty)
    if role == "teacher":
        query += " AND q.created_by_type = 'teacher' AND q.created_by_id = ?"
        params.append(actor_id)
    query += " ORDER BY q.id DESC LIMIT 200"
    questions = db.execute(query, params).fetchall()

    return {
        "questions": questions,
        "stages": stages, "streams": streams,
        "curricula": curricula, "subjects": subjects,
        "q_subject": q_subject, "q_stage": q_stage,
        "q_stream": q_stream, "q_curriculum": q_curriculum,
        "q_difficulty": q_difficulty,
    }


@app.route("/admin/question-bank/<int:qid>/toggle", methods=["POST"])
def admin_question_bank_toggle(qid):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    db.execute("UPDATE question_bank SET is_published = 1 - is_published WHERE id = ?", (qid,))
    db.commit()
    return redirect(url_for("admin_question_bank"))


@app.route("/admin/question-bank/<int:qid>/delete", methods=["POST"])
def admin_question_bank_delete(qid):
    if "admin_id" not in session:
        return redirect(url_for("admin_login"))
    db = get_db()
    db.execute("DELETE FROM daily_set_questions WHERE question_id = ?", (qid,))
    db.execute("DELETE FROM question_bank WHERE id = ?", (qid,))
    db.commit()
    flash("تم حذف السؤال.", "success")
    return redirect(url_for("admin_question_bank"))


@app.route("/teacher/question-bank", methods=["GET", "POST"])
def teacher_question_bank():
    if "teacher_id" not in session:
        return redirect(url_for("teacher_login"))
    db = get_db()
    teacher_id = session["teacher_id"]
    if request.method == "POST":
        text = (request.form.get("question_text") or "").strip()
        if text:
            db.execute(
                 """INSERT INTO question_bank
                      (question_text, option_a, option_b, option_c, option_d, correct_index, explanation,
                       difficulty, stage_id, stream_id, subject_id, curriculum_id, is_published,
                       created_by_type, created_by_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'teacher', ?, ?)""",
                (
                    text,
                    (request.form.get("option_a") or "").strip(),
                    (request.form.get("option_b") or "").strip(),
                    (request.form.get("option_c") or "").strip(),
                    (request.form.get("option_d") or "").strip(),
                    int(request.form.get("correct_index") or 0),
                    (request.form.get("explanation") or "").strip(),
                    int(request.form.get("difficulty") or 1),
                    request.form.get("stage_id", type=int),
                    request.form.get("stream_id", type=int),
                    request.form.get("subject_id", type=int),
                    request.form.get("curriculum_id", type=int),
                    teacher_id,
                    datetime.utcnow().isoformat(),
                ),
            )
            db.commit()
            flash("تمت إضافة السؤال لبنك الأسئلة.", "success")
        else:
            flash("اكتب نص السؤال الأول.", "danger")
    ctx = _question_bank_context(db, ("teacher", teacher_id))
    ctx["page_title"] = "بنك الأسئلة"
    ctx["page_subtitle"] = "أسئلتك اللي ضفتها في بنك الأسئلة — بيشتغل بيها طلابك في لمية اليوم."
    return render_template("teacher_question_bank.html", **ctx)


@app.route("/teacher/question-bank/<int:qid>/delete", methods=["POST"])
def teacher_question_bank_delete(qid):
    if "teacher_id" not in session:
        return redirect(url_for("teacher_login"))
    db = get_db()
    row = db.execute(
        "SELECT * FROM question_bank WHERE id = ? AND created_by_type = 'teacher' AND created_by_id = ?",
        (qid, session["teacher_id"]),
    ).fetchone()
    if row:
        db.execute("DELETE FROM daily_set_questions WHERE question_id = ?", (qid,))
        db.execute("DELETE FROM question_bank WHERE id = ?", (qid,))
        db.commit()
        flash("تم حذف السؤال.", "success")
    return redirect(url_for("teacher_question_bank"))


if __name__ == "__main__":
    init_db()
    with app.app_context():
        run_daily_backup_if_needed()
    # تشغيل على الشبكة كلها (0.0.0.0) عشان أي جهاز على نفس الشبكة يفتح المنصة
    # من رابط IP الكمبيوتر ده. waitress = سيرفر إنتاجي سريع وآمن على ويندوز
    # (أحسن من flask run بتاع التطوير).
    try:
        from waitress import serve
        # 24 خيط عشان 100 طالب شغالين مع بعض - SQLite بـ WAL بيسمح بالقراءات
        # المتوازية، والكتابات بتيجي كتيرة بس كلها صغيرة.
        serve(app, host="0.0.0.0", port=5000, threads=24)
    except ImportError:
        app.run(host="0.0.0.0", port=5000, debug=False)
else:
    init_db()
