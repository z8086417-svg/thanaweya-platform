# ============================================================
# Dockerfile - تشغيل المنصة في Container جاهز للاستضافة
# ------------------------------------------------------------
# للبناء:  docker build -t thanaweya-platform .
# للتشغيل: docker run -p 5000:5000 thanaweya-platform
# ============================================================

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# مجلدات الملفات المرفوعة والنسخ الاحتياطية
RUN mkdir -p /app/uploads/videos /app/backups

# المنصة شغالة على port 5000 (Flask/Gunicorn)
EXPOSE 5000

# Gunicorn: سيرفر إنتاج حقيقي بدل Flask dev server.
# لو مش شغال gunicorn على ويندوز، شغّل `python app.py` محليًا.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
