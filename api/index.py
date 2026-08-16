import sys
from pathlib import Path

# إضافة المجلد الرئيسي للمسارات لضمان رؤية app.py
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app import app
