# app.py
from app import create_app

# ایجاد و اجرای اپلیکیشن Flask
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
