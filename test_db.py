import os
import sqlite3
import pymysql

db_backend = os.getenv("DB_BACKEND", "sqlite").strip().lower()

if db_backend == "mysql":
    try:
        connection = pymysql.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", "root"),
            database=os.getenv("DB_NAME", "quizapp"),
            port=int(os.getenv("DB_PORT", "3306")),
        )
        print("Database connected successfully! (MySQL)")
        connection.close()
    except Exception as e:
        print(f"MySQL connection failed: {e}")
else:
    try:
        db_path = os.getenv("SQLITE_DB_PATH", "quizapp.db")
        connection = sqlite3.connect(db_path)
        connection.execute("SELECT 1")
        print(f"Database connected successfully! (SQLite: {db_path})")
        connection.close()
    except Exception as e:
        print(f"SQLite connection failed: {e}")
