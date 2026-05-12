import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'os_analyzer.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS OStargets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                appname TEXT NOT NULL,
                accesskey TEXT UNIQUE NOT NULL,
                createdate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                error TEXT,
                status INT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS AIcache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                problem_key TEXT UNIQUE NOT NULL,
                response TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

def get_scanhistory_items():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT domain, AppName, Accesskey, createDate FROM OSTargets ORDER BY createdate DESC")
        return cursor.fetchall()

def delete_scanhistory_item(accesskey: str) -> bool:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM OSTargets WHERE Accesskey = ?", (accesskey,))
            conn.commit()
            return True
    except Exception as e:
        print(f"Erro ao deletar item: {e}")
        return False

def clear_all_scanhistory() -> bool:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM OSTargets")
            conn.commit()
            return True
    except Exception as e:
        print(f"Erro ao limpar histórico: {e}")
        return False

def ai_get_cached_response(problem_key: str):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT response FROM AIcache WHERE problem_key = ?", (problem_key,))
        row = cursor.fetchone()
        return row[0] if row else None

def ai_save_cache(problem_key: str, response: str) -> bool:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO AIcache (problem_key, response) VALUES (?, ?)", 
                (problem_key, response)
            )
            conn.commit()
            return True
    except sqlite3.Error as e:
        print(f"Erro ao salvar cache: {e}")
        return False

def ai_clear_cache() -> bool:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM AIcache")
            conn.commit()
            return True
    except Exception as e:
        print(f"Erro ao limpar cache: {e}")
        return False

def db_insert_targetinformations(domain: str, subdomain: str, app_name: str, access_key: str, status: int = 1) -> bool:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO OStargets 
                (domain, subdomain, AppName, accesskey, status) 
                VALUES (?, ?, ?, ?, ?)
            ''', (domain, subdomain, app_name, access_key, status))
            conn.commit()
            return True
    except Exception as e:
        print(f"Erro ao inserir alvo no banco: {e}")
        return False