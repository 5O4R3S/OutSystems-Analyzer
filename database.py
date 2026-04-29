import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'os_analyzer.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    
    conn = get_connection()
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
    conn.close()

def get_scanhistory_items():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT domain, AppName, Accesskey, createDate FROM OSTargets ORDER BY createdate DESC")
    rows = cursor.fetchall()

    conn.close()
    return rows

def delete_scanhistory_item(accesskey: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM OSTargets WHERE Accesskey = ?", (accesskey,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Erro ao deletar item: {e}")
        return False
    finally:
        conn.close()

def clear_all_scanhistory() -> bool:

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM OSTargets")
        conn.commit()
        return True
    except Exception as e:
        print(f"Erro ao limpar histórico: {e}")
        return False
    finally:
        conn.close()

def ai_get_cached_response(problem_key: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT response FROM AIcache WHERE problem_key = ?", (problem_key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def ai_save_cache(problem_key: str, response: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    success = False
    try:
        cursor.execute(
            "INSERT INTO AIcache (problem_key, response) VALUES (?, ?)", 
            (problem_key, response)
        )
        conn.commit()
        success = True
    except sqlite3.Error as e:
        print(f"Erro ao salvar cache: {e}")
        success = False
    finally:
        conn.close()
    return success

def ai_clear_cache() -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    success = False
    try:
        cursor.execute("DELETE FROM AIcache")
        conn.commit()
        success = True
    except Exception as e:
        print(f"Erro ao limpar cache: {e}")
        success = False
    finally:
        conn.close()
    return success