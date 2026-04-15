import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'os_analyzer.db')

def get_connection():
    """Retorna uma conexão ao banco (cria o arquivo se não existir)"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Cria o banco e a tabela se não existirem"""
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