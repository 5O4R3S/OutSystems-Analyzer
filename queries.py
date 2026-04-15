from database import get_connection

def db_insert_targetinformations(domain: str, subdomain: str, app_name: str, access_key: str, status: int = 1) -> bool:
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO OStargets 
            (domain, subdomain, AppName, accesskey, status) 
            VALUES (?, ?, ?, ?, ?)
        ''', (domain, subdomain, app_name, access_key, status))
        
        conn.commit()
        conn.close()
        return True
    
    except Exception as e:
        print(f"Erro ao inserir alvo no banco: {e}")
        if conn:
            conn.close()
        return False