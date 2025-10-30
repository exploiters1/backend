import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def test_supabase():
    try:
        conn = psycopg2.connect(
            host=os.environ.get("DB_HOST"),
            database=os.environ.get("DB_NAME"),
            user=os.environ.get("DB_USER"),
            password=os.environ.get("DB_PASS"),
            port=os.environ.get("DB_PORT"),
            sslmode="require"
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        print("✅ Supabase connected successfully!")
        print(f"PostgreSQL: {cursor.fetchone()[0]}")
        
        # Test tables
        cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
        tables = cursor.fetchall()
        print("📊 Tables found:", [table[0] for table in tables])
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")

if __name__ == "__main__":
    test_supabase()