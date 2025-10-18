import mysql.connector

try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="your_mysql_password",
        database="encryptedmed"
    )
    print("✅ Connected to MySQL successfully!")
except mysql.connector.Error as err:
    print("❌ Error:", err)
finally:
    if 'conn' in locals() and conn.is_connected():
        conn.close()
