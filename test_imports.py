try:
    import psycopg2
    import flask
    import bcrypt
    from Crypto.Cipher import AES
    print("✅ All imports successful!")
except ImportError as e:
    print(f"❌ Import error: {e}")