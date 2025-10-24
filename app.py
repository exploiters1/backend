# app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import bcrypt
import os
import json
from datetime import datetime, timedelta, date
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import secrets

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ---------------- CONFIG ----------------
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# AES configuration:
# Provide AES_KEY as env var (16, 24 or 32 bytes). Optional AES_FALLBACK_IV for legacy ciphertexts (16 bytes)
AES_KEY = os.environ.get("AES_KEY", "ThisIsASecretKey")  # default 16 chars but set env in prod
AES_FALLBACK_IV = os.environ.get("AES_FALLBACK_IV")     # optional, used only for backward compatibility

if len(AES_KEY) not in (16, 24, 32):
    raise ValueError(f"AES_KEY must be 16, 24, or 32 bytes long, got {len(AES_KEY)}")
if AES_FALLBACK_IV is not None and len(AES_FALLBACK_IV) != 16:
    raise ValueError(f"AES_FALLBACK_IV must be 16 bytes long if provided, got {len(AES_FALLBACK_IV)}")

AES_KEY_BYTES = AES_KEY.encode("utf-8")

# fields in users table considered sensitive and encrypted at-rest:
SENSITIVE_PROFILE_FIELDS = ["phone_number", "address", "city", "pincode", "state"]

# ---------------- AES HELPERS ----------------
def encrypt_data(plaintext: str) -> str:
    """
    Encrypt plaintext using AES-CBC with a random IV.
    Returns base64(iv + ciphertext) string.
    """
    if plaintext is None:
        return ""
    iv = secrets.token_bytes(16)
    cipher = AES.new(AES_KEY_BYTES, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    combined = iv + ct_bytes
    return base64.b64encode(combined).decode("utf-8")

def decrypt_data(ciphertext: str) -> str:
    """
    Decrypt ciphertext produced by encrypt_data.
    Handles two cases:
     - new format: base64(iv + ct)
     - fallback format: base64(ct) that was encrypted with a static IV (AES_FALLBACK_IV)
    If decryption fails returns empty string.
    """
    try:
        if not ciphertext:
            return ""
        # fix base64 padding
        missing_padding = len(ciphertext) % 4
        if missing_padding:
            ciphertext += "=" * (4 - missing_padding)
        combined = base64.b64decode(ciphertext)
        if len(combined) > 16:
            # assume first 16 bytes are IV
            iv = combined[:16]
            ct = combined[16:]
            cipher = AES.new(AES_KEY_BYTES, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode("utf-8")
        else:
            # combined too short to contain IV+ct: try fallback static IV if provided
            if AES_FALLBACK_IV:
                cipher = AES.new(AES_KEY_BYTES, AES.MODE_CBC, AES_FALLBACK_IV.encode("utf-8"))
                pt = unpad(cipher.decrypt(combined), AES.block_size)
                return pt.decode("utf-8")
            # else fail
            return ""
    except Exception as e:
        # final fallback attempt with AES_FALLBACK_IV
        try:
            if AES_FALLBACK_IV:
                missing_padding = len(ciphertext) % 4
                if missing_padding:
                    ciphertext += "=" * (4 - missing_padding)
                ct = base64.b64decode(ciphertext)
                cipher = AES.new(AES_KEY_BYTES, AES.MODE_CBC, AES_FALLBACK_IV.encode("utf-8"))
                pt = unpad(cipher.decrypt(ct), AES.block_size)
                return pt.decode("utf-8")
        except Exception:
            pass
        print("Decryption error:", e)
        return ""

# ---------------- DATABASE ----------------
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            user=os.environ.get("DB_USER", "root"),
            password=os.environ.get("DB_PASS", ""),
            database=os.environ.get("DB_NAME", "encryptedmed")
        )
        return conn
    except Error as e:
        print(f"DB Connection Error: {e}")
        return None

# ---------------- ROOT ----------------
@app.route("/")
def home():
    return jsonify({"message": "Flask backend running ✅"})

# ---------------- REGISTER / LOGIN ----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")
    specialization = data.get("specialization", "")

    if not name or not email or not password or role not in ["doctor", "patient"]:
        return jsonify({"error": "Invalid input"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "User already exists"}), 400

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (name,email,password,role,specialization) VALUES (%s,%s,%s,%s,%s)",
            (name, email, hashed_pw.decode("utf-8"), role, specialization)
        )
        conn.commit()
        return jsonify({"message": f"{role.capitalize()} registered successfully ✅"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")

    if not email or not password or role not in ["doctor", "patient"]:
        return jsonify({"error": "Invalid input"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email=%s AND role=%s", (email, role))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
            return jsonify({"error": "Incorrect password"}), 401

        return jsonify({
            "message": "Login successful ✅",
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
                "specialization": user.get("specialization", "")
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ---------------- ADMIN ----------------
@app.route("/admin/register", methods=["POST"])
def admin_register():
    data = request.get_json() or {}
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    hospital_name = data.get("hospital_name")
    hospital_address = data.get("hospital_address")

    if not all([name, email, password, hospital_name, hospital_address]):
        return jsonify({"error": "Missing required fields"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500

    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM admins WHERE email=%s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "Admin already exists"}), 400

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO admins (name, email, password, hospital_name, hospital_address) VALUES (%s,%s,%s,%s,%s)",
            (name, email, hashed_pw.decode("utf-8"), hospital_name, hospital_address)
        )
        conn.commit()
        return jsonify({"message": "Admin registered successfully ✅"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM admins WHERE email=%s", (email,))
        admin = cursor.fetchone()
        if not admin:
            return jsonify({"error": "Admin not found"}), 404

        if not bcrypt.checkpw(password.encode("utf-8"), admin["password"].encode("utf-8")):
            return jsonify({"error": "Incorrect password"}), 401

        return jsonify({
            "message": "Login successful ✅",
            "admin": {
                "id": admin["id"],
                "name": admin["name"],
                "email": admin["email"],
                "hospital_name": admin["hospital_name"],
                "hospital_address": admin["hospital_address"]
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/admin/forgot-password", methods=["POST"])
def admin_forgot_password():
    import random
    import string

    data = request.get_json() or {}
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM admins WHERE email=%s", (email,))
        admin = cursor.fetchone()
        if not admin:
            return jsonify({"error": "Admin not found"}), 404

        # Generate a temporary password or token
        temp_password = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        hashed_pw = bcrypt.hashpw(temp_password.encode("utf-8"), bcrypt.gensalt())

        # Update admin password in DB
        cursor.execute("UPDATE admins SET password=%s WHERE email=%s", (hashed_pw.decode("utf-8"), email))
        conn.commit()

        # TODO: Send temp_password via email (using SMTP or email service)
        print(f"[DEBUG] Temporary password for {email}: {temp_password}")

        return jsonify({"message": "Temporary password sent to your email ✅"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ---------------- USERS ----------------
@app.route("/doctors", methods=["GET"])
def get_all_doctors():
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, name, email, specialization FROM users WHERE role='doctor'")
        doctors = cursor.fetchall()
        return jsonify(doctors)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/patients", methods=["GET"])
def get_all_patients():
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, name, email, age, weight FROM users WHERE role='patient'")
        patients = cursor.fetchall()
        return jsonify(patients)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ---------------- PROFILE ----------------
@app.route("/profile/<role>/<int:user_id>", methods=["GET", "PUT"])
def profile(role, user_id):
    if role not in ["doctor", "patient"]:
        return jsonify({"error": "Invalid role"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)

    if request.method == "GET":
        try:
            cursor.execute("SELECT * FROM users WHERE id=%s AND role=%s", (user_id, role))
            user = cursor.fetchone()
            if not user:
                return jsonify({"error": f"{role.capitalize()} not found"}), 404
            # decrypt sensitive profile fields if they exist
            for f in SENSITIVE_PROFILE_FIELDS:
                if user.get(f):
                    try:
                        user[f] = decrypt_data(user[f])
                    except Exception:
                        pass
            if user.get("profile_pic"):
                user["profile_pic_url"] = f"{request.host_url}uploads/{user['profile_pic']}"
            if user.get("signature"):
                user["signature_url"] = f"{request.host_url}uploads/{user['signature']}"
            return jsonify(user)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    # ---- PUT (Update) ----
    try:
        form = request.form
        profile_pic_file = request.files.get("profile_pic")
        signature_file = request.files.get("signature")

        updates = []
        values = []

        # fields that we will accept and possibly encrypt before storing
        allowed_fields = ["name", "email", "specialization", "age", "weight",
                          "phone_number", "address", "city", "pincode", "state", "date_of_birth"]

        for field in allowed_fields:
            if form.get(field) is not None:
                val = form.get(field)
                # encrypt sensitive fields at rest
                if field in SENSITIVE_PROFILE_FIELDS and val != "":
                    val = encrypt_data(val)
                updates.append(f"{field}=%s")
                values.append(val)

        # Auto-calc age from DOB (age stored plaintext)
        dob_str = form.get("date_of_birth")
        if dob_str:
            try:
                dob_date = datetime.strptime(dob_str, "%Y-%m-%d").date()
                today = date.today()
                calculated_age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
                updates.append("age=%s")
                values.append(calculated_age)
            except Exception:
                pass

        if profile_pic_file:
            filename = f"profile_{user_id}_{secure_filename(profile_pic_file.filename)}"
            profile_pic_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            updates.append("profile_pic=%s")
            values.append(filename)
        if signature_file:
            filename = f"signature_{user_id}_{secure_filename(signature_file.filename)}"
            signature_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            updates.append("signature=%s")
            values.append(filename)

        if updates:
            sql = f"UPDATE users SET {', '.join(updates)} WHERE id=%s AND role=%s"
            values.extend([user_id, role])
            cursor.execute(sql, tuple(values))
            conn.commit()

        return jsonify({"message": f"{role.capitalize()} profile updated successfully ✅"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ---------------- PATIENT RECORDS ----------------
@app.route("/patient-records/<int:patient_id>", methods=["GET"])
def get_patient_records(patient_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT pr.*, u.name AS doctor_name
            FROM patient_records pr
            JOIN users u ON pr.doctor_id=u.id
            WHERE pr.patient_id=%s
        """, (patient_id,))
        records = cursor.fetchall()

        for r in records:
            if r.get("scan_report"):
                decrypted = decrypt_data(r["scan_report"])
                try:
                    data = json.loads(decrypted)
                    r["past_diseases"] = data.get("past_diseases", "")
                    r["current_condition"] = data.get("current_condition", "")
                    r["scan_report"] = data.get("scan_report", None)
                except Exception:
                    r["past_diseases"] = ""
                    r["current_condition"] = ""
                    r["scan_report"] = None
            else:
                r["past_diseases"] = ""
                r["current_condition"] = ""
                r["scan_report"] = None

        return jsonify(records)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/patient-records", methods=["POST"])
def add_patient_record():
    try:
        patient_id = request.form.get("patient_id")
        doctor_id = request.form.get("doctor_id")
        past_diseases = request.form.get("past_diseases", "")
        current_condition = request.form.get("current_condition", "")
        scan_file = request.files.get("scan_report")

        if not patient_id or not doctor_id:
            return jsonify({"error": "Missing patient_id or doctor_id"}), 400

        scan_filename = None
        if scan_file:
            scan_filename = f"scan_{doctor_id}_{secure_filename(scan_file.filename)}"
            scan_file.save(os.path.join(app.config["UPLOAD_FOLDER"], scan_filename))

        record_content = json.dumps({
            "past_diseases": past_diseases,
            "current_condition": current_condition,
            "scan_report": scan_filename
        })
        encrypted_record = encrypt_data(record_content)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO patient_records
                (patient_id, doctor_id, scan_report)
                VALUES (%s,%s,%s)
            """, (patient_id, doctor_id, encrypted_record))
            conn.commit()
            return jsonify({"message": "Patient record added successfully ✅"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/patient-records/<int:record_id>", methods=["PUT"])
def update_patient_record(record_id):
    try:
        doctor_id = request.form.get("doctor_id")
        past_diseases = request.form.get("past_diseases", "")
        current_condition = request.form.get("current_condition", "")
        scan_file = request.files.get("scan_report")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM patient_records WHERE id=%s", (record_id,))
            record = cursor.fetchone()
            if not record:
                return jsonify({"error": "Record not found"}), 404
            if int(record["doctor_id"]) != int(doctor_id):
                return jsonify({"error": "You can only modify your own records"}), 403

            existing_data = {}
            if record["scan_report"]:
                decrypted = decrypt_data(record["scan_report"])
                try:
                    existing_data = json.loads(decrypted)
                except Exception:
                    existing_data = {}

            scan_filename = existing_data.get("scan_report")
            if scan_file:
                scan_filename = f"scan_{doctor_id}_{secure_filename(scan_file.filename)}"
                scan_file.save(os.path.join(app.config["UPLOAD_FOLDER"], scan_filename))

            record_content = json.dumps({
                "past_diseases": past_diseases,
                "current_condition": current_condition,
                "scan_report": scan_filename
            })
            encrypted_record = encrypt_data(record_content)

            cursor.execute("""
                UPDATE patient_records
                SET scan_report=%s, updated_at=NOW()
                WHERE id=%s
            """, (encrypted_record, record_id))
            conn.commit()
            return jsonify({"message": "Record updated successfully ✅"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- PRESCRIPTIONS ----------------
@app.route("/save", methods=["POST"])
def save_prescription():
    try:
        data = request.get_json() or {}
        doctor_id = data.get("doctor_id")
        doctor_name = data.get("doctor_name")
        patient_id = data.get("patient_id")
        patient_name = data.get("patient_name")
        patient_age = data.get("patient_age")
        patient_weight = data.get("patient_weight")
        prescription = data.get("prescription", "")
        medicines = data.get("medicines", [])
        notes = data.get("notes", "")
        issue_date = datetime.now().strftime("%Y-%m-%d")
        validity_days = data.get("validity_days", 30)

        if not all([doctor_id, patient_id, prescription]):
            return jsonify({"error": "Missing required data"}), 400

        prescription_content = json.dumps({
            "prescription": prescription,
            "medicines": medicines,
            "notes": notes,
            "issue_date": issue_date,
            "validity_days": validity_days
        })
        encrypted_prescription = encrypt_data(prescription_content)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO prescriptions (
                    doctor_id, doctor_name, patient_id, patient_name, patient_age, patient_weight,
                    encrypted_data, created_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())
            """, (
                doctor_id, doctor_name, patient_id, patient_name, patient_age, patient_weight,
                encrypted_prescription
            ))
            conn.commit()
            new_id = cursor.lastrowid
            return jsonify({"message": "Prescription saved successfully ✅", "id": new_id}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/prescriptions/patient/<int:patient_id>", methods=["GET"])
def get_prescriptions(patient_id):
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "DB connection failed"}), 500
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT * FROM prescriptions
                WHERE patient_id=%s
                ORDER BY created_at DESC
            """, (patient_id,))
            rows = cursor.fetchall()

            prescriptions = []
            for r in rows:
                decrypted = decrypt_data(r.get("encrypted_data", ""))
                try:
                    data = json.loads(decrypted)
                except Exception:
                    data = {}
                created_at_val = r.get("created_at")
                created_at_str = created_at_val.strftime("%Y-%m-%d %H:%M:%S") if isinstance(created_at_val, datetime) else (created_at_val or "")
                prescriptions.append({
                    "id": r.get("id"),
                    "doctor_id": r.get("doctor_id"),
                    "doctor_name": r.get("doctor_name"),
                    "patient_id": r.get("patient_id"),
                    "patient_name": r.get("patient_name"),
                    "patient_age": r.get("patient_age"),
                    "patient_weight": r.get("patient_weight"),
                    "prescription": data.get("prescription", ""),
                    "medicines": data.get("medicines", []),
                    "notes": data.get("notes", ""),
                    "issue_date": data.get("issue_date", ""),
                    "validity_days": data.get("validity_days", 30),
                    "created_at": created_at_str
                })

            return jsonify(prescriptions)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/prescriptions/<int:prescription_id>", methods=["GET"])
def get_prescription_by_id(prescription_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM prescriptions WHERE id=%s", (prescription_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Prescription not found"}), 404

        decrypted = decrypt_data(row.get("encrypted_data", ""))
        try:
            data = json.loads(decrypted)
        except Exception:
            data = {}

        created_at_val = row.get("created_at")
        created_at_str = created_at_val.strftime("%Y-%m-%d %H:%M:%S") if isinstance(created_at_val, datetime) else (created_at_val or "")

        prescription = {
            "id": row.get("id"),
            "doctor_id": row.get("doctor_id"),
            "doctor_name": row.get("doctor_name"),
            "patient_id": row.get("patient_id"),
            "patient_name": row.get("patient_name"),
            "patient_age": row.get("patient_age"),
            "patient_weight": row.get("patient_weight"),
            "prescription": data.get("prescription", ""),
            "medicines": data.get("medicines", []),
            "notes": data.get("notes", ""),
            "issue_date": data.get("issue_date", ""),
            "validity_days": data.get("validity_days", 30),
            "created_at": created_at_str
        }

        return jsonify(prescription)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/dashboard/doctor/<int:doctor_id>", methods=["GET"])
def doctor_dashboard(doctor_id):
    """
    Returns a dashboard summary for the doctor:
      - today's visits count
      - prescriptions today count
      - last attended patients list
      - hospital info (if admin)
    """
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        today_str = date.today().strftime("%Y-%m-%d")

        # ---------------- Today's Visits ----------------
        cursor.execute("""
            SELECT COUNT(*) AS visits_today
            FROM appointments
            WHERE doctor_id=%s AND DATE(date)=%s AND status='accepted'
        """, (doctor_id, today_str))
        visits_today = cursor.fetchone().get("visits_today", 0)

        # ---------------- Prescriptions Today ----------------
        cursor.execute("""
            SELECT COUNT(*) AS prescriptions_today
            FROM prescriptions
            WHERE doctor_id=%s AND DATE(created_at)=%s
        """, (doctor_id, today_str))
        prescriptions_today = cursor.fetchone().get("prescriptions_today", 0)

        # ---------------- Last Attended Patients ----------------
        cursor.execute("""
            SELECT 
                p.id AS patient_id,
                p.name AS name,
                MAX(pr.created_at) AS last_prescription_time,
                DATE(MAX(pr.created_at)) AS last_visit_date
            FROM prescriptions pr
            JOIN users p ON pr.patient_id = p.id
            WHERE pr.doctor_id = %s
            GROUP BY p.id, p.name
            ORDER BY last_prescription_time DESC
            LIMIT 10
        """, (doctor_id,))
        patients = cursor.fetchall()

        # Format datetime to string
        for p in patients:
            if isinstance(p.get("last_prescription_time"), datetime):
                p["last_prescription_time"] = p["last_prescription_time"].strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(p.get("last_visit_date"), (datetime, date)):
                p["last_visit_date"] = p["last_visit_date"].strftime("%Y-%m-%d")

        # ---------------- Hospital Info ----------------
        cursor.execute("""
            SELECT hospital_name, hospital_address
            FROM admins
            WHERE id=%s
        """, (doctor_id,))  # if admin id = doctor_id; otherwise you can hardcode admin ID
        admin_info = cursor.fetchone() or {"hospital_name": "", "hospital_address": ""}

        return jsonify({
            "visits_today": visits_today,
            "prescriptions_today": prescriptions_today,
            "last_attended_patients": patients,
            "hospital_name": admin_info.get("hospital_name", ""),
            "hospital_address": admin_info.get("hospital_address", "")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ---------------- APPOINTMENTS ----------------
@app.route("/appointments", methods=["GET", "POST"])
def appointments():
    # POST: add new appointment; GET: query by patient_id or doctor_id (query params)
    if request.method == "POST":
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "DB connection failed"}), 500
        cursor = conn.cursor()
        try:
            data = request.get_json() or {}
            patient_id = data.get("patient_id")
            doctor_id = data.get("doctor_id")
            date_str = data.get("date")
            time_str = data.get("time")
            reason = data.get("reason", "")

            if not all([patient_id, doctor_id, date_str, time_str]):
                return jsonify({"error": "Missing required appointment data"}), 400

            # Validate date
            try:
                app_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                if app_date < date.today():
                    return jsonify({"error": "Appointment date cannot be in the past"}), 400
            except ValueError:
                return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

            cursor.execute("""
                INSERT INTO appointments (patient_id, doctor_id, date, time, reason, status, created_at)
                VALUES (%s, %s, %s, %s, %s, 'pending', NOW())
            """, (patient_id, doctor_id, date_str, time_str, reason))
            conn.commit()
            new_id = cursor.lastrowid
            return jsonify({"message": "Appointment booked successfully ✅", "id": new_id}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    # GET
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        patient_id = request.args.get("patient_id")
        doctor_id = request.args.get("doctor_id")

        query = """
            SELECT a.id, a.date, a.time, a.status,
                   d.name AS doctor_name, p.name AS patient_name, a.reason
            FROM appointments a
            JOIN users d ON a.doctor_id = d.id
            JOIN users p ON a.patient_id = p.id
        """
        conditions = []
        values = []

        if patient_id:
            conditions.append("a.patient_id=%s")
            values.append(patient_id)
        if doctor_id:
            conditions.append("a.doctor_id=%s")
            values.append(doctor_id)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY a.date DESC, a.time DESC"

        cursor.execute(query, tuple(values))
        appointments = cursor.fetchall()

        # Serialize date/time
        for a in appointments:
            if isinstance(a.get("date"), (datetime, date)):
                a["date"] = a["date"].strftime("%Y-%m-%d")
            if isinstance(a.get("time"), (datetime, timedelta)):
                if isinstance(a["time"], timedelta):
                    total_seconds = a["time"].total_seconds()
                    hours = int(total_seconds // 3600)
                    minutes = int((total_seconds % 3600) // 60)
                    seconds = int(total_seconds % 60)
                    a["time"] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                else:
                    a["time"] = a["time"].strftime("%H:%M:%S")

        return jsonify(appointments)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Convenience path-style route (some clients expect /appointments/patient/<id>)
@app.route("/appointments/patient/<int:patient_id>", methods=["GET"])
def appointments_by_patient_path(patient_id):
    # Delegate to the same query logic by calling the GET with query param
    with get_db_connection() as conn:
        # MySQLConnection doesn't support context manager in some versions; handle manually
        pass
    # Simpler: just call the query logic directly
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        query = """
            SELECT a.id, a.date, a.time, a.status,
                   d.name AS doctor_name, p.name AS patient_name, a.reason
            FROM appointments a
            JOIN users d ON a.doctor_id = d.id
            JOIN users p ON a.patient_id = p.id
            WHERE a.patient_id=%s
            ORDER BY a.date DESC, a.time DESC
        """
        cursor.execute(query, (patient_id,))
        appointments = cursor.fetchall()

        for a in appointments:
            if isinstance(a.get("date"), (datetime, date)):
                a["date"] = a["date"].strftime("%Y-%m-%d")
            if isinstance(a.get("time"), (datetime, timedelta)):
                if isinstance(a["time"], timedelta):
                    total_seconds = a["time"].total_seconds()
                    hours = int(total_seconds // 3600)
                    minutes = int((total_seconds % 3600) // 60)
                    seconds = int(total_seconds % 60)
                    a["time"] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                else:
                    a["time"] = a["time"].strftime("%H:%M:%S")

        return jsonify(appointments)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Update appointment status (accept/reject/pending)
@app.route("/appointments/<int:appointment_id>/status", methods=["PUT"])
def update_appointment_status(appointment_id):
    data = request.get_json() or {}
    status = data.get("status")
    if status not in ["pending", "accepted", "rejected"]:
        return jsonify({"error": "Invalid status"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE appointments SET status=%s WHERE id=%s", (status, appointment_id))
        conn.commit()
        return jsonify({"message": f"Appointment status updated to {status} ✅"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Delete appointment (cancel)
@app.route("/appointments/<int:appointment_id>", methods=["DELETE"])
def delete_appointment(appointment_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM appointments WHERE id=%s", (appointment_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Appointment not found"}), 404
        return jsonify({"message": "Appointment cancelled successfully ✅"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/appointments/doctor/<int:doctor_id>", methods=["GET"])
def get_appointments_by_doctor(doctor_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT a.id, a.date, a.time, a.status, a.reason,
                   d.name AS doctor_name, p.name AS patient_name
            FROM appointments a
            JOIN users d ON a.doctor_id = d.id
            JOIN users p ON a.patient_id = p.id
            WHERE a.doctor_id=%s
            ORDER BY a.date DESC, a.time DESC
        """, (doctor_id,))
        appointments = cursor.fetchall()

        for a in appointments:
            if isinstance(a.get("date"), (datetime, date)):
                a["date"] = a["date"].strftime("%Y-%m-%d")
            if isinstance(a.get("time"), (datetime, timedelta)):
                if isinstance(a["time"], timedelta):
                    total_seconds = a["time"].total_seconds()
                    hours = int(total_seconds // 3600)
                    minutes = int((total_seconds % 3600) // 60)
                    seconds = int(total_seconds % 60)
                    a["time"] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                else:
                    a["time"] = a["time"].strftime("%H:%M:%S")

        return jsonify(appointments)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ---------------- SERVE UPLOADS ----------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ---------------- LAST ATTENDED PATIENTS ----------------
@app.route("/prescriptions/doctor/<int:doctor_id>/recent", methods=["GET"])
def get_last_attended_patients(doctor_id):
    """
    Fetch patients attended by the doctor, ordered by most recent prescription.
    Returns: List of patients with last visit date and last prescription time.
    """
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT 
                p.id AS patient_id,
                p.name AS name,
                MAX(pr.created_at) AS last_prescription_time,
                DATE(MAX(pr.created_at)) AS last_visit_date
            FROM prescriptions pr
            JOIN users p ON pr.patient_id = p.id
            WHERE pr.doctor_id = %s
            GROUP BY p.id, p.name
            ORDER BY last_prescription_time DESC
        """, (doctor_id,))

        patients = cursor.fetchall()

        # Serialize datetime to string
        for p in patients:
            if isinstance(p.get("last_prescription_time"), datetime):
                p["last_prescription_time"] = p["last_prescription_time"].strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(p.get("last_visit_date"), (datetime, date)):
                p["last_visit_date"] = p["last_visit_date"].strftime("%Y-%m-%d")

        return jsonify(patients)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ---------------- RUN ----------------
if __name__ == "__main__":
    # For production, use gunicorn/uwsgi and set debug=False
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
