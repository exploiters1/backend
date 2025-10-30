from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
import os
import json
from datetime import datetime, timedelta, date
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import secrets
import traceback

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ---------------- CONFIG ----------------
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# AES configuration
AES_KEY = os.environ.get("AES_KEY", "ThisIsA32ByteSecretKeyForAES256!")
AES_KEY_BYTES = AES_KEY.encode("utf-8")

# Fields considered sensitive and encrypted at-rest:
SENSITIVE_PROFILE_FIELDS = ["phone_number", "address", "city", "pincode", "state"]

# ---------------- AES HELPERS ----------------
def encrypt_data(plaintext: str) -> str:
    """Encrypt plaintext using AES-CBC with a random IV."""
    if plaintext is None:
        return ""
    iv = secrets.token_bytes(16)
    cipher = AES.new(AES_KEY_BYTES, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    combined = iv + ct_bytes
    return base64.b64encode(combined).decode("utf-8")

def decrypt_data(ciphertext: str) -> str:
    """Decrypt ciphertext produced by encrypt_data."""
    try:
        if not ciphertext:
            return ""
        missing_padding = len(ciphertext) % 4
        if missing_padding:
            ciphertext += "=" * (4 - missing_padding)
        combined = base64.b64decode(ciphertext)
        if len(combined) > 16:
            iv = combined[:16]
            ct = combined[16:]
            cipher = AES.new(AES_KEY_BYTES, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode("utf-8")
        return ""
    except Exception as e:
        print("Decryption error:", e)
        return ""

# ---------------- DATABASE (SUPABASE POSTGRESQL) ----------------
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=os.environ.get("DB_HOST", "db.your-supabase-url.supabase.co"),
            database=os.environ.get("DB_NAME", "postgres"),
            user=os.environ.get("DB_USER", "postgres"),
            password=os.environ.get("DB_PASS", "your-password"),
            port=os.environ.get("DB_PORT", "5432"),
            sslmode="require"
        )
        return conn
    except Exception as e:
        print(f"Supabase Connection Error: {e}")
        return None

# ---------------- HEALTH & ROOT ----------------
@app.route("/")
def home():
    return jsonify({"message": "Flask backend running ✅ with Supabase", "status": "healthy"})

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    try:
        conn = get_db_connection()
        if conn:
            conn.close()
            return jsonify({"status": "healthy", "database": "connected"})
        else:
            return jsonify({"status": "unhealthy", "database": "disconnected"}), 500
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# ---------------- AUTHENTICATION ENDPOINTS ----------------
@app.route("/register", methods=["POST"])
def register():
    """Register a new user (doctor or patient)"""
    try:
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
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({"error": "User already exists"}), 400

            hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO users (name, email, password, role, specialization) VALUES (%s, %s, %s, %s, %s)",
                (name, email, hashed_pw.decode("utf-8"), role, specialization)
            )
            conn.commit()
            
            return jsonify({"message": f"{role.capitalize()} registered successfully ✅"}), 201
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/login", methods=["POST"])
def login():
    """Login for users"""
    try:
        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")
        role = data.get("role")

        if not email or not password or role not in ["doctor", "patient"]:
            return jsonify({"error": "Invalid input"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute("SELECT * FROM users WHERE email = %s AND role = %s", (email, role))
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

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/register", methods=["POST"])
def admin_register():
    """Register a new admin"""
    try:
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
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute("SELECT * FROM admins WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({"error": "Admin already exists"}), 400

            hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO admins (name, email, password, hospital_name, hospital_address) VALUES (%s, %s, %s, %s, %s)",
                (name, email, hashed_pw.decode("utf-8"), hospital_name, hospital_address)
            )
            conn.commit()
            
            return jsonify({"message": "Admin registered successfully ✅"}), 201
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/login", methods=["POST"])
def admin_login():
    """Login for admin"""
    try:
        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute("SELECT * FROM admins WHERE email = %s", (email,))
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

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- PHARMACIST AUTH ENDPOINTS ----------------
@app.route("/register_pharmacist", methods=["POST"])
def register_pharmacist():
    """Register a new pharmacist"""
    try:
        data = request.get_json() or {}
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        phone = data.get("phone")
        pharmacy_name = data.get("pharmacy_name")

        if not all([name, email, password, phone, pharmacy_name]):
            return jsonify({"error": "All fields are required"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute("SELECT * FROM pharmacists WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({"error": "Pharmacist with this email already exists"}), 400

            hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO pharmacists (name, email, password, phone, pharmacy_name) VALUES (%s, %s, %s, %s, %s)",
                (name, email, hashed_pw.decode("utf-8"), phone, pharmacy_name)
            )
            conn.commit()
            
            return jsonify({"message": "Pharmacist registered successfully ✅"}), 201
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/login_pharmacist", methods=["POST"])
def login_pharmacist():
    """Login for pharmacist"""
    try:
        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute("SELECT * FROM pharmacists WHERE email = %s", (email,))
            pharmacist = cursor.fetchone()

            if not pharmacist:
                return jsonify({"error": "Pharmacist not found"}), 404

            if not bcrypt.checkpw(password.encode("utf-8"), pharmacist["password"].encode("utf-8")):
                return jsonify({"error": "Invalid password"}), 401

            return jsonify({
                "message": "Login successful ✅",
                "pharmacist": {
                    "id": pharmacist["id"],
                    "name": pharmacist["name"],
                    "email": pharmacist["email"],
                    "phone": pharmacist["phone"],
                    "pharmacy_name": pharmacist["pharmacy_name"]
                }
            })
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- PROFILE MANAGEMENT ----------------
@app.route("/profile/<role>/<int:user_id>", methods=["GET", "PUT"])
def profile(role, user_id):
    """Get or update user profile"""
    if role not in ["doctor", "patient"]:
        return jsonify({"error": "Invalid role"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
        
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        if request.method == "GET":
            cursor.execute("SELECT * FROM users WHERE id = %s AND role = %s", (user_id, role))
            user = cursor.fetchone()
            
            if not user:
                return jsonify({"error": f"{role.capitalize()} not found"}), 404
            
            for field in SENSITIVE_PROFILE_FIELDS:
                if user.get(field):
                    user[field] = decrypt_data(user[field])
            
            if role == "doctor":
                cursor.execute("SELECT hospital_name FROM admins LIMIT 1")
                hospital = cursor.fetchone()
                user["hospital_name"] = hospital["hospital_name"] if hospital else "Medical Center"
            
            if user.get("profile_pic"):
                user["profile_pic_url"] = f"{request.host_url}uploads/{user['profile_pic']}"
            if user.get("signature"):
                user["signature_url"] = f"{request.host_url}uploads/{user['signature']}"
            
            return jsonify(user)

        elif request.method == "PUT":
            form = request.form
            profile_pic_file = request.files.get("profile_pic")
            signature_file = request.files.get("signature")

            updates = []
            values = []

            allowed_fields = ["name", "email", "specialization", "age", "weight",
                            "phone_number", "address", "city", "pincode", "state", "date_of_birth"]

            for field in allowed_fields:
                if form.get(field) is not None:
                    val = form.get(field)
                    if field in SENSITIVE_PROFILE_FIELDS and val != "":
                        val = encrypt_data(val)
                    updates.append(f"{field} = %s")
                    values.append(val)

            dob_str = form.get("date_of_birth")
            if dob_str:
                try:
                    dob_date = datetime.strptime(dob_str, "%Y-%m-%d").date()
                    today = date.today()
                    calculated_age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
                    updates.append("age = %s")
                    values.append(calculated_age)
                except Exception:
                    pass

            if profile_pic_file:
                filename = f"profile_{user_id}_{secure_filename(profile_pic_file.filename)}"
                profile_pic_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                updates.append("profile_pic = %s")
                values.append(filename)
                
            if signature_file:
                filename = f"signature_{user_id}_{secure_filename(signature_file.filename)}"
                signature_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                updates.append("signature = %s")
                values.append(filename)

            if updates:
                sql = f"UPDATE users SET {', '.join(updates)} WHERE id = %s AND role = %s"
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
    """Get all records for a patient"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT pr.*, u.name AS doctor_name, u.specialization
            FROM patient_records pr
            JOIN users u ON pr.doctor_id = u.id
            WHERE pr.patient_id = %s AND (pr.is_active IS NULL OR pr.is_active = TRUE)
            ORDER BY pr.created_at DESC
        """, (patient_id,))
        
        records = cursor.fetchall()
        processed_records = []

        for record in records:
            processed_record = {
                "id": record["id"],
                "patient_id": record["patient_id"],
                "doctor_id": record["doctor_id"],
                "doctor_name": record["doctor_name"],
                "specialization": record["specialization"],
                "created_at": record["created_at"],
                "updated_at": record["updated_at"],
                "record_type": record.get("record_type", "consultation"),
                "severity": record.get("severity", "medium")
            }
            
            if any([record.get("diagnosis"), record.get("symptoms"), record.get("current_condition")]):
                processed_record.update({
                    "past_diseases": record.get("past_diseases", ""),
                    "current_condition": record.get("current_condition", ""),
                    "diagnosis": record.get("diagnosis", ""),
                    "symptoms": record.get("symptoms", ""),
                    "treatment_plan": record.get("treatment_plan", ""),
                    "medications": record.get("medications", ""),
                    "blood_pressure": record.get("blood_pressure", ""),
                    "heart_rate": record.get("heart_rate"),
                    "temperature": record.get("temperature"),
                    "weight": record.get("weight"),
                    "height": record.get("height"),
                    "blood_sugar": record.get("blood_sugar"),
                    "oxygen_saturation": record.get("oxygen_saturation"),
                    "allergies": record.get("allergies", ""),
                    "follow_up_date": record.get("follow_up_date"),
                    "next_appointment_date": record.get("next_appointment_date"),
                    "doctor_notes": record.get("doctor_notes", "")
                })
            elif record.get("scan_report"):
                try:
                    decrypted_data = decrypt_data(record["scan_report"])
                    if decrypted_data:
                        data = json.loads(decrypted_data)
                        processed_record.update(data)
                except Exception as e:
                    print(f"Error decrypting record {record['id']}: {e}")
            
            processed_records.append(processed_record)

        return jsonify(processed_records)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/patient-records", methods=["POST"])
def add_patient_record():
    """Add a new patient record"""
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400

        data = request.get_json()
        patient_id = data.get("patient_id")
        doctor_id = data.get("doctor_id")
        
        if not patient_id or not doctor_id:
            return jsonify({"error": "Missing patient_id or doctor_id"}), 400

        record_data = {
            "past_diseases": data.get("past_diseases", ""),
            "current_condition": data.get("current_condition", ""),
            "diagnosis": data.get("diagnosis", ""),
            "symptoms": data.get("symptoms", ""),
            "treatment_plan": data.get("treatment_plan", ""),
            "medications": data.get("medications", ""),
            "blood_pressure": data.get("blood_pressure", ""),
            "heart_rate": data.get("heart_rate"),
            "temperature": data.get("temperature"),
            "weight": data.get("weight"),
            "height": data.get("height"),
            "blood_sugar": data.get("blood_sugar"),
            "oxygen_saturation": data.get("oxygen_saturation"),
            "allergies": data.get("allergies", ""),
            "follow_up_date": data.get("follow_up_date"),
            "next_appointment_date": data.get("next_appointment_date"),
            "doctor_notes": data.get("doctor_notes", ""),
            "record_type": data.get("record_type", "consultation"),
            "severity": data.get("severity", "medium")
        }

        encrypted_backup = encrypt_data(json.dumps(record_data, default=str))

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO patient_records 
                (patient_id, doctor_id, past_diseases, current_condition, diagnosis, symptoms, 
                 treatment_plan, medications, blood_pressure, heart_rate, temperature, weight, 
                 height, blood_sugar, oxygen_saturation, allergies, follow_up_date, 
                 next_appointment_date, doctor_notes, record_type, severity, scan_report, 
                 created_at, updated_at, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), TRUE)
            """, (
                patient_id, doctor_id,
                record_data["past_diseases"], record_data["current_condition"], record_data["diagnosis"],
                record_data["symptoms"], record_data["treatment_plan"], record_data["medications"],
                record_data["blood_pressure"], record_data["heart_rate"], record_data["temperature"],
                record_data["weight"], record_data["height"], record_data["blood_sugar"],
                record_data["oxygen_saturation"], record_data["allergies"], record_data["follow_up_date"],
                record_data["next_appointment_date"], record_data["doctor_notes"], record_data["record_type"],
                record_data["severity"], encrypted_backup
            ))
            
            conn.commit()
            record_id = cursor.lastrowid
            
            return jsonify({
                "message": "Patient record added successfully ✅",
                "record_id": record_id
            })
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": f"Database error: {str(e)}"}), 500
        finally:
            cursor.close()
            conn.close()
                
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

@app.route("/patient-records/<int:record_id>", methods=["PUT"])
def update_patient_record(record_id):
    """Update a patient record"""
    try:
        data = request.get_json() or {}
        doctor_id = data.get("doctor_id")
        
        if not doctor_id:
            return jsonify({"error": "Missing doctor_id"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute("SELECT * FROM patient_records WHERE id = %s", (record_id,))
            record = cursor.fetchone()
            
            if not record:
                return jsonify({"error": "Record not found"}), 404
                
            if int(record["doctor_id"]) != int(doctor_id):
                return jsonify({"error": "You can only modify your own records"}), 403

            updated_data = {
                "past_diseases": data.get("past_diseases", record.get("past_diseases", "")),
                "current_condition": data.get("current_condition", record.get("current_condition", "")),
                "diagnosis": data.get("diagnosis", record.get("diagnosis", "")),
                "symptoms": data.get("symptoms", record.get("symptoms", "")),
                "treatment_plan": data.get("treatment_plan", record.get("treatment_plan", "")),
                "medications": data.get("medications", record.get("medications", "")),
                "blood_pressure": data.get("blood_pressure", record.get("blood_pressure", "")),
                "heart_rate": data.get("heart_rate", record.get("heart_rate")),
                "temperature": data.get("temperature", record.get("temperature")),
                "weight": data.get("weight", record.get("weight")),
                "height": data.get("height", record.get("height")),
                "blood_sugar": data.get("blood_sugar", record.get("blood_sugar")),
                "oxygen_saturation": data.get("oxygen_saturation", record.get("oxygen_saturation")),
                "allergies": data.get("allergies", record.get("allergies", "")),
                "follow_up_date": data.get("follow_up_date", record.get("follow_up_date")),
                "next_appointment_date": data.get("next_appointment_date", record.get("next_appointment_date")),
                "doctor_notes": data.get("doctor_notes", record.get("doctor_notes", "")),
                "record_type": data.get("record_type", record.get("record_type", "consultation")),
                "severity": data.get("severity", record.get("severity", "medium"))
            }

            encrypted_backup = encrypt_data(json.dumps(updated_data))

            cursor.execute("""
                UPDATE patient_records
                SET past_diseases = %s, current_condition = %s, diagnosis = %s, symptoms = %s,
                    treatment_plan = %s, medications = %s, blood_pressure = %s, heart_rate = %s,
                    temperature = %s, weight = %s, height = %s, blood_sugar = %s, oxygen_saturation = %s,
                    allergies = %s, follow_up_date = %s, next_appointment_date = %s, doctor_notes = %s,
                    record_type = %s, severity = %s, scan_report = %s, updated_at = NOW()
                WHERE id = %s
            """, (
                updated_data["past_diseases"], updated_data["current_condition"], updated_data["diagnosis"],
                updated_data["symptoms"], updated_data["treatment_plan"], updated_data["medications"],
                updated_data["blood_pressure"], updated_data["heart_rate"], updated_data["temperature"],
                updated_data["weight"], updated_data["height"], updated_data["blood_sugar"],
                updated_data["oxygen_saturation"], updated_data["allergies"], updated_data["follow_up_date"],
                updated_data["next_appointment_date"], updated_data["doctor_notes"], updated_data["record_type"],
                updated_data["severity"], encrypted_backup, record_id
            ))
            
            conn.commit()
            return jsonify({"message": "Record updated successfully ✅"})
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/patient-records/<int:record_id>", methods=["DELETE"])
def delete_patient_record(record_id):
    """Delete a patient record (soft delete)"""
    try:
        data = request.get_json() or {}
        doctor_id = data.get("doctor_id")
        
        if not doctor_id:
            return jsonify({"error": "Missing doctor_id"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute("SELECT * FROM patient_records WHERE id = %s", (record_id,))
            record = cursor.fetchone()
            
            if not record:
                return jsonify({"error": "Record not found"}), 404
                
            if int(record["doctor_id"]) != int(doctor_id):
                return jsonify({"error": "You can only delete your own records"}), 403

            cursor.execute("UPDATE patient_records SET is_active = FALSE WHERE id = %s", (record_id,))
            conn.commit()
            
            return jsonify({"message": "Record deleted successfully ✅"})
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- PRESCRIPTIONS ----------------
@app.route("/prescriptions", methods=["POST"])
def save_prescription():
    """Save a new prescription"""
    try:
        data = request.get_json() or {}
        doctor_id = data.get("doctor_id")
        doctor_name = data.get("doctor_name")
        patient_id = data.get("patient_id")
        patient_name = data.get("patient_name")
        patient_age = data.get("patient_age")
        patient_weight = data.get("patient_weight")
        prescription_text = data.get("prescription", "")
        medicines = data.get("medicines", [])
        notes = data.get("notes", "")
        validity_days = data.get("validity_days", 30)

        if not all([doctor_id, patient_id, prescription_text]):
            return jsonify({"error": "Missing required data"}), 400

        prescription_content = json.dumps({
            "prescription": prescription_text,
            "medicines": medicines,
            "notes": notes,
            "issue_date": datetime.now().strftime("%Y-%m-%d"),
            "validity_days": validity_days
        })
        encrypted_prescription = encrypt_data(prescription_content)

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO prescriptions 
                (doctor_id, doctor_name, patient_id, patient_name, patient_age, patient_weight, encrypted_data, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                doctor_id, doctor_name, patient_id, patient_name, patient_age, patient_weight, encrypted_prescription
            ))
            
            conn.commit()
            prescription_id = cursor.lastrowid
            
            return jsonify({
                "message": "Prescription saved successfully ✅",
                "prescription_id": prescription_id
            }), 201
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": f"Database error: {str(e)}"}), 500
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/prescriptions/patient/<int:patient_id>", methods=["GET"])
def get_patient_prescriptions(patient_id):
    """Get all prescriptions for a patient"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT * FROM prescriptions 
            WHERE patient_id = %s 
            ORDER BY created_at DESC
        """, (patient_id,))
        
        prescriptions = cursor.fetchall()
        processed_prescriptions = []

        for prescription in prescriptions:
            decrypted_data = decrypt_data(prescription.get("encrypted_data", ""))
            try:
                data = json.loads(decrypted_data) if decrypted_data else {}
            except:
                data = {}

            processed_prescriptions.append({
                "id": prescription["id"],
                "doctor_id": prescription["doctor_id"],
                "doctor_name": prescription["doctor_name"],
                "patient_id": prescription["patient_id"],
                "patient_name": prescription["patient_name"],
                "patient_age": prescription["patient_age"],
                "patient_weight": prescription["patient_weight"],
                "prescription": data.get("prescription", ""),
                "medicines": data.get("medicines", []),
                "notes": data.get("notes", ""),
                "issue_date": data.get("issue_date", ""),
                "validity_days": data.get("validity_days", 30),
                "created_at": prescription["created_at"].strftime("%Y-%m-%d %H:%M:%S") if prescription.get("created_at") else ""
            })

        return jsonify(processed_prescriptions)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/get_all_prescriptions", methods=["GET"])
def get_all_prescriptions():
    """Get all prescriptions for pharmacist dashboard"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT 
                p.id, p.patient_name, p.patient_id, p.doctor_name, p.doctor_id,
                p.created_at, DATE(p.created_at) as date, p.encrypted_data,
                COALESCE(pd.status, 'Pending') as status, pd.dispensed_at
            FROM prescriptions p
            LEFT JOIN prescription_dispense pd ON p.id = pd.prescription_id
            ORDER BY p.created_at DESC
        """)
        
        prescriptions = cursor.fetchall()
        processed_prescriptions = []

        for prescription in prescriptions:
            processed_prescription = {
                "id": prescription["id"],
                "patient_name": prescription["patient_name"],
                "patient_id": prescription["patient_id"],
                "doctor_name": prescription["doctor_name"],
                "doctor_id": prescription["doctor_id"],
                "date": prescription["date"].strftime("%Y-%m-%d") if prescription["date"] else "",
                "status": prescription["status"],
                "medicines": [],
                "prescription_text": "",
                "notes": "",
                "dispensed_at": prescription["dispensed_at"].strftime("%Y-%m-%d %H:%M:%S") if prescription["dispensed_at"] else None
            }
            
            encrypted_data = prescription.get("encrypted_data")
            if encrypted_data:
                try:
                    decrypted_data = decrypt_data(encrypted_data)
                    if decrypted_data:
                        data = json.loads(decrypted_data)
                        processed_prescription.update({
                            "medicines": data.get("medicines", []),
                            "prescription_text": data.get("prescription", ""),
                            "notes": data.get("notes", "")
                        })
                except Exception as e:
                    print(f"Error decrypting prescription {prescription['id']}: {e}")

            processed_prescriptions.append(processed_prescription)

        return jsonify({
            "prescriptions": processed_prescriptions,
            "count": len(processed_prescriptions)
        })

    except Exception as e:
        return jsonify({"error": str(e), "prescriptions": [], "count": 0}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/update_dispense_status", methods=["POST"])
def update_dispense_status():
    """Update prescription dispense status"""
    try:
        data = request.get_json() or {}
        prescription_id = data.get("prescription_id")
        status = data.get("status")

        if not prescription_id or not status:
            return jsonify({"error": "Prescription ID and status are required"}), 400

        if status not in ["Dispensed", "Pending"]:
            return jsonify({"error": "Invalid status"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cursor.execute("SELECT id FROM prescriptions WHERE id = %s", (prescription_id,))
            if not cursor.fetchone():
                return jsonify({"error": "Prescription not found"}), 404

            if status == "Dispensed":
                cursor.execute("""
                    INSERT INTO prescription_dispense (prescription_id, status, dispensed_at) 
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (prescription_id) 
                    DO UPDATE SET status = %s, dispensed_at = NOW()
                """, (prescription_id, status, status))
            else:
                cursor.execute("""
                    INSERT INTO prescription_dispense (prescription_id, status, dispensed_at) 
                    VALUES (%s, %s, NULL)
                    ON CONFLICT (prescription_id) 
                    DO UPDATE SET status = %s, dispensed_at = NULL
                """, (prescription_id, status, status))
            
            conn.commit()
            
            return jsonify({"message": f"Prescription status updated to {status} ✅"})
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- APPOINTMENTS ----------------
@app.route("/appointments", methods=["GET", "POST"])
def appointments():
    """Handle appointments (get all or create new)"""
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500
        
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    try:
        if request.method == "POST":
            data = request.get_json() or {}
            patient_id = data.get("patient_id")
            doctor_id = data.get("doctor_id")
            date_str = data.get("date")
            time_str = data.get("time")
            reason = data.get("reason", "")

            if not all([patient_id, doctor_id, date_str, time_str]):
                return jsonify({"error": "Missing required appointment data"}), 400

            cursor.execute("""
                INSERT INTO appointments (patient_id, doctor_id, date, time, reason, status, created_at)
                VALUES (%s, %s, %s, %s, %s, 'pending', NOW())
            """, (patient_id, doctor_id, date_str, time_str, reason))
            
            conn.commit()
            appointment_id = cursor.lastrowid
            
            return jsonify({
                "message": "Appointment booked successfully ✅",
                "appointment_id": appointment_id
            }), 201

        else:  # GET
            patient_id = request.args.get("patient_id")
            doctor_id = request.args.get("doctor_id")

            query = """
                SELECT a.id, a.date, a.time, a.status, a.reason,
                       d.name AS doctor_name, p.name AS patient_name
                FROM appointments a
                JOIN users d ON a.doctor_id = d.id
                JOIN users p ON a.patient_id = p.id
            """
            conditions = []
            values = []

            if patient_id:
                conditions.append("a.patient_id = %s")
                values.append(patient_id)
            if doctor_id:
                conditions.append("a.doctor_id = %s")
                values.append(doctor_id)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY a.date DESC, a.time DESC"

            cursor.execute(query, tuple(values))
            appointments = cursor.fetchall()

            for appointment in appointments:
                if isinstance(appointment.get("date"), (datetime, date)):
                    appointment["date"] = appointment["date"].strftime("%Y-%m-%d")
                if hasattr(appointment.get("time"), 'strftime'):
                    appointment["time"] = appointment["time"].strftime("%H:%M:%S")

            return jsonify(appointments)
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/appointments/patient/<int:patient_id>", methods=["GET"])
def appointments_by_patient_path(patient_id):
    """Get appointments for a specific patient"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT a.id, a.date, a.time, a.status, a.reason,
                   d.name AS doctor_name, p.name AS patient_name
            FROM appointments a
            JOIN users d ON a.doctor_id = d.id
            JOIN users p ON a.patient_id = p.id
            WHERE a.patient_id = %s
            ORDER BY a.date DESC, a.time DESC
        """, (patient_id,))
        
        appointments = cursor.fetchall()

        for appointment in appointments:
            if isinstance(appointment.get("date"), (datetime, date)):
                appointment["date"] = appointment["date"].strftime("%Y-%m-%d")
            if hasattr(appointment.get("time"), 'strftime'):
                appointment["time"] = appointment["time"].strftime("%H:%M:%S")

        return jsonify(appointments)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/appointments/doctor/<int:doctor_id>", methods=["GET"])
def get_appointments_by_doctor(doctor_id):
    """Get appointments for a specific doctor"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT a.id, a.date, a.time, a.status, a.reason,
                   d.name AS doctor_name, p.name AS patient_name
            FROM appointments a
            JOIN users d ON a.doctor_id = d.id
            JOIN users p ON a.patient_id = p.id
            WHERE a.doctor_id = %s
            ORDER BY a.date DESC, a.time DESC
        """, (doctor_id,))
        
        appointments = cursor.fetchall()

        for appointment in appointments:
            if isinstance(appointment.get("date"), (datetime, date)):
                appointment["date"] = appointment["date"].strftime("%Y-%m-%d")
            if hasattr(appointment.get("time"), 'strftime'):
                appointment["time"] = appointment["time"].strftime("%H:%M:%S")

        return jsonify(appointments)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/appointments/<int:appointment_id>/status", methods=["PUT"])
def update_appointment_status(appointment_id):
    """Update appointment status"""
    try:
        data = request.get_json() or {}
        status = data.get("status")
        
        if status not in ["pending", "accepted", "rejected"]:
            return jsonify({"error": "Invalid status"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute("UPDATE appointments SET status = %s WHERE id = %s", (status, appointment_id))
            conn.commit()
            
            return jsonify({"message": f"Appointment status updated to {status} ✅"})
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/appointments/<int:appointment_id>", methods=["DELETE"])
def delete_appointment(appointment_id):
    """Delete an appointment"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute("DELETE FROM appointments WHERE id = %s", (appointment_id,))
            conn.commit()
            
            if cursor.rowcount == 0:
                return jsonify({"error": "Appointment not found"}), 404
                
            return jsonify({"message": "Appointment cancelled successfully ✅"})
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/appointments/doctor/<int:doctor_id>/upcoming", methods=["GET"])
def get_upcoming_appointments(doctor_id):
    """Get upcoming appointments for doctor"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT 
                a.id, a.date, a.time, a.status, a.reason,
                p.name as patient_name, p.id as patient_id
            FROM appointments a
            JOIN users p ON a.patient_id = p.id
            WHERE a.doctor_id = %s 
            AND a.date >= CURRENT_DATE
            AND a.status = 'accepted'
            ORDER BY a.date ASC, a.time ASC
            LIMIT 10
        """, (doctor_id,))
        
        appointments = cursor.fetchall()
        
        for appointment in appointments:
            if isinstance(appointment.get("date"), (datetime, date)):
                appointment["date"] = appointment["date"].strftime("%Y-%m-%d")
            if hasattr(appointment.get("time"), 'strftime'):
                appointment["time"] = appointment["time"].strftime("%H:%M")
        
        return jsonify(appointments)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ---------------- QR CODE FUNCTIONALITY ----------------
@app.route("/qr/patient/<int:patient_id>", methods=["GET"])
def get_patient_qr_data(patient_id):
    """Get patient data for QR code generation"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT u.id, u.name, u.email, u.age, u.weight, u.phone_number, u.blood_group,
                   a.hospital_name
            FROM users u
            LEFT JOIN admins a ON u.admin_id = a.id
            WHERE u.id = %s AND u.role = 'patient'
        """, (patient_id,))
        
        patient = cursor.fetchone()
        
        if not patient:
            return jsonify({"error": "Patient not found"}), 404

        hospital_name = patient.get("hospital_name")
        if not hospital_name:
            cursor.execute("SELECT hospital_name FROM admins LIMIT 1")
            hospital = cursor.fetchone()
            hospital_name = hospital["hospital_name"] if hospital else "Medical Center"

        qr_data = {
            "patient_id": patient["id"],
            "name": patient["name"],
            "email": patient["email"],
            "phone_number": decrypt_data(patient["phone_number"]) if patient.get("phone_number") else "",
            "age": patient["age"],
            "blood_group": patient.get("blood_group", ""),
            "type": "patient_identification",
            "hospital": hospital_name,
            "system": "EncryptedMed",
            "timestamp": datetime.now().isoformat(),
            "version": "1.0"
        }
        
        return jsonify(qr_data)
        
    except Exception as e:
        return jsonify({"error": f"Failed to generate QR data: {str(e)}"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/qr/validate", methods=["POST"])
def validate_qr_code():
    """Validate scanned QR code data"""
    try:
        data = request.get_json() or {}
        qr_content = data.get("qr_data")
        
        if not qr_content:
            return jsonify({"error": "No QR data provided"}), 400
        
        try:
            qr_data = json.loads(qr_content)
        except json.JSONDecodeError:
            return jsonify({
                "type": "search_term",
                "search_term": qr_content,
                "message": "QR content treated as search term"
            })
        
        if not isinstance(qr_data, dict):
            return jsonify({"error": "Invalid QR data format"}), 400
        
        if qr_data.get("type") == "patient_identification" and qr_data.get("patient_id"):
            patient_id = qr_data["patient_id"]
            
            conn = get_db_connection()
            if not conn:
                return jsonify({"error": "Database connection failed"}), 500
                
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            cursor.execute("""
                SELECT u.id, u.name, u.email, u.age, u.weight, u.phone_number, u.blood_group,
                       u.profile_pic, a.hospital_name
                FROM users u
                LEFT JOIN admins a ON u.admin_id = a.id
                WHERE u.id = %s AND u.role = 'patient'
            """, (patient_id,))
            
            patient = cursor.fetchone()
            
            if patient:
                response_data = {
                    "type": "patient_identification",
                    "patient": {
                        "id": patient["id"],
                        "name": patient["name"],
                        "email": patient["email"],
                        "age": patient["age"],
                        "weight": patient["weight"],
                        "phone_number": decrypt_data(patient["phone_number"]) if patient.get("phone_number") else "",
                        "blood_group": patient.get("blood_group", ""),
                        "profile_pic_url": f"{request.host_url}uploads/{patient['profile_pic']}" if patient.get("profile_pic") else None,
                        "hospital_name": patient.get("hospital_name", "Medical Center")
                    },
                    "exists_in_database": True,
                    "message": "Patient verified successfully"
                }
            else:
                response_data = {
                    "type": "patient_identification",
                    "patient": qr_data,
                    "exists_in_database": False,
                    "message": "Patient data from QR code (not in local database)"
                }
            
            return jsonify(response_data)
        
        else:
            return jsonify({
                "type": "unknown",
                "data": qr_data,
                "message": "QR code recognized but not a patient identification code"
            })
            
    except Exception as e:
        return jsonify({"error": f"QR validation failed: {str(e)}"}), 500

@app.route("/qr/patient/<int:patient_id>/quick-access", methods=["GET"])
def get_patient_quick_access(patient_id):
    """Get quick access patient data for prescription writing"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT id, name, email, age, weight, blood_group, phone_number
            FROM users 
            WHERE id = %s AND role = 'patient'
        """, (patient_id,))
        
        patient = cursor.fetchone()
        
        if not patient:
            return jsonify({"error": "Patient not found"}), 404
        
        cursor.execute("""
            SELECT created_at, encrypted_data
            FROM prescriptions 
            WHERE patient_id = %s 
            ORDER BY created_at DESC 
            LIMIT 1
        """, (patient_id,))
        
        last_prescription = cursor.fetchone()
        
        cursor.execute("""
            SELECT diagnosis, symptoms, current_condition, created_at
            FROM patient_records 
            WHERE patient_id = %s 
            ORDER BY created_at DESC 
            LIMIT 3
        """, (patient_id,))
        
        recent_records = cursor.fetchall()
        
        prescription_data = None
        if last_prescription and last_prescription.get("encrypted_data"):
            try:
                decrypted = decrypt_data(last_prescription["encrypted_data"])
                if decrypted:
                    prescription_data = json.loads(decrypted)
            except Exception as e:
                print(f"Error decrypting prescription: {e}")
        
        response_data = {
            "patient": {
                "id": patient["id"],
                "name": patient["name"],
                "email": patient["email"],
                "age": patient["age"],
                "weight": patient["weight"],
                "blood_group": patient.get("blood_group", ""),
                "phone_number": decrypt_data(patient["phone_number"]) if patient.get("phone_number") else ""
            },
            "last_prescription": prescription_data,
            "recent_records": recent_records,
            "summary": {
                "has_medical_history": len(recent_records) > 0,
                "last_visit": last_prescription["created_at"].strftime("%Y-%m-%d") if last_prescription else "Never",
                "records_count": len(recent_records)
            }
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({"error": f"Failed to get patient data: {str(e)}"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/qr/search-patient", methods=["POST"])
def search_patient_by_qr():
    """Search for patient using QR code data"""
    try:
        data = request.get_json() or {}
        search_term = data.get("search_term")
        
        if not search_term:
            return jsonify({"error": "No search term provided"}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT id, name, email, age, weight, phone_number, blood_group, profile_pic
            FROM users 
            WHERE role = 'patient' AND (
                id = %s OR 
                name ILIKE %s OR 
                email ILIKE %s OR 
                phone_number ILIKE %s
            )
            LIMIT 10
        """, (
            search_term if search_term.isdigit() else -1,
            f"%{search_term}%",
            f"%{search_term}%", 
            f"%{search_term}%"
        ))
        
        patients = cursor.fetchall()
        
        for patient in patients:
            if patient.get("phone_number"):
                patient["phone_number"] = decrypt_data(patient["phone_number"])
            if patient.get("profile_pic"):
                patient["profile_pic_url"] = f"{request.host_url}uploads/{patient['profile_pic']}"
        
        return jsonify({
            "patients": patients,
            "count": len(patients),
            "search_term": search_term
        })
        
    except Exception as e:
        return jsonify({"error": f"Search failed: {str(e)}"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/qr/bulk-patients", methods=["GET"])
def get_bulk_patients_for_qr():
    """Get all patients for QR code generation (admin/doctor use)"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT id, name, email, age, phone_number, blood_group
            FROM users 
            WHERE role = 'patient'
            ORDER BY name
        """)
        
        patients = cursor.fetchall()
        
        cursor.execute("SELECT hospital_name FROM admins LIMIT 1")
        hospital = cursor.fetchone()
        hospital_name = hospital["hospital_name"] if hospital else "Medical Center"
        
        for patient in patients:
            if patient.get("phone_number"):
                patient["phone_number"] = decrypt_data(patient["phone_number"])
            
            patient["qr_data"] = {
                "patient_id": patient["id"],
                "name": patient["name"],
                "email": patient["email"],
                "phone_number": patient.get("phone_number", ""),
                "age": patient["age"],
                "blood_group": patient.get("blood_group", ""),
                "type": "patient_identification",
                "hospital": hospital_name,
                "system": "EncryptedMed",
                "timestamp": datetime.now().isoformat(),
                "version": "1.0"
            }
            
            patient["qr_string"] = json.dumps(patient["qr_data"])
        
        return jsonify({
            "patients": patients,
            "hospital": hospital_name,
            "total_count": len(patients)
        })
        
    except Exception as e:
        return jsonify({"error": f"Failed to get patients: {str(e)}"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ---------------- ENHANCED PATIENT SEARCH ----------------
@app.route("/patients/search-enhanced", methods=["GET"])
def search_patients_enhanced():
    """Enhanced patient search with QR code support"""
    try:
        search_term = request.args.get('q', '')
        limit = int(request.args.get('limit', 20))
        
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        if search_term:
            cursor.execute("""
                SELECT 
                    u.id, u.name, u.email, u.age, u.weight, 
                    u.phone_number, u.blood_group, u.profile_pic,
                    COUNT(DISTINCT pr.id) as prescription_count,
                    MAX(pr.created_at) as last_visit
                FROM users u
                LEFT JOIN prescriptions pr ON u.id = pr.patient_id
                WHERE u.role = 'patient' AND (
                    u.id = %s OR 
                    u.name ILIKE %s OR 
                    u.email ILIKE %s OR
                    u.phone_number ILIKE %s
                )
                GROUP BY u.id, u.name, u.email, u.age, u.weight, 
                         u.phone_number, u.blood_group, u.profile_pic
                ORDER BY 
                    CASE 
                        WHEN u.id = %s THEN 1
                        WHEN u.name ILIKE %s THEN 2
                        ELSE 3
                    END,
                    last_visit DESC NULLS LAST
                LIMIT %s
            """, (
                search_term if search_term.isdigit() else -1,
                f"%{search_term}%",
                f"%{search_term}%",
                f"%{search_term}%",
                search_term if search_term.isdigit() else -1,
                f"{search_term}%",
                limit
            ))
        else:
            cursor.execute("""
                SELECT 
                    u.id, u.name, u.email, u.age, u.weight, 
                    u.phone_number, u.blood_group, u.profile_pic,
                    COUNT(DISTINCT pr.id) as prescription_count,
                    MAX(pr.created_at) as last_visit
                FROM users u
                LEFT JOIN prescriptions pr ON u.id = pr.patient_id
                WHERE u.role = 'patient'
                GROUP BY u.id, u.name, u.email, u.age, u.weight, 
                         u.phone_number, u.blood_group, u.profile_pic
                ORDER BY last_visit DESC NULLS LAST, u.name ASC
                LIMIT %s
            """, (limit,))
        
        patients = cursor.fetchall()
        
        for patient in patients:
            if patient.get("phone_number"):
                patient["phone_number"] = decrypt_data(patient["phone_number"])
            
            if patient.get("profile_pic"):
                patient["profile_pic_url"] = f"{request.host_url}uploads/{patient['profile_pic']}"
            
            if patient.get("last_visit") and isinstance(patient["last_visit"], datetime):
                patient["last_visit_formatted"] = patient["last_visit"].strftime("%Y-%m-%d")
                patient["visited_recently"] = (datetime.now() - patient["last_visit"]).days <= 7
            else:
                patient["last_visit_formatted"] = "Never"
                patient["visited_recently"] = False
        
        return jsonify({
            "patients": patients,
            "search_term": search_term,
            "total_found": len(patients)
        })
        
    except Exception as e:
        return jsonify({"error": f"Search failed: {str(e)}"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ---------------- CAMERA PERMISSION UTILITIES ----------------
@app.route("/camera/permission-check", methods=["GET"])
def check_camera_permissions():
    """Check browser compatibility and camera permission status"""
    try:
        user_agent = request.headers.get('User-Agent', '').lower()
        
        compatibility = {
            "compatible": True,
            "browser": "unknown",
            "issues": []
        }
        
        if 'chrome' in user_agent:
            compatibility["browser"] = "chrome"
        elif 'firefox' in user_agent:
            compatibility["browser"] = "firefox"
        elif 'safari' in user_agent:
            compatibility["browser"] = "safari"
            compatibility["issues"].append("Safari may have limited camera features")
        elif 'edge' in user_agent:
            compatibility["browser"] = "edge"
        else:
            compatibility["issues"].append("Unsupported browser detected")
        
        if 'mobile' in user_agent:
            compatibility["issues"].append("Mobile devices may have limited camera support")
        
        return jsonify({
            "compatibility": compatibility,
            "user_agent": user_agent[:100],
            "https": request.is_secure,
            "host": request.host
        })
        
    except Exception as e:
        return jsonify({"error": f"Permission check failed: {str(e)}"}), 500

# ---------------- SCAN REPORTS ----------------
@app.route("/scan-reports/patient/<int:patient_id>", methods=["GET"])
def get_scan_reports(patient_id):
    """Get all scan reports for a patient"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT sr.*, u.name AS doctor_name
            FROM scan_reports sr
            JOIN users u ON sr.doctor_id = u.id
            WHERE sr.patient_id = %s
            ORDER BY sr.report_date DESC, sr.created_at DESC
        """, (patient_id,))
        
        scan_reports = cursor.fetchall()
        return jsonify(scan_reports)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/scan-reports/upload", methods=["POST"])
def upload_scan_report():
    """Upload a scan report for a patient"""
    try:
        patient_id = request.form.get("patient_id")
        doctor_id = request.form.get("doctor_id")
        report_type = request.form.get("report_type")
        report_date = request.form.get("report_date")
        description = request.form.get("description", "")
        findings = request.form.get("findings", "")
        scan_file = request.files.get("scan_file")

        if not all([patient_id, doctor_id, report_type, report_date]):
            return jsonify({"error": "Missing required fields"}), 400

        file_name = None
        if scan_file and scan_file.filename:
            file_name = f"scan_{patient_id}_{int(datetime.now().timestamp())}_{secure_filename(scan_file.filename)}"
            scan_file.save(os.path.join(app.config["UPLOAD_FOLDER"], file_name))

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO scan_reports 
                (patient_id, doctor_id, report_type, report_date, description, findings, file_name, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (patient_id, doctor_id, report_type, report_date, description, findings, file_name))
            
            conn.commit()
            report_id = cursor.lastrowid
            
            return jsonify({
                "message": "Scan report uploaded successfully ✅",
                "report_id": report_id
            })
            
        except Exception as e:
            conn.rollback()
            return jsonify({"error": f"Database error: {str(e)}"}), 500
        finally:
            cursor.close()
            conn.close()
                
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

@app.route("/scan-reports/download/<int:report_id>", methods=["GET"])
def download_scan_report(report_id):
    """Download a scan report file"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT file_name FROM scan_reports WHERE id = %s", (report_id,))
        report = cursor.fetchone()
        
        if not report or not report["file_name"]:
            return jsonify({"error": "Scan report or file not found"}), 404
            
        return send_from_directory(app.config["UPLOAD_FOLDER"], report["file_name"], as_attachment=True)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ---------------- MEDICINE VERIFICATION SYSTEM ----------------
# ---------------- MEDICINE VERIFICATION SYSTEM ----------------
@app.route("/prescription-verification/patient/<int:patient_id>", methods=["GET"])
def get_prescriptions_for_verification(patient_id):
    """Get prescriptions pending verification for a patient"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # First, let's check if we have any dispensed prescriptions
        cursor.execute("""
            SELECT 
                p.id,
                p.patient_id,
                p.patient_name,
                p.doctor_name,
                p.created_at,
                pd.status as dispense_status,
                pd.dispensed_at,
                pd.pharmacist_id,
                ph.name as pharmacist_name,
                ph.pharmacy_name
            FROM prescriptions p
            LEFT JOIN prescription_dispense pd ON p.id = pd.prescription_id
            LEFT JOIN pharmacists ph ON pd.pharmacist_id = ph.id
            WHERE p.patient_id = %s 
            AND (pd.status = 'Dispensed' OR pd.status IS NULL)
            ORDER BY p.created_at DESC
        """, (patient_id,))
        
        prescriptions = cursor.fetchall()
        processed_prescriptions = []

        for prescription in prescriptions:
            # Get prescription details
            cursor.execute("SELECT encrypted_data FROM prescriptions WHERE id = %s", (prescription['id'],))
            prescription_data = cursor.fetchone()
            
            medicines = []
            if prescription_data and prescription_data['encrypted_data']:
                try:
                    decrypted_data = decrypt_data(prescription_data['encrypted_data'])
                    if decrypted_data:
                        data = json.loads(decrypted_data)
                        medicines = data.get('medicines', [])
                        
                        # If no medicines array but has prescription text, create medicines list
                        if not medicines and data.get('prescription'):
                            # Parse prescription text to extract medicines
                            prescription_text = data.get('prescription', '')
                            # Simple parsing - you might want to improve this
                            medicines = [{"name": prescription_text, "dosage": "", "frequency": "", "duration": ""}]
                except Exception as e:
                    print(f"Error decrypting prescription {prescription['id']}: {e}")
                    # Create a default medicine entry
                    medicines = [{"name": "Unknown Medicine", "dosage": "", "frequency": "", "duration": ""}]
            
            # Get medicine verification status
            verified_medicines = []
            for medicine in medicines:
                cursor.execute("""
                    SELECT 
                        verified,
                        verification_timestamp,
                        patient_notes,
                        verification_method
                    FROM medicine_verification 
                    WHERE prescription_id = %s AND medicine_name = %s
                """, (prescription['id'], medicine.get('name', 'Unknown')))
                
                verification = cursor.fetchone()
                
                verified_medicines.append({
                    **medicine,
                    'verified': verification['verified'] if verification else False,
                    'verification_timestamp': verification['verification_timestamp'] if verification else None,
                    'patient_notes': verification['patient_notes'] if verification else None,
                    'verification_method': verification['verification_method'] if verification else None
                })
            
            # Get prescription verification status
            cursor.execute("""
                SELECT verification_status, verified_at, patient_confirmation
                FROM prescription_verification 
                WHERE prescription_id = %s
            """, (prescription['id'],))
            
            prescription_verification = cursor.fetchone()
            
            verification_count = sum(1 for m in verified_medicines if m.get('verified', False))
            total_medicines = len(verified_medicines)
            
            prescription_data = {
                'id': prescription['id'],
                'patient_id': prescription['patient_id'],
                'patient_name': prescription['patient_name'],
                'doctor_name': prescription['doctor_name'],
                'pharmacy_name': prescription.get('pharmacy_name', 'Unknown Pharmacy'),
                'dispensed_at': prescription.get('dispensed_at'),
                'dispense_status': prescription.get('dispense_status', 'Pending'),
                'created_at': prescription['created_at'],
                'medicines': verified_medicines,
                'verification_status': prescription_verification['verification_status'] if prescription_verification else 'pending',
                'all_verified': verification_count == total_medicines and total_medicines > 0,
                'verification_count': verification_count,
                'total_medicines': total_medicines
            }
            
            processed_prescriptions.append(prescription_data)

        return jsonify({
            "prescriptions": processed_prescriptions,
            "count": len(processed_prescriptions),
            "error": None
        })

    except Exception as e:
        print(f"Error in get_prescriptions_for_verification: {str(e)}")
        return jsonify({
            "error": f"Failed to get prescriptions: {str(e)}",
            "prescriptions": [],
            "count": 0
        }), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/verify-medicine", methods=["POST"])
def verify_medicine():
    """Verify a specific medicine from a prescription"""
    try:
        data = request.get_json() or {}
        prescription_id = data.get("prescription_id")
        medicine_name = data.get("medicine_name")
        patient_id = data.get("patient_id")
        verified = data.get("verified", True)
        patient_notes = data.get("patient_notes", "")
        verification_method = data.get("verification_method", "manual")

        if not all([prescription_id, medicine_name, patient_id]):
            return jsonify({"error": "Missing required fields"}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Verify the prescription belongs to the patient
        cursor.execute("SELECT patient_id FROM prescriptions WHERE id = %s", (prescription_id,))
        prescription = cursor.fetchone()
        
        if not prescription:
            return jsonify({"error": "Prescription not found"}), 404
            
        if prescription['patient_id'] != int(patient_id):
            return jsonify({"error": "Prescription not found or access denied"}), 403

        # Update or insert medicine verification
        cursor.execute("""
            INSERT INTO medicine_verification 
            (prescription_id, medicine_name, verified, verification_timestamp, patient_notes, verification_method)
            VALUES (%s, %s, %s, NOW(), %s, %s)
            ON CONFLICT (prescription_id, medicine_name) 
            DO UPDATE SET 
                verified = EXCLUDED.verified,
                verification_timestamp = NOW(),
                patient_notes = EXCLUDED.patient_notes,
                verification_method = EXCLUDED.verification_method,
                updated_at = NOW()
        """, (prescription_id, medicine_name, verified, patient_notes, verification_method))

        # Check if all medicines are verified to update prescription verification status
        cursor.execute("""
            SELECT 
                COUNT(*) as total_medicines,
                SUM(CASE WHEN verified THEN 1 ELSE 0 END) as verified_count
            FROM medicine_verification 
            WHERE prescription_id = %s
        """, (prescription_id,))
        
        verification_stats = cursor.fetchone()
        
        # Get prescription details to count total medicines
        cursor.execute("SELECT encrypted_data FROM prescriptions WHERE id = %s", (prescription_id,))
        prescription_data = cursor.fetchone()
        total_prescription_medicines = 0
        
        if prescription_data and prescription_data['encrypted_data']:
            try:
                decrypted_data = decrypt_data(prescription_data['encrypted_data'])
                if decrypted_data:
                    data = json.loads(decrypted_data)
                    medicines = data.get('medicines', [])
                    total_prescription_medicines = len(medicines)
            except:
                pass
        
        # Use the larger count to determine completion
        total_medicines = max(verification_stats['total_medicines'], total_prescription_medicines)
        verified_count = verification_stats['verified_count']
        
        if total_medicines > 0 and verified_count >= total_medicines:
            verification_status = 'verified'
        elif verified_count > 0:
            verification_status = 'in_progress'
        else:
            verification_status = 'pending'

        # Update prescription verification
        cursor.execute("""
            INSERT INTO prescription_verification 
            (prescription_id, verification_status, patient_confirmation)
            VALUES (%s, %s, %s)
            ON CONFLICT (prescription_id) 
            DO UPDATE SET 
                verification_status = EXCLUDED.verification_status,
                patient_confirmation = EXCLUDED.patient_confirmation,
                updated_at = NOW()
        """, (prescription_id, verification_status, True))

        conn.commit()

        return jsonify({
            "message": f"Medicine '{medicine_name}' verification updated successfully",
            "verified": verified,
            "verification_status": verification_status,
            "verified_count": verified_count,
            "total_medicines": total_medicines
        })

    except Exception as e:
        print(f"Error in verify_medicine: {str(e)}")
        if conn:
            conn.rollback()
        return jsonify({"error": f"Failed to verify medicine: {str(e)}"}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/prescription-verification/stats/<int:patient_id>", methods=["GET"])
def get_verification_stats(patient_id):
    """Get verification statistics for patient"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get basic counts
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT p.id) as total_prescriptions,
                COUNT(DISTINCT CASE WHEN pv.verification_status = 'verified' THEN p.id END) as verified_prescriptions,
                COUNT(DISTINCT CASE WHEN pv.verification_status = 'in_progress' THEN p.id END) as in_progress_prescriptions,
                COUNT(DISTINCT CASE WHEN pv.verification_status IS NULL OR pv.verification_status = 'pending' THEN p.id END) as pending_prescriptions
            FROM prescriptions p
            LEFT JOIN prescription_verification pv ON p.id = pv.prescription_id
            WHERE p.patient_id = %s
        """, (patient_id,))
        
        prescription_stats = cursor.fetchone()

        # Get medicine counts
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT mv.medicine_name) as total_medicines,
                COUNT(DISTINCT CASE WHEN mv.verified = true THEN mv.medicine_name END) as verified_medicines
            FROM medicine_verification mv
            JOIN prescriptions p ON mv.prescription_id = p.id
            WHERE p.patient_id = %s
        """, (patient_id,))
        
        medicine_stats = cursor.fetchone()

        # If no medicine verification records, try to count from prescriptions
        if medicine_stats['total_medicines'] == 0:
            cursor.execute("""
                SELECT COUNT(*) as total_medicines
                FROM (
                    SELECT p.id, p.encrypted_data
                    FROM prescriptions p
                    WHERE p.patient_id = %s
                ) prescriptions
            """, (patient_id,))
            
            alt_stats = cursor.fetchone()
            total_medicines = alt_stats['total_medicines'] or 0
            verified_medicines = 0
        else:
            total_medicines = medicine_stats['total_medicines']
            verified_medicines = medicine_stats['verified_medicines']

        verification_rate = round((verified_medicines / total_medicines * 100) if total_medicines > 0 else 0, 1)

        stats = {
            **prescription_stats,
            "total_medicines": total_medicines,
            "verified_medicines": verified_medicines
        }

        return jsonify({
            "stats": stats,
            "verification_rate": verification_rate,
            "error": None
        })

    except Exception as e:
        print(f"Error in get_verification_stats: {str(e)}")
        return jsonify({
            "error": f"Failed to get verification stats: {str(e)}",
            "stats": {
                "total_prescriptions": 0,
                "verified_prescriptions": 0,
                "in_progress_prescriptions": 0,
                "pending_prescriptions": 0,
                "total_medicines": 0,
                "verified_medicines": 0
            },
            "verification_rate": 0
        }), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
# ---------------- ENHANCED DOCTOR DASHBOARD ----------------
@app.route("/stats/doctor/<int:doctor_id>", methods=["GET"])
def get_doctor_stats(doctor_id):
    """Get comprehensive statistics for doctor dashboard"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT COUNT(DISTINCT patient_id) as total_patients 
            FROM prescriptions 
            WHERE doctor_id = %s
        """, (doctor_id,))
        total_patients = cursor.fetchone()["total_patients"]

        cursor.execute("""
            SELECT COUNT(*) as todays_appointments 
            FROM appointments 
            WHERE doctor_id = %s AND date = CURRENT_DATE
        """, (doctor_id,))
        todays_appointments = cursor.fetchone()["todays_appointments"]

        cursor.execute("""
            SELECT COUNT(*) as monthly_prescriptions 
            FROM prescriptions 
            WHERE doctor_id = %s AND EXTRACT(MONTH FROM created_at) = EXTRACT(MONTH FROM CURRENT_DATE) 
            AND EXTRACT(YEAR FROM created_at) = EXTRACT(YEAR FROM CURRENT_DATE)
        """, (doctor_id,))
        monthly_prescriptions = cursor.fetchone()["monthly_prescriptions"]

        cursor.execute("""
            SELECT COUNT(DISTINCT patient_id) as urgent_cases 
            FROM patient_records 
            WHERE doctor_id = %s AND severity = 'high' 
            AND created_at >= NOW() - INTERVAL '7 days'
        """, (doctor_id,))
        urgent_cases = cursor.fetchone()["urgent_cases"]

        cursor.execute("""
            SELECT 
                TO_CHAR(created_at, 'Day') as day,
                COUNT(*) as prescriptions
            FROM prescriptions 
            WHERE doctor_id = %s AND created_at >= NOW() - INTERVAL '7 days'
            GROUP BY TO_CHAR(created_at, 'Day'), EXTRACT(DOW FROM created_at)
            ORDER BY EXTRACT(DOW FROM created_at)
        """, (doctor_id,))
        weekly_trend = cursor.fetchall()

        return jsonify({
            "totalPatients": total_patients,
            "todaysAppointments": todays_appointments,
            "monthlyPrescriptions": monthly_prescriptions,
            "urgentCases": urgent_cases,
            "weeklyTrend": weekly_trend
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/notifications/doctor/<int:doctor_id>", methods=["GET"])
def get_doctor_notifications(doctor_id):
    """Get notifications for doctor"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT 
                CONCAT('Appointment with ', p.name, ' at ', a.time) as title,
                CONCAT('Reason: ', COALESCE(a.reason, 'General Checkup')) as message,
                a.date as notification_date,
                'appointment' as type
            FROM appointments a
            JOIN users p ON a.patient_id = p.id
            WHERE a.doctor_id = %s AND a.date = CURRENT_DATE AND a.status = 'accepted'
            ORDER BY a.time ASC
            LIMIT 5
        """, (doctor_id,))
        
        appointments = cursor.fetchall()

        cursor.execute("""
            SELECT 
                CONCAT('New appointment request from ', p.name) as title,
                CONCAT('Date: ', a.date, ' | Time: ', a.time) as message,
                a.created_at as notification_date,
                'appointment_request' as type
            FROM appointments a
            JOIN users p ON a.patient_id = p.id
            WHERE a.doctor_id = %s AND a.status = 'pending'
            ORDER BY a.created_at DESC
            LIMIT 5
        """, (doctor_id,))
        
        pending_requests = cursor.fetchall()

        notifications = appointments + pending_requests
        notifications.sort(key=lambda x: x['notification_date'], reverse=True)
        
        return jsonify(notifications[:10])
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/hospital/doctor/<int:doctor_id>", methods=["GET"])
def get_hospital_by_doctor(doctor_id):
    """Get hospital information for a specific doctor"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT a.hospital_name, a.hospital_address 
            FROM admins a
            JOIN users u ON u.admin_id = a.id
            WHERE u.id = %s
            LIMIT 1
        """, (doctor_id,))
        
        hospital = cursor.fetchone()
        
        if not hospital:
            cursor.execute("SELECT hospital_name, hospital_address FROM admins LIMIT 1")
            hospital = cursor.fetchone()
        
        if hospital:
            return jsonify(hospital)
        else:
            return jsonify({
                "hospital_name": "Medical Center",
                "hospital_address": "123 Healthcare Street, City, State"
            })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/prescriptions/doctor/<int:doctor_id>/recent-detailed", methods=["GET"])
def get_recent_patients_detailed(doctor_id):
    """Get detailed recent patient information with prescription counts"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT 
                p.id AS patient_id,
                p.name AS patient_name,
                p.age,
                p.weight,
                MAX(pr.created_at) AS last_visit_date,
                COUNT(pr.id) AS total_prescriptions,
                (
                    SELECT pr2.diagnosis 
                    FROM patient_records pr2 
                    WHERE pr2.patient_id = p.id AND pr2.doctor_id = %s 
                    ORDER BY pr2.created_at DESC 
                    LIMIT 1
                ) AS last_condition,
                (
                    CASE 
                        WHEN MAX(pr.created_at) >= NOW() - INTERVAL '1 day' THEN 'urgent'
                        WHEN MAX(pr.created_at) >= NOW() - INTERVAL '7 days' THEN 'recent' 
                        ELSE 'routine'
                    END
                ) AS urgency_level
            FROM prescriptions pr
            JOIN users p ON pr.patient_id = p.id
            WHERE pr.doctor_id = %s
            GROUP BY p.id, p.name, p.age, p.weight
            ORDER BY last_visit_date DESC
            LIMIT 20
        """, (doctor_id, doctor_id))
        
        patients = cursor.fetchall()
        
        for patient in patients:
            if isinstance(patient.get("last_visit_date"), datetime):
                patient["last_visit_date"] = patient["last_visit_date"].strftime("%Y-%m-%d %H:%M:%S")
        
        return jsonify({"patients": patients})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/prescriptions/doctor/<int:doctor_id>/recent", methods=["GET"])
def get_last_attended_patients(doctor_id):
    """Fetch patients attended by the doctor, ordered by most recent prescription."""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("""
            SELECT 
                p.id AS patient_id,
                p.name AS name,
                MAX(pr.created_at) AS last_prescription_time,
                DATE(MAX(pr.created_at)) AS last_visit_date,
                COUNT(pr.id) AS total_prescriptions,
                (
                    SELECT id FROM prescriptions 
                    WHERE patient_id = p.id AND doctor_id = %s 
                    ORDER BY created_at DESC LIMIT 1
                ) AS last_prescription_id
            FROM prescriptions pr
            JOIN users p ON pr.patient_id = p.id
            WHERE pr.doctor_id = %s
            GROUP BY p.id, p.name
            ORDER BY last_prescription_time DESC
            LIMIT 10
        """, (doctor_id, doctor_id))

        patients = cursor.fetchall()

        for p in patients:
            if isinstance(p.get("last_prescription_time"), datetime):
                p["last_prescription_time"] = p["last_prescription_time"].strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(p.get("last_visit_date"), (datetime, date)):
                p["last_visit_date"] = p["last_visit_date"].strftime("%Y-%m-%d")

        return jsonify({"patients": patients})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ---------------- DEBUG & DIAGNOSTIC ENDPOINTS ----------------
@app.route("/diagnose-record-issue", methods=["GET"])
def diagnose_record_issue():
    """Diagnostic endpoint to identify why records aren't saving properly"""
    try:
        test_data = {
            "patient_id": 10,
            "doctor_id": 19,
            "diagnosis": "Test Diagnosis",
            "symptoms": "Test Symptoms", 
            "current_condition": "Test Condition",
            "treatment_plan": "Test Treatment"
        }
        
        encrypted = encrypt_data(json.dumps(test_data))
        decrypted = decrypt_data(encrypted)
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'patient_records' 
            ORDER BY ordinal_position
        """)
        table_structure = cursor.fetchall()
        
        cursor.execute("""
            SELECT id, patient_id, doctor_id, diagnosis, symptoms, LENGTH(scan_report::text) as data_length 
            FROM patient_records 
            ORDER BY id DESC LIMIT 5
        """)
        recent_records = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "encryption_test": {
                "works": bool(decrypted),
                "original": test_data,
                "decrypted": json.loads(decrypted) if decrypted else None
            },
            "table_structure": table_structure,
            "recent_records": recent_records,
            "aes_config": {
                "key_length": len(AES_KEY)
            }
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/migrate-records", methods=["POST"])
def migrate_records():
    """Migrate existing encrypted records to individual field format"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT id, scan_report, patient_id, doctor_id, created_at, updated_at
            FROM patient_records 
            WHERE scan_report IS NOT NULL AND scan_report != '' 
            AND (diagnosis IS NULL OR diagnosis = '')
        """)
        records_to_migrate = cursor.fetchall()
        
        migrated_count = 0
        error_count = 0
        
        for record in records_to_migrate:
            try:
                decrypted_data = decrypt_data(record["scan_report"])
                if decrypted_data:
                    data = json.loads(decrypted_data)
                    
                    cursor.execute("""
                        UPDATE patient_records 
                        SET 
                            past_diseases = %s, current_condition = %s, diagnosis = %s,
                            symptoms = %s, treatment_plan = %s, medications = %s,
                            blood_pressure = %s, heart_rate = %s, temperature = %s,
                            weight = %s, height = %s, blood_sugar = %s,
                            oxygen_saturation = %s, allergies = %s, follow_up_date = %s,
                            next_appointment_date = %s, doctor_notes = %s,
                            record_type = %s, severity = %s, updated_at = NOW()
                        WHERE id = %s
                    """, (
                        data.get("past_diseases", ""), data.get("current_condition", ""),
                        data.get("diagnosis", ""), data.get("symptoms", ""),
                        data.get("treatment_plan", ""), data.get("medicines", ""),
                        data.get("blood_pressure", ""), data.get("heart_rate"),
                        data.get("temperature"), data.get("weight"), data.get("height"),
                        data.get("blood_sugar"), data.get("oxygen_saturation"),
                        data.get("allergies", ""), data.get("follow_up_date"),
                        data.get("next_appointment_date"), data.get("doctor_notes", ""),
                        data.get("record_type", "consultation"), data.get("severity", "medium"),
                        record["id"]
                    ))
                    
                    migrated_count += 1
                    print(f"Migrated record {record['id']}")
                    
            except Exception as e:
                error_count += 1
                print(f"Error migrating record {record['id']}: {e}")
        
        conn.commit()
        
        return jsonify({
            "message": f"Migration completed: {migrated_count} records migrated, {error_count} errors",
            "migrated_count": migrated_count,
            "error_count": error_count
        })
        
    except Exception as e:
        return jsonify({"error": f"Migration failed: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/test_decryption", methods=["GET"])
def test_decryption():
    """Test AES decryption with a known prescription"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT id, encrypted_data FROM prescriptions LIMIT 1")
        prescription = cursor.fetchone()
        
        if not prescription:
            return jsonify({"error": "No prescriptions found"}), 404

        result = {
            "prescription_id": prescription["id"],
            "encrypted_data_length": len(prescription["encrypted_data"]),
            "encrypted_preview": prescription["encrypted_data"][:100] + "..."
        }

        encrypted_data = prescription["encrypted_data"]
        decrypted = decrypt_data(encrypted_data)
        
        result["decryption_success"] = bool(decrypted)
        result["decrypted_data"] = decrypted if decrypted else "Decryption failed"
        
        if decrypted:
            try:
                parsed = json.loads(decrypted)
                result["json_parse_success"] = True
                result["parsed_data"] = parsed
            except json.JSONDecodeError as e:
                result["json_parse_success"] = False
                result["json_error"] = str(e)

        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/debug_prescription/<int:prescription_id>", methods=["GET"])
def debug_prescription(prescription_id):
    """Debug endpoint to check prescription decryption"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM prescriptions WHERE id = %s", (prescription_id,))
        prescription = cursor.fetchone()
        
        if not prescription:
            return jsonify({"error": "Prescription not found"}), 404

        result = {
            "prescription_id": prescription["id"],
            "patient_name": prescription["patient_name"],
            "doctor_name": prescription["doctor_name"],
            "encrypted_data_length": len(prescription["encrypted_data"]) if prescription["encrypted_data"] else 0,
            "encrypted_data_preview": prescription["encrypted_data"][:100] + "..." if prescription["encrypted_data"] else None,
            "created_at": prescription["created_at"]
        }

        if prescription["encrypted_data"]:
            try:
                decrypted = decrypt_data(prescription["encrypted_data"])
                result["decryption_success"] = bool(decrypted)
                result["decrypted_length"] = len(decrypted) if decrypted else 0
                result["decrypted_preview"] = decrypted[:200] + "..." if decrypted else None
                
                if decrypted:
                    try:
                        parsed_data = json.loads(decrypted)
                        result["parse_success"] = True
                        result["parsed_data"] = parsed_data
                    except json.JSONDecodeError as e:
                        result["parse_success"] = False
                        result["parse_error"] = str(e)
                        result["raw_decrypted"] = decrypted
            except Exception as e:
                result["decryption_success"] = False
                result["decryption_error"] = str(e)

        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/debug-record/<int:record_id>", methods=["GET"])
def debug_record(record_id):
    """Debug endpoint to check encryption/decryption for a specific record"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT * FROM patient_records WHERE id = %s", (record_id,))
        record = cursor.fetchone()
        
        if not record:
            return jsonify({"error": "Record not found"}), 404

        result = {
            "record_id": record["id"],
            "patient_id": record["patient_id"],
            "doctor_id": record["doctor_id"],
            "diagnosis": record["diagnosis"],
            "symptoms": record["symptoms"],
            "scan_report_length": len(record["scan_report"]) if record["scan_report"] else 0,
            "encrypted_data_preview": record["scan_report"][:100] + "..." if record["scan_report"] else None,
            "created_at": record["created_at"]
        }

        if record["scan_report"]:
            try:
                decrypted = decrypt_data(record["scan_report"])
                result["decryption_success"] = bool(decrypted)
                result["decrypted_length"] = len(decrypted) if decrypted else 0
                
                if decrypted:
                    try:
                        parsed_data = json.loads(decrypted)
                        result["parsed_data"] = parsed_data
                        result["parse_success"] = True
                    except json.JSONDecodeError as e:
                        result["parse_success"] = False
                        result["parse_error"] = str(e)
                        result["raw_decrypted"] = decrypted
            except Exception as e:
                result["decryption_success"] = False
                result["decryption_error"] = str(e)

        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/debug-aes", methods=["GET"])
def debug_aes():
    """Debug AES configuration"""
    test_data = "Hello, World!"
    encrypted = encrypt_data(test_data)
    decrypted = decrypt_data(encrypted)
    
    return jsonify({
        "aes_key_length": len(AES_KEY),
        "aes_key_preview": AES_KEY[:8] + "..." + AES_KEY[-8:],
        "test_data": test_data,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "success": test_data == decrypted
    })

# ---------------- UTILITY ENDPOINTS ----------------
@app.route("/doctors", methods=["GET"])
def get_all_doctors():
    """Get all doctors"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT id, name, email, specialization FROM users WHERE role = 'doctor'")
        doctors = cursor.fetchall()
        return jsonify(doctors)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/patients", methods=["GET"])
def get_all_patients():
    """Get all patients"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT id, name, email, age, weight FROM users WHERE role = 'patient'")
        patients = cursor.fetchall()
        return jsonify(patients)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/hospital", methods=["GET"])
def get_hospital_info():
    """Get hospital information"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT hospital_name, hospital_address FROM admins LIMIT 1")
        hospital = cursor.fetchone()
        
        if not hospital:
            return jsonify({"error": "No hospital found"}), 404
            
        return jsonify(hospital)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route("/admins", methods=["GET"])
def get_all_admins():
    """Get all admins"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT id, name, email, hospital_name, hospital_address FROM admins")
        admins = cursor.fetchall()
        return jsonify(admins)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ---------------- FILE UPLOADS ----------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    """Serve uploaded files"""
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ---------------- ERROR HANDLING ----------------
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# ---------------- RUN APPLICATION ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
