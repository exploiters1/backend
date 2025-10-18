from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import bcrypt
import os
import json
from datetime import datetime
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ---------------- CONFIG ----------------
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------------- AES CONFIG ----------------
AES_KEY = os.environ.get("AES_KEY", "ThisIsASecretKey")
AES_IV = os.environ.get("AES_IV", "ThisIsAnInitVect")

if len(AES_KEY) not in (16, 24, 32):
    raise ValueError(f"AES_KEY must be 16, 24, or 32 bytes long, got {len(AES_KEY)}")
if len(AES_IV) != 16:
    raise ValueError(f"AES_IV must be 16 bytes long, got {len(AES_IV)}")

def encrypt_data(plaintext: str) -> str:
    cipher = AES.new(AES_KEY.encode("utf-8"), AES.MODE_CBC, AES_IV.encode("utf-8"))
    ct_bytes = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return base64.b64encode(ct_bytes).decode("utf-8")

def decrypt_data(ciphertext: str) -> str:
    try:
        ct_bytes = base64.b64decode(ciphertext)
        cipher = AES.new(AES_KEY.encode("utf-8"), AES.MODE_CBC, AES_IV.encode("utf-8"))
        pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        return pt.decode("utf-8")
    except Exception as e:
        print("Decryption error:", e)
        return ""

# ---------------- DATABASE ----------------
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="encryptedmed"
        )
        return conn
    except Error as e:
        print(f"DB Connection Error: {e}")
        return None

# ---------------- ROOT ----------------
@app.route("/")
def home():
    return jsonify({"message": "Flask backend running ✅"})

# ---------------- REGISTER ----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
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

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        cursor.close()
        conn.close()
        return jsonify({"error": "User already exists"}), 400

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    cursor.execute(
        "INSERT INTO users (name,email,password,role,specialization) VALUES (%s,%s,%s,%s,%s)",
        (name, email, hashed_pw.decode("utf-8"), role, specialization)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": f"{role.capitalize()} registered successfully ✅"}), 201

# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")

    if not email or not password or role not in ["doctor", "patient"]:
        return jsonify({"error": "Invalid input"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s AND role=%s", (email, role))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

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

# ---------------- GET ALL PATIENTS ----------------
@app.route("/patients", methods=["GET"])
def get_patients():
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, name, age, weight, email, phone_number FROM users WHERE role='patient'")
    patients = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(patients)

# ---------------- GET SINGLE PATIENT ----------------
@app.route("/profile/patient/<int:user_id>", methods=["GET"])
def get_patient(user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id=%s AND role='patient'", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({"error": "Patient not found"}), 404

    if user.get("profile_pic"):
        user["profile_pic_url"] = f"{request.host_url}uploads/{user['profile_pic']}"
    if user.get("signature"):
        user["signature_url"] = f"{request.host_url}uploads/{user['signature']}"

    return jsonify(user)

# ---------------- PROFILE (GET & UPDATE) ----------------
@app.route("/profile/<role>/<int:user_id>", methods=["GET", "PUT"])
def profile(role, user_id):
    if role not in ["doctor", "patient"]:
        return jsonify({"error": "Invalid role"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)

    if request.method == "GET":
        cursor.execute("SELECT * FROM users WHERE id=%s AND role=%s", (user_id, role))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if not user:
            return jsonify({"error": f"{role.capitalize()} not found"}), 404
        if user.get("profile_pic"):
            user["profile_pic_url"] = f"{request.host_url}uploads/{user['profile_pic']}"
        if user.get("signature"):
            user["signature_url"] = f"{request.host_url}uploads/{user['signature']}"
        return jsonify(user)

    # PUT update
    try:
        form = request.form
        profile_pic_file = request.files.get("profile_pic")
        signature_file = request.files.get("signature")

        updates = []
        values = []

        for field in ["name", "email", "specialization", "age", "weight",
                      "phone_number", "address", "city", "pincode", "state", "date_of_birth"]:
            if form.get(field):
                updates.append(f"{field}=%s")
                values.append(form.get(field))

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
        cursor.close()
        conn.close()
        return jsonify({"message": f"{role.capitalize()} profile updated successfully ✅"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- PATIENT RECORDS ----------------
@app.route("/patient-records/<int:patient_id>", methods=["GET"])
def get_patient_records(patient_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT pr.*, u.name AS doctor_name
        FROM patient_records pr
        JOIN users u ON pr.doctor_id=u.id
        WHERE pr.patient_id=%s
    """, (patient_id,))
    records = cursor.fetchall()
    cursor.close()
    conn.close()

    for r in records:
        if r.get("scan_report"):
            decrypted = decrypt_data(r["scan_report"])
            try:
                data = json.loads(decrypted)
                r["past_diseases"] = data.get("past_diseases", "")
                r["current_condition"] = data.get("current_condition", "")
                r["scan_report"] = data.get("scan_report", None)
            except:
                r["past_diseases"] = ""
                r["current_condition"] = ""
                r["scan_report"] = None
        else:
            r["past_diseases"] = ""
            r["current_condition"] = ""
            r["scan_report"] = None

    return jsonify(records)


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
        cursor.execute("""
            INSERT INTO patient_records
            (patient_id, doctor_id, scan_report)
            VALUES (%s,%s,%s)
        """, (patient_id, doctor_id, encrypted_record))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"message": "Patient record added successfully ✅"})
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
        cursor.execute("SELECT * FROM patient_records WHERE id=%s", (record_id,))
        record = cursor.fetchone()
        if not record:
            cursor.close()
            conn.close()
            return jsonify({"error": "Record not found"}), 404
        if int(record["doctor_id"]) != int(doctor_id):
            cursor.close()
            conn.close()
            return jsonify({"error": "You can only modify your own records"}), 403

        existing_data = json.loads(decrypt_data(record["scan_report"]))

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
        cursor.close()
        conn.close()
        return jsonify({"message": "Record updated successfully ✅"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- PRESCRIPTIONS ----------------
@app.route("/save", methods=["POST"])
def save_prescription():
    try:
        data = request.get_json()
        doctor_id = data.get("doctor_id")
        doctor_name = data.get("doctor_name")
        patient_id = data.get("patient_id")
        patient_name = data.get("patient_name")
        patient_age = data.get("patient_age")
        patient_weight = data.get("patient_weight")
        prescription = data.get("prescription", "")
        medicines = data.get("medicines", [])
        issue_date = datetime.now().strftime("%Y-%m-%d")
        validity_days = data.get("validity_days", 30)

        if not all([doctor_id, patient_id, prescription]):
            return jsonify({"error": "Missing required data"}), 400

        prescription_content = json.dumps({
            "prescription": prescription,
            "medicines": medicines,
            "issue_date": issue_date,
            "validity_days": validity_days
        })
        encrypted_prescription = encrypt_data(prescription_content)

        conn = get_db_connection()
        cursor = conn.cursor()
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
        cursor.close()
        conn.close()

        return jsonify({"message": "Prescription saved successfully ✅"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/prescriptions/<int:patient_id>/<int:doctor_id>", methods=["GET"])
def get_prescriptions(patient_id, doctor_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM prescriptions
            WHERE patient_id=%s AND doctor_id=%s
            ORDER BY created_at DESC
        """, (patient_id, doctor_id))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        prescriptions = []
        for r in rows:
            decrypted = decrypt_data(r["encrypted_data"])
            try:
                data = json.loads(decrypted)
                prescriptions.append({
                    "id": r["id"],
                    "doctor_id": r["doctor_id"],
                    "doctor_name": r["doctor_name"],
                    "patient_id": r["patient_id"],
                    "patient_name": r["patient_name"],
                    "patient_age": r["patient_age"],
                    "patient_weight": r["patient_weight"],
                    "prescription": data.get("prescription", ""),
                    "medicines": data.get("medicines", []),
                    "issue_date": data.get("issue_date", ""),
                    "validity_days": data.get("validity_days", 30),
                    "created_at": r["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                })
            except:
                continue

        return jsonify(prescriptions)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- NEW: GET ALL PRESCRIPTIONS OF DOCTOR ----------------
@app.route("/prescriptions/doctor/<int:doctor_id>", methods=["GET"])
def get_doctor_prescriptions(doctor_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM prescriptions
            WHERE doctor_id=%s
            ORDER BY created_at DESC
        """, (doctor_id,))
        rows = cursor.fetchall()

        # Get doctor's signature URL
        cursor.execute("SELECT signature FROM users WHERE id=%s", (doctor_id,))
        sig_row = cursor.fetchone()
        doctor_signature_url = None
        if sig_row and sig_row.get("signature"):
            doctor_signature_url = f"{request.host_url}uploads/{sig_row['signature']}"

        cursor.close()
        conn.close()

        prescriptions = []
        for r in rows:
            decrypted = decrypt_data(r["encrypted_data"])
            try:
                data = json.loads(decrypted)
                prescriptions.append({
                    "id": r["id"],
                    "doctor_id": r["doctor_id"],
                    "doctor_name": r["doctor_name"],
                    "doctor_signature": doctor_signature_url,
                    "patient_id": r["patient_id"],
                    "patient_name": r["patient_name"],
                    "patient_age": r["patient_age"],
                    "patient_weight": r["patient_weight"],
                    "prescription": data.get("prescription", ""),
                    "medicines": data.get("medicines", []),
                    "issue_date": data.get("issue_date", ""),
                    "validity_days": data.get("validity_days", 30),
                    "created_at": r["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                })
            except:
                continue

        return jsonify(prescriptions)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- UPLOADS ----------------
@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
