import sqlite3
import re
import os
import html
import base64
import uuid
import qrcode
import hashlib
from flask import Blueprint, request, jsonify, session,render_template,redirect,url_for,flash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import secrets
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from datetime import datetime


DATABASE = "instance/db.sqlite3"
ALLOWED_EXTENSIONS = {"mp4", "avi", "mov"}
INSTANCE_FOLDER = "instance"
DB_PATH = os.path.join(INSTANCE_FOLDER, "db.sqlite3")
VIDEO_UPLOAD_FOLDER = "static/videos"

# Instead of using app.config, use a dict manually
mail = Mail()
mail_settings = {
    'MAIL_SERVER': 'smtp.gmail.com',
    'MAIL_PORT': 587,
    'MAIL_USE_TLS': True,
    'MAIL_USERNAME': 'your_gmail',
    'MAIL_PASSWORD': 'your_password',
    'MAIL_DEFAULT_SENDER': 'default_mail'
}
# Ensure the instance folder exists
os.makedirs(INSTANCE_FOLDER, exist_ok=True)

UPLOAD_FOLDER_UPI = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER_UPI, exist_ok=True)  # Ensure the folder exists
routes_bp = Blueprint("routes", __name__)

def get_db_connection():
    """Creates a database connection and returns the cursor."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def sanitize_input(user_input):
    if not user_input:
        return ""  # Return an empty string if None or empty
    return html.escape(str(user_input).strip())  # Convert to string first

def hash_password(password):
    """Hashes passwords using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    """Checks if file extension is allowed."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_token():
    return secrets.token_urlsafe(32)

def token_expiry_time(minutes=30):
    return (datetime.utcnow() + timedelta(minutes=minutes)).strftime('%Y-%m-%d %H:%M:%S')
def confirm_token(token, expiration=3600):  # 1 hour
    serializer = URLSafeTimedSerializer("a3f5c9b1e86f4b74f4d0c7e7f5b05f3e6b243892bc3a5e2cbd12d5fa5d09c2d9")
    try:
        return serializer.loads(token, salt="password-reset-salt", max_age=expiration)
    except Exception:
        return False
    
def send_reset_email(email, token):
    reset_link = url_for('routes.reset_password', token=token, _external=True)
    msg = Message("Reset Your Password", recipients=[email])
    msg.body = f"""
    Hello,

    To reset your password, click the link below:
    {reset_link}

    If you didn’t request this, you can safely ignore this email.
    """
    mail.send(msg)


"""  CONTEXT PROCESSOR """
@routes_bp.context_processor
def inject_pending_count():
    user_id = session.get("user_id")
    
    if not user_id:
        return {"pending_count": 0}

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Count pending payments where user is the creator
    cursor.execute(
        "SELECT COUNT(*) FROM transactions WHERE creator_id = ? AND status = 'pending_review'",
        (user_id,)
    )
    pending_count = cursor.fetchone()[0]
    
    conn.close()
    
    return {"pending_count": pending_count}


"""---------------------------------------------  API REQUESTS ---------------------------------------------"""
"""---------------------------------------------  API REQUESTS ---------------------------------------------"""

@routes_bp.route("/api/request_swap", methods=["POST"])
def api_request_swap():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized! Please log in."}), 401

    data = request.json

    try:
        requester_id = session["user_id"]  # ✅ Get logged-in user's ID
        requested_skill_id = int(sanitize_input(str(data.get("requested_skill_id", "")).strip()))
        offered_skill_id = int(sanitize_input(str(data.get("offered_skill_id", "")).strip()))
    except ValueError:
        return jsonify({"error": "Invalid input! IDs must be numbers."}), 400

    if not requested_skill_id or not offered_skill_id:
        return jsonify({"error": "All fields are required!"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO skill_swaps (requester_id, requested_skill_id, offered_skill_id, status)
            VALUES (?, ?, ?, 'pending')
        """, (requester_id, requested_skill_id, offered_skill_id))

        conn.commit()
        return jsonify({"message": "Skill swap request submitted!"}), 201
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@routes_bp.route("/api/pending_swaps", methods=["GET"])
def api_get_pending_swaps():
    """Fetch all pending swap requests for the logged-in user."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized! Please log in."}), 401

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT ss.id, ss.requested_skill_id, ss.offered_skill_id, ss.status, 
                   u.username AS requester_name, sk1.title AS requested_skill, sk2.title AS offered_skill
            FROM skill_swaps ss
            JOIN users u ON ss.requester_id = u.id
            JOIN skills sk1 ON ss.requested_skill_id = sk1.id
            JOIN skills sk2 ON ss.offered_skill_id = sk2.id
            WHERE sk1.user_id = ? AND ss.status = 'pending'
        """, (user_id,))

        swaps = cursor.fetchall()

        return jsonify([{
            "swap_id": swap["id"],
            "requester_name": swap["requester_name"],
            "requested_skill": swap["requested_skill"],
            "offered_skill": swap["offered_skill"],
            "status": swap["status"]
        } for swap in swaps]), 200

    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


@routes_bp.route("/api/update_swap", methods=["POST"])
def api_update_swap():
    """Accept or reject a skill swap request securely."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized! Please log in."}), 401

    data = request.json

    # Sanitize input
    try:
        swap_id = int(sanitize_input(str(data.get("swap_id", "")).strip()))
        action = sanitize_input(str(data.get("action", "")).strip().lower())
    except ValueError:
        return jsonify({"error": "Invalid input! swap_id must be a number."}), 400

    if not swap_id or action not in ["accept", "reject"]:
        return jsonify({"error": "Invalid request! Provide swap_id and action (accept/reject)."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if the swap request exists and belongs to the logged-in user
        cursor.execute("""
            SELECT ss.id, ss.requested_skill_id, sk.user_id AS skill_owner
            FROM skill_swaps ss
            JOIN skills sk ON ss.requested_skill_id = sk.id
            WHERE ss.id = ? AND sk.user_id = ?
        """, (swap_id, session["user_id"]))

        swap = cursor.fetchone()

        if not swap:
            return jsonify({"error": "Swap request not found or unauthorized!"}), 403

        # 🔥 Fix: Match DB constraint values
        new_status = "approved" if action == "accept" else "rejected"

        if new_status == "approved":
            cursor.execute("""
                INSERT INTO completed_swaps (requester_id, requested_skill_id, offered_skill_id)
                SELECT requester_id, requested_skill_id, offered_skill_id FROM skill_swaps WHERE id = ?
            """, (swap_id,))

        # Update the swap request status
        cursor.execute("""
            UPDATE skill_swaps SET status = ? WHERE id = ?
        """, (new_status, swap_id))

        conn.commit()
        return jsonify({"message": f"Skill swap request {new_status} successfully!"}), 200

    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@routes_bp.route("/api/get_swaps", methods=["GET"])
def api_get_swaps():
    """Get all skill swap requests related to the logged-in user."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized! Please log in."}), 401

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT ss.id, ss.requester_id, ss.requested_skill_id, ss.offered_skill_id, ss.status,
                   r.username AS requester_name, o.username AS owner_name,
                   sr.title AS requested_skill, so.title AS offered_skill
            FROM skill_swaps ss
            JOIN users r ON ss.requester_id = r.id
            JOIN users o ON sr.user_id = o.id
            JOIN skills sr ON ss.requested_skill_id = sr.id
            JOIN skills so ON ss.offered_skill_id = so.id
            WHERE ss.requester_id = ? OR sr.user_id = ?
        """, (user_id, user_id))

        swaps = cursor.fetchall()

        return jsonify({"swaps": [dict(s) for s in swaps]}), 200

    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@routes_bp.route("/api/cancel_swap", methods=["POST"])
def api_cancel_swap():
    """Cancel a skill swap request if it's still pending."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized! Please log in."}), 401

    data = request.json

    # Sanitize input
    try:
        swap_id = int(sanitize_input(str(data.get("swap_id", "")).strip()))
    except ValueError:
        return jsonify({"error": "Invalid swap ID!"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Ensure only the requester can cancel the request
        cursor.execute("""
            SELECT id FROM skill_swaps
            WHERE id = ? AND requester_id = ? AND status = 'pending'
        """, (swap_id, session["user_id"]))

        swap = cursor.fetchone()

        if not swap:
            return jsonify({"error": "Swap request not found or cannot be canceled!"}), 403

        # Delete the swap request
        cursor.execute("DELETE FROM skill_swaps WHERE id = ?", (swap_id,))
        conn.commit()

        return jsonify({"message": "Swap request canceled successfully!"}), 200

    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

#---------------------------------------------------------------------------
@routes_bp.route("/api/upload_skill", methods=["POST"])
def api_upload_skill():
    """Uploads a new skill (without videos)"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized! Please log in."}), 401

    user_id = session["user_id"]
    title = sanitize_input(request.form.get("title", "").strip())
    description = sanitize_input(request.form.get("description", "").strip())
    amount = request.form.get("amount", "0.0")
    print(user_id,title,description,amount)
    try:
        amount = float(amount)
    except ValueError:
        return jsonify({"error": "Invalid amount!"}), 400

    if not title or not description:
        return jsonify({"error": "Title and description are required!"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert the new skill into the 'skills' table (without video)
    cursor.execute(
        "INSERT INTO skills (user_id, title, description, amount) VALUES (?, ?, ?, ?)",
        (user_id, title, description, amount),
    )

    skill_id = cursor.lastrowid  # Get the new skill ID

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Skill uploaded successfully! Now upload videos separately.",
        "skill_id": skill_id,
        "amount": amount
    }), 201

@routes_bp.route("/api/upload_video", methods=["POST"])
def api_upload_video():
    if "video" not in request.files:
        return jsonify({"error": "No video file uploaded"}), 400

    file = request.files["video"]
    skill_id = request.form.get("skill_id")
    title = request.form.get("title")
    amount = request.form.get("amount")  # Fetch amount
    if not skill_id or not title or not amount:
        return jsonify({"error": "Missing required fields"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(VIDEO_UPLOAD_FOLDER, filename)
    file.save(filepath)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Insert video details into the database
    cursor.execute("""
        INSERT INTO videos (skill_id, title, video_path, amount)
        VALUES (?, ?, ?, ?)
    """, (skill_id, title, filename, amount))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Video uploaded successfully!",
        "video_path": filepath
    })


# ------------------------------------------------------------------------------------------------------------------------


@routes_bp.route("/api/register", methods=["POST"])
def api_register():
    data = request.json
    username = sanitize_input(data.get("username", ""))
    email = sanitize_input(data.get("email", ""))
    password = data.get("password", "")
    upi_id = sanitize_input(data.get("upi_id", ""))  # Get UPI ID (optional)

    if not username or not email or not password:
        return jsonify({"error": "All fields are required!"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long!"}), 400

    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return jsonify({"error": "Invalid email format!"}), 400

    hashed_password = hash_password(password)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password, upi_id) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, upi_id if upi_id else None),
        )
        conn.commit()
        return jsonify({"message": "User registered successfully!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists!"}), 400
    finally:
        conn.close()


@routes_bp.route("/api/login", methods=["POST"])
def api_login():
    data = request.json
    email = sanitize_input(data.get("email", ""))
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required!"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid email or password!"}), 401

    stored_password = user["password"]
    if hash_password(password) != stored_password:
        return jsonify({"error": "Invalid email or password!"}), 401

    # Set session after successful login
    session["user_id"] = user["id"]
    session["username"] = user["username"]

    return jsonify({"message": "Login successful!", "username": user["username"]}), 200

@routes_bp.route("/api/logout", methods=["POST"])
def api_logout():
    """Clears user session and logs out the user."""
    session.clear()
    return jsonify({"message": "Logged out successfully!"}), 200


""" ---------------------------------------------------                  PAYMENT APIS                 ----------------------------------------------------------"""

@routes_bp.route("/api/verify_payment", methods=["POST"])
def api_verify_payment():
    """Verify payment by uploading proof."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized! Please log in."}), 401

    if "payment_proof" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["payment_proof"]
    order_id = sanitize_input(request.form.get("order_id", "").strip())

    if not order_id:
        return jsonify({"error": "Order ID is required"}), 400

    # Validate file type
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
    file_extension = file.filename.rsplit(".", 1)[-1].lower()

    if file_extension not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Invalid file type! Allowed: PNG, JPG, JPEG, PDF"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if transaction exists and is pending
        cursor.execute(
            "SELECT user_id FROM transactions WHERE order_id = ? AND status = 'pending'",
            (order_id,),
        )
        transaction = cursor.fetchone()

        if not transaction:
            return jsonify({"error": "Transaction not found or already reviewed"}), 404

        buyer_id = transaction[0]

        # Ensure only the buyer uploads proof
        if session["user_id"] != buyer_id:
            return jsonify({"error": "Unauthorized: Only the buyer can upload payment proof"}), 403

        # Save file securely
        proof_filename = f"proof_{order_id}.{file_extension}"
        proof_path = os.path.join("static/payment_proofs", proof_filename)
        file.save(proof_path)

        # Update transaction status and store proof path
        cursor.execute(
            "UPDATE transactions SET status = 'pending_review', payment_proof = ? WHERE order_id = ?",
            (proof_filename, order_id),
        )
        conn.commit()

        return jsonify({
            "message": "Payment proof uploaded successfully. Awaiting creator approval.",
            "proof_path": proof_path
        })
    except Exception as e:
        conn.rollback()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    finally:
        conn.close()

    
@routes_bp.route("/api/buy_video", methods=["POST"])
def api_buy_video():
    """API to buy a specific video of a skill."""
    data = request.json
    video_id = sanitize_input(str(data.get("video_id", "")))  # Ensure it's a string
    order_id = str(uuid.uuid4())  # Generate a unique order ID

    if not video_id:
        return jsonify({"error": "Video ID is required"}), 400

    try:
        video_id = int(video_id)  # Ensure video_id is an integer
    except ValueError:
        return jsonify({"error": "Invalid video ID"}), 400

    user_id = session.get("user_id")  # Ensure user is logged in
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch video price and skill creator ID
    cursor.execute("""
        SELECT v.title, v.amount, s.user_id 
        FROM videos v 
        JOIN skills s ON v.skill_id = s.id 
        WHERE v.id = ?
    """, (video_id,))
    
    video = cursor.fetchone()
    

    if not video:
        return jsonify({"error": "Video not found"}), 404

    video_title, amount, creator_id = video
    print(video_title,amount)

    # Fetch creator's UPI ID
    cursor.execute("SELECT upi_id FROM users WHERE id = ?", (creator_id,))
    creator = cursor.fetchone()

    if not creator or not creator[0]:
        return jsonify({"error": "Skill creator's UPI ID not found"}), 404

    creator_upi = sanitize_input(creator[0])  # Sanitize UPI ID

    # Generate UPI Payment Link
    upi_link = f"upi://pay?pa={creator_upi}&pn=Skill Marketplace&am={amount}&cu=INR"

    # Generate QR Code
    qr = qrcode.make(upi_link)
    qr_path = f"static/upi_qr/upi_qr_{user_id}.png"
    qr.save(qr_path)

    # Store transaction in DB with video_id
    cursor.execute("""
        INSERT INTO transactions (order_id, user_id, creator_id, video_id, amount, status) 
        VALUES (?, ?, ?, ?, ?, ?)
    """, (order_id, user_id, creator_id, video_id, amount, "pending"))

    conn.commit()
    conn.close()
    
    return jsonify({
        "upi_link": upi_link,
        "qr_code": qr_path,
        "order_id": order_id,
        "video_id": video_id,  # Include video_id in response
        "message": f"Complete the UPI payment for '{video_title}' and upload proof."
    })


@routes_bp.route("/api/approve_payment", methods=["POST"])
def api_approve_payment():
    data = request.json
    order_id = sanitize_input(data.get("order_id", ""))
    approval_status = sanitize_input(data.get("status", ""))  # 'approved' or 'rejected'

    if not order_id or approval_status not in ["approved", "rejected"]:
        return jsonify({"error": "Invalid input"}), 400

    user_id = session.get("user_id")  # Get logged-in user ID
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if transaction exists and is pending review
    cursor.execute(
        "SELECT creator_id, payment_proof FROM transactions WHERE order_id = ? AND status = 'pending_review'",
        (order_id,),
    )
    transaction = cursor.fetchone()

    if not transaction:
        conn.close()
        return jsonify({"error": "Transaction not found or already processed"}), 404

    creator_id, payment_proof = transaction

    # Ensure only the creator can approve/reject the payment
    if user_id != creator_id:
        conn.close()
        return jsonify({"error": "Unauthorized: Only the skill creator can approve this payment"}), 403

    # Update transaction status
    cursor.execute(
        "UPDATE transactions SET status = ? WHERE order_id = ?",
        (approval_status, order_id),
    )
    conn.commit()
    conn.close()

    return jsonify({
        "message": f"Transaction {approval_status}",
        "order_id": order_id
    })

"""---------------------------------------------  PAGE RENDER ROUTES ---------------------------------------------"""
@routes_bp.route("/")
def home():
    """Render home page with featured skills."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT skills.id, skills.title, users.username
        FROM skills
        JOIN users ON skills.user_id = users.id
        ORDER BY skills.id DESC LIMIT 6
    """)


    skills = [{"id": row[0], "name": row[1], "owner": row[2]} for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template("home.html", skills=skills)



@routes_bp.route("/login")
def login_page():
    """Renders the login page"""
    return render_template("login.html")

@routes_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            token = generate_token()
            expiry = token_expiry_time()

            # Remove any old token for this email
            cursor.execute("DELETE FROM password_reset_tokens WHERE email = ?", (email,))

            # Store new token
            cursor.execute("INSERT INTO password_reset_tokens (email, token, expiry_time) VALUES (?, ?, ?)",
                           (email, token, expiry))
            conn.commit()

            send_reset_email(email, token)
            flash('Password reset link sent to your email.', 'success')
        else:
            flash('No account found with that email.', 'danger')

        conn.close()
    
    return render_template('forgot_password.html')


@routes_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch the token from DB
    cursor.execute("SELECT email, expiry_time FROM password_reset_tokens WHERE token = ?", (token,))
    record = cursor.fetchone()

    if not record:
        flash("Invalid or expired token.", "danger")
        conn.close()
        return redirect(url_for('routes.forgot_password'))

    email, expiry_str = record

    # Check expiry
    expiry = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
    if datetime.utcnow() > expiry:
        flash("Token has expired. Please try again.", "danger")
        cursor.execute("DELETE FROM password_reset_tokens WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return redirect(url_for('routes.forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return render_template('reset_password.html', token=token)

        # Hash the password (important!)
        hashed = hash_password(password)

        # Update password in users table
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, email))

        # Delete token after use
        cursor.execute("DELETE FROM password_reset_tokens WHERE token = ?", (token,))
        conn.commit()
        conn.close()

        flash("Password reset successful! You can now log in.", "success")
        return redirect(url_for('routes.login_page'))

    conn.close()
    return render_template('reset_password.html', token=token)

@routes_bp.route("/register")
def register_page():
    """Renders the registration page"""
    return render_template("register.html")

@routes_bp.route("/dashboard")
def dashboard():
    """Renders the user dashboard"""
    if "user_id" not in session:
        return redirect(url_for("routes.login_page"))
    return render_template("dashboard.html")

@routes_bp.route("/upload_skill", methods=["GET"])
def upload_skill_page():
    """Render the skill upload page, showing either skill creation or video upload."""
    if "user_id" not in session:
        return redirect(url_for("routes.login_page"))  # Redirect to login if not authenticated

    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all skills for the logged-in user
    cursor.execute("SELECT id, title FROM skills WHERE user_id = ?", (user_id,))
    skills = cursor.fetchall()  # Get all skills

    conn.close()

    return render_template("upload_skill.html", skills=skills)


@routes_bp.route("/skills")
def skills_page():
    """Renders the page where users can browse available skills."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(""" 
        SELECT 
            s.id, s.title, s.description, s.amount,
            u.username,
            (
                SELECT v.video_path 
                FROM videos v 
                WHERE v.skill_id = s.id 
                LIMIT 1
            ) AS video_path
        FROM skills s
        JOIN users u ON s.user_id = u.id
        ORDER BY s.id DESC
    """)

    skills = []
    for row in cursor.fetchall():
        skills.append({
            "id": row[0],
            "title": row[1],
            "description": row[2],
            "amount": row[3],
            "owner": row[4],
            "video_path": 'videos/'+row[5]  # May be None if no video
        })
    print(skills)
    conn.close()
    return render_template("skills.html", skills=skills)

@routes_bp.route("/skill/<int:skill_id>")
def skill_detail(skill_id):
    """Display details of a specific skill along with its video parts."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch skill details
    cursor.execute("""
        SELECT skills.id, skills.title, skills.description, users.username
        FROM skills
        JOIN users ON skills.user_id = users.id
        WHERE skills.id = ?
    """, (skill_id,))
    skill = cursor.fetchone()

    if not skill:
        conn.close()
        return "Skill not found", 404

    # Fetch associated videos for the skill
    cursor.execute("SELECT id, title, amount, video_path FROM videos WHERE skill_id = ?", (skill_id,))
    videos = cursor.fetchall()

    # Check which videos the logged-in user has purchased
    purchased_videos = set()
    if "user_id" in session:
        user_id = session["user_id"]

        # 1. Direct purchases
        cursor.execute("""
            SELECT video_id FROM transactions 
            WHERE user_id = ? AND status = 'approved'
        """, (user_id,))
        purchased_videos.update(row[0] for row in cursor.fetchall())

        # 2. Swaps — access both sides if user is requester or creator of requested skill
        # a. First, get all skill IDs user owns
        cursor.execute("SELECT id FROM skills WHERE user_id = ?", (user_id,))
        user_owned_skill_ids = {row[0] for row in cursor.fetchall()}

        # b. Now get all completed swaps
        cursor.execute("SELECT requester_id, requested_skill_id, offered_skill_id FROM completed_swaps")
        swap_skill_ids = set()

        for requester_id, requested_skill_id, offered_skill_id in cursor.fetchall():
            if user_id == requester_id:
                # user requested a swap, give them the skill they requested
                swap_skill_ids.add(requested_skill_id)
            elif requested_skill_id in user_owned_skill_ids:
                # someone requested user's skill, give user access to offered skill
                swap_skill_ids.add(offered_skill_id)

        # c. Get videos from those swap_skill_ids
        if swap_skill_ids:
            placeholders = ",".join("?" * len(swap_skill_ids))
            cursor.execute(f"""
                SELECT id FROM videos 
                WHERE skill_id IN ({placeholders})
            """, tuple(swap_skill_ids))
            purchased_videos.update(row[0] for row in cursor.fetchall())
    print(purchased_videos)
    skill_data = {
        "id": skill[0],
        "title": skill[1],
        "description": skill[2],
        "owner": skill[3],
        "videos": [
            {"id": vid[0], "title": vid[1], "amount": vid[2], "video_path": vid[3]}
            for vid in videos
        ]
    }

    return render_template("skill_detail.html", skill=skill_data, purchased_videos=purchased_videos)







@routes_bp.route("/logout")
def logout():
    """Logs the user out and redirects to home"""
    session.pop("user_id", None)
    return redirect(url_for("routes.home"))
def init_routes(app):
    app.register_blueprint(routes_bp)


@routes_bp.route("/checkout/video/<int:video_id>")
def checkout_video(video_id):
    """Checkout process for purchasing a specific video."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("routes.login_page"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch video details
    cursor.execute("SELECT title, amount, skill_id FROM videos WHERE id = ?", (video_id,))
    video = cursor.fetchone()

    if not video:
        return "Video not found", 404

    title, amount, skill_id = video

    # Fetch skill owner (creator)
    cursor.execute("""
        SELECT users.id, users.upi_id FROM skills 
        JOIN users ON skills.user_id = users.id 
        WHERE skills.id = ?
    """, (skill_id,))
    creator = cursor.fetchone()

    if not creator or not creator[1]:
        return "Skill creator's UPI ID not found", 404

    creator_id, creator_upi = creator

    # Generate UPI Payment Link
    upi_link = f"upi://pay?pa={creator_upi}&pn=Skill Marketplace&am={amount}&cu=INR"

    return render_template(
        "payment/checkout.html", 
        video_id=video_id, 
        title=title, 
        amount=amount, 
        upi_link=upi_link
    )


@routes_bp.route("/payment")
def payment_page():
    """Display payment details after a user initiates a transaction."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("routes.login_page"))

    order_id = request.args.get("order_id")

    if not order_id:
        return "Invalid request", 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch transaction details using video_id
    cursor.execute(
        """SELECT t.order_id, t.amount, v.title, v.video_path, t.creator_id
           FROM transactions t
           JOIN videos v ON t.video_id = v.id
           WHERE t.order_id = ? AND t.user_id = ?""",
        (order_id, user_id)
    )
    transaction = cursor.fetchone()
    conn.close()

    if not transaction:
        return "Transaction not found", 404

    order_id, amount, video_title, video_path, creator_id = transaction

    # Correctly generate the QR code path based on the creator_id
    qr_path = f"static/upi_qr/upi_qr_{creator_id}.png"

    return render_template(
        "payment/payment.html",
        order_id=order_id,
        amount=amount,
        video_title=video_title,
        video_path=video_path,
        qr_path=qr_path  # Ensure the template receives the correct QR path
    )


@routes_bp.route("/dashboard/payments", methods=["GET"], endpoint="dashboard_payments")
def payment_verification_dashboard():
    """Display pending payment proofs for verification."""
    user_id = session.get("user_id")
    if not user_id:
        return "Unauthorized", 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    print(user_id)
    
    # Fetch pending payments for this creator (linked to videos, not skills)
    cursor.execute(
        """
        SELECT t.order_id, t.user_id, t.video_id, t.amount, t.payment_proof, v.title
        FROM transactions t
        JOIN videos v ON t.video_id = v.id
        WHERE t.creator_id = ? AND t.status = 'pending_review'
        """,
        (user_id,)
    )
    pending_payments = cursor.fetchall()
    print(pending_payments)
    conn.close()

    # Convert payment_proof from binary to base64 for proper rendering
    formatted_payments = []
    for payment in pending_payments:
        order_id, user_id, video_id, amount, proof, video_title = payment

        

        formatted_payments.append({
            "order_id": order_id,
            "user_id": user_id,
            "video_id": video_id,
            "amount": amount,
            "payment_proof": proof,
            "video_title": video_title
        })

    return render_template("payment/payment_verification.html", payments=formatted_payments)


@routes_bp.route("/my-courses", endpoint="my-courses")
def my_courses():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("routes.login_page"))

    conn = get_db_connection()
    cursor = conn.cursor()

    purchased_videos = set()

    # 1️⃣ Direct purchases
    cursor.execute("""
        SELECT video_id FROM transactions 
        WHERE user_id = ? AND status = 'approved'
    """, (user_id,))
    purchased_videos.update(row[0] for row in cursor.fetchall())

    # 2️⃣ Swaps — access both sides if user is requester or owns requested skill
    cursor.execute("SELECT id FROM skills WHERE user_id = ?", (user_id,))
    user_owned_skill_ids = {row[0] for row in cursor.fetchall()}

    cursor.execute("SELECT requester_id, requested_skill_id, offered_skill_id FROM completed_swaps")
    swap_skill_ids = set()

    for requester_id, requested_skill_id, offered_skill_id in cursor.fetchall():
        if user_id == requester_id:
            swap_skill_ids.add(requested_skill_id)
        elif requested_skill_id in user_owned_skill_ids:
            swap_skill_ids.add(offered_skill_id)

    if swap_skill_ids:
        placeholders = ",".join("?" * len(swap_skill_ids))
        cursor.execute(f"""
            SELECT id FROM videos 
            WHERE skill_id IN ({placeholders})
        """, tuple(swap_skill_ids))
        purchased_videos.update(row[0] for row in cursor.fetchall())

    # 3️⃣ Finally fetch only videos user has access to
    if not purchased_videos:
        return render_template("my_courses.html", videos=[])

    placeholders = ",".join("?" * len(purchased_videos))
    cursor.execute(f"""
        SELECT v.id, v.title, v.video_path, v.skill_id, s.title AS skill_title, u.username
        FROM videos v
        JOIN skills s ON v.skill_id = s.id
        JOIN users u ON s.user_id = u.id
        WHERE v.id IN ({placeholders})
    """, tuple(purchased_videos))

    videos = [
        {
            "id": row[0],
            "title": row[1],
            "video_path": row[2],
            "skill_id": row[3],
            "skill_title": row[4],
            "owner": row[5],
            "access_type": "Purchased/Swapped"
        }
        for row in cursor.fetchall()
    ]

    conn.close()
    return render_template("my_courses.html", videos=videos)





@routes_bp.route("/course/<int:course_id>")
def course_detail(course_id):
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("routes.login_page"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the user has an approved transaction for this course
    cursor.execute("""
        SELECT t.status, s.title, s.description, s.amount, u.username 
        FROM transactions t
        JOIN skills s ON t.skill_id = s.id
        JOIN users u ON s.user_id = u.id
        WHERE t.user_id = ? AND s.id = ? AND t.status = 'approved'
    """, (user_id, course_id))
    
    skill = cursor.fetchone()
    
    if not skill:
        conn.close()
        return "Access Denied", 403  # Prevent unauthorized access

    # Fetch all videos for the course
    cursor.execute("SELECT filename FROM videos WHERE skill_id = ?", (course_id,))
    videos = cursor.fetchall()

    conn.close()

    skill_data = {
        "title": skill[1],
        "description": skill[2],
        "amount": skill[3],
        "owner": skill[4],
        "videos": [{"filename": video[0]} for video in videos]
    }

    return render_template("course_detail.html", skill=skill_data)

@routes_bp.route("/skills_swap", endpoint="skills_swap")
def skill_swap_page():
    if "user_id" not in session:
        return redirect(url_for("routes.login_page"))

    conn = get_db_connection()
    cursor = conn.cursor()
    user_id = session["user_id"]

    try:
        # Skills owned by the user
        cursor.execute("SELECT id, title FROM skills WHERE user_id = ?", (user_id,))
        user_skills = cursor.fetchall()

        # Skills not owned by the user (available to request)
        cursor.execute("SELECT id, title FROM skills WHERE user_id != ?", (user_id,))
        other_skills = cursor.fetchall()

        # Fetch swaps where this user is either requester or owner of requested skill
        cursor.execute("""
            SELECT s.id, 
                s.status,
                req.title AS requested_skill,
                req.user_id AS owner_id,
                off.title AS offered_skill,
                u.username AS requester_name
            FROM skill_swaps s
            JOIN skills req ON s.requested_skill_id = req.id
            JOIN skills off ON s.offered_skill_id = off.id
            JOIN users u ON s.requester_id = u.id
            WHERE req.user_id = ? OR s.requester_id = ?
            ORDER BY s.id DESC
        """, (user_id, user_id))
        # pending_swaps = cursor.fetchall()
        pending_swaps = [dict(row) for row in cursor.fetchall()]

    except sqlite3.Error as e:
        flash("Error loading skills or swaps: " + str(e), "danger")
        user_skills = []
        other_skills = []
        pending_swaps = []
        
    finally:
        conn.close()
    
    # Fetch rows as a list of dictionaries
    # pending_swaps = [dict(row) for row in cursor.fetchall()]

    # Print first row to debug
    if pending_swaps:
        print(pending_swaps[0])  # This will show the first row's data in the console/log
    return render_template(
        "swap_skill.html",
        user_skills=user_skills,
        other_skills=other_skills,
        pending_swaps=pending_swaps
    )

@routes_bp.route("/handle_swap_action", methods=["POST"])
def handle_swap_action():
    if "user_id" not in session:
        return redirect(url_for("routes.login_page"))

    swap_id = request.form.get("swap_id")
    action = request.form.get("action")  # 'accept' or 'reject'

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if action == "accept":
            cursor.execute("UPDATE skill_swaps SET status = 'accepted' WHERE id = ?", (swap_id,))
        elif action == "reject":
            cursor.execute("UPDATE skill_swaps SET status = 'denied' WHERE id = ?", (swap_id,))
        conn.commit()
        flash(f"Swap request has been {action}ed.", "success")
    except sqlite3.Error as e:
        flash("Error updating swap request: " + str(e), "danger")
    finally:
        conn.close()

    return redirect(url_for("routes.skills_swap"))
