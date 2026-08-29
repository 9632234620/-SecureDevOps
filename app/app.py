from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import logging
import os
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "securedevops-secret-key-change-this"
)


# ============================================================
# LOGGING CONFIGURATION
# ============================================================

os.makedirs("/app/logs", exist_ok=True)

logging.basicConfig(
    filename="/app/logs/app.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_database_connection():

    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "database"),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD", "rootpassword"),
        database=os.environ.get("DB_NAME", "securedevops")
    )


# ============================================================
# AUDIT LOG FUNCTION
# ============================================================

def create_audit_log(username, action, status, ip_address):

    connection = None
    cursor = None

    try:

        connection = get_database_connection()

        cursor = connection.cursor()

        query = """
        INSERT INTO audit_logs
        (username, action, status, ip_address)
        VALUES (%s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (
                username,
                action,
                status,
                ip_address
            )
        )

        connection.commit()

    except Exception as error:

        logger.error(
            "AUDIT LOG ERROR | %s",
            error
        )

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return """
    <!DOCTYPE html>

    <html>

    <head>

        <title>SecureDevOps</title>

        <style>

            body {
                font-family: Arial;
                text-align: center;
                margin-top: 150px;
                background: #e8f4ff;
            }

            h1 {
                color: #1f4e79;
            }

            a {
                display: inline-block;
                padding: 12px 25px;
                margin: 10px;
                background: #1f4e79;
                color: white;
                text-decoration: none;
                border-radius: 5px;
            }

        </style>

    </head>

    <body>

        <h1>🔐 SecureDevOps</h1>

        <h2>
            Zero-Trust Containerized Application
        </h2>

        <p>
            Welcome to the SecureDevOps Platform
        </p>

        <a href="/register">
            Register
        </a>

        <a href="/login">
            Login
        </a>

    </body>

    </html>
    """


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        ip_address = request.remote_addr

        if not username or not email or not password:

            create_audit_log(
                username,
                "REGISTRATION",
                "FAILED",
                ip_address
            )

            return """
            <h2>❌ Registration Failed</h2>

            <p>
                All fields are required.
            </p>

            <a href="/register">
                Try Again
            </a>
            """

        # Hash password
        hashed_password = generate_password_hash(
            password
        )

        connection = None
        cursor = None

        try:

            connection = get_database_connection()

            cursor = connection.cursor()

            query = """
            INSERT INTO users
            (username, email, password, role)
            VALUES (%s, %s, %s, %s)
            """

            cursor.execute(
                query,
                (
                    username,
                    email,
                    hashed_password,
                    "viewer"
                )
            )

            connection.commit()

            logger.info(
                "USER REGISTERED | Username: %s | Status: SUCCESS",
                username
            )

            create_audit_log(
                username,
                "REGISTRATION",
                "SUCCESS",
                ip_address
            )

            return redirect(
                url_for("login")
            )

        except mysql.connector.Error as error:

            logger.warning(
                "USER REGISTRATION | Username: %s | "
                "Status: FAILED | Error: %s",
                username,
                error
            )

            create_audit_log(
                username,
                "REGISTRATION",
                "FAILED",
                ip_address
            )

            return f"""
            <h2>❌ Registration Failed</h2>

            <p>{error}</p>

            <a href="/register">
                Try Again
            </a>
            """

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

    return render_template(
        "register.html"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        ip_address = request.remote_addr

        connection = None
        cursor = None

        try:

            connection = get_database_connection()

            cursor = connection.cursor(
                dictionary=True
            )

            query = """
            SELECT id, username, email, password, role
            FROM users
            WHERE username = %s
            """

            cursor.execute(
                query,
                (username,)
            )

            user = cursor.fetchone()

            if user and check_password_hash(
                user["password"],
                password
            ):

                session["username"] = user["username"]

                session["role"] = user["role"]

                logger.info(
                    "LOGIN | Username: %s | Status: SUCCESS",
                    username
                )

                create_audit_log(
                    username,
                    "LOGIN",
                    "SUCCESS",
                    ip_address
                )

                if user["role"] == "admin":

                    return redirect(
                        url_for("admin")
                    )

                return redirect(
                    url_for("dashboard")
                )

            else:

                logger.warning(
                    "LOGIN | Username: %s | Status: FAILED",
                    username
                )

                create_audit_log(
                    username,
                    "LOGIN",
                    "FAILED",
                    ip_address
                )

                return """
                <h2>❌ Invalid username or password</h2>

                <a href="/login">
                    Try Again
                </a>
                """

        except mysql.connector.Error as error:

            logger.error(
                "LOGIN DATABASE ERROR | "
                "Username: %s | Error: %s",
                username,
                error
            )

            create_audit_log(
                username,
                "LOGIN",
                "DATABASE_ERROR",
                ip_address
            )

            return """
            <h2>❌ Database Error</h2>

            <a href="/login">
                Try Again
            </a>
            """

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

    return render_template(
        "login.html"
    )


# ============================================================
# USER DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "username" not in session:

        create_audit_log(
            "Unknown",
            "DASHBOARD_ACCESS",
            "DENIED",
            request.remote_addr
        )

        return redirect(
            url_for("login")
        )

    username = session["username"]

    logger.info(
        "DASHBOARD ACCESS | Username: %s | Status: SUCCESS",
        username
    )

    create_audit_log(
        username,
        "DASHBOARD_ACCESS",
        "SUCCESS",
        request.remote_addr
    )

    return render_template(
        "dashboard.html",
        username=username,
        role=session["role"]
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")
def admin():

    if "username" not in session:

        create_audit_log(
            "Unknown",
            "ADMIN_ACCESS",
            "DENIED",
            request.remote_addr
        )

        return redirect(
            url_for("login")
        )

    username = session["username"]

    # RBAC
    if session.get("role") != "admin":

        logger.warning(
            "ADMIN ACCESS DENIED | Username: %s | Status: DENIED",
            username
        )

        create_audit_log(
            username,
            "ADMIN_ACCESS",
            "DENIED",
            request.remote_addr
        )

        return """
        <!DOCTYPE html>

        <html>

        <head>

            <title>Access Denied</title>

        </head>

        <body style="text-align:center; margin-top:150px;">

            <h1>🚫 Access Denied</h1>

            <h2>
                Admin privileges required
            </h2>

            <p>
                You do not have permission to access this page.
            </p>

            <a href="/dashboard">
                Back to Dashboard
            </a>

        </body>

        </html>
        """

    connection = None
    cursor = None

    try:

        connection = get_database_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            """
            SELECT id, username, email, role
            FROM users
            ORDER BY id
            """
        )

        users = cursor.fetchall()

        cursor.close()
        connection.close()

        connection = None
        cursor = None

        # Read application logs
        logs = []

        try:

            with open(
                "/app/logs/app.log",
                "r"
            ) as file:

                logs = file.readlines()[-30:]

        except Exception as error:

            logs = [
                "Unable to read logs: " + str(error)
            ]

        create_audit_log(
            username,
            "ADMIN_ACCESS",
            "SUCCESS",
            request.remote_addr
        )

        return render_template(
            "admin.html",
            username=username,
            users=users,
            logs=logs
        )

    except mysql.connector.Error as error:

        logger.error(
            "ADMIN DATABASE ERROR | Error: %s",
            error
        )

        create_audit_log(
            username,
            "ADMIN_ACCESS",
            "DATABASE_ERROR",
            request.remote_addr
        )

        return """
        <h2>❌ Database Error</h2>

        <a href="/dashboard">
            Back to Dashboard
        </a>
        """

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()
            # ============================================================
# DEPLOYMENT MANAGEMENT
# ============================================================

@app.route("/deployments", methods=["GET", "POST"])
def deployments():

    # User must be logged in
    if "username" not in session:

        create_audit_log(
            "Unknown",
            "DEPLOYMENT_ACCESS",
            "DENIED",
            request.remote_addr
        )

        return redirect(
            url_for("login")
        )

    username = session["username"]

    connection = None
    cursor = None

    try:

        connection = get_database_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        # ----------------------------------------------------
        # CREATE DEPLOYMENT
        # ----------------------------------------------------

        if request.method == "POST":

            version = request.form.get(
                "version",
                ""
            ).strip()

            environment = request.form.get(
                "environment",
                "Development"
            )

            status = request.form.get(
                "status",
                "Running"
            )

            if not version:

                return """
                <h2>❌ Version is required</h2>

                <a href="/deployments">
                    Go Back
                </a>
                """

            query = """
            INSERT INTO deployments
            (version, environment, status)
            VALUES (%s, %s, %s)
            """

            cursor.execute(
                query,
                (
                    version,
                    environment,
                    status
                )
            )

            connection.commit()

            logger.info(
                "DEPLOYMENT | User: %s | Version: %s | "
                "Environment: %s | Status: %s",
                username,
                version,
                environment,
                status
            )

            create_audit_log(
                username,
                "DEPLOYMENT_CREATED",
                status,
                request.remote_addr
            )

        # ----------------------------------------------------
        # GET DEPLOYMENT HISTORY
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                id,
                version,
                environment,
                status,
                created_at
            FROM deployments
            ORDER BY id DESC
            """
        )

        deployment_list = cursor.fetchall()

        return render_template(
            "deployment.html",
            deployments=deployment_list
        )

    except mysql.connector.Error as error:

        logger.error(
            "DEPLOYMENT ERROR | User: %s | Error: %s",
            username,
            error
        )

        return f"""
        <h2>❌ Deployment Error</h2>

        <p>{error}</p>

        <a href="/dashboard">
            Back to Dashboard
        </a>
        """

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()
            # ============================================================
# MONITORING DASHBOARD
# ============================================================

@app.route("/monitoring")
def monitoring():

    # User must be logged in
    if "username" not in session:

        create_audit_log(
            "Unknown",
            "MONITORING_ACCESS",
            "DENIED",
            request.remote_addr
        )

        return redirect(
            url_for("login")
        )

    username = session["username"]

    connection = None
    cursor = None

    try:

        connection = get_database_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        # ----------------------------------------------------
        # CHECK DATABASE
        # ----------------------------------------------------

        database_status = "Connected"

        # ----------------------------------------------------
        # COUNT USERS
        # ----------------------------------------------------

        cursor.execute(
            "SELECT COUNT(*) AS total FROM users"
        )

        user_count = cursor.fetchone()["total"]

        # ----------------------------------------------------
        # COUNT DEPLOYMENTS
        # ----------------------------------------------------

        cursor.execute(
            "SELECT COUNT(*) AS total FROM deployments"
        )

        deployment_count = cursor.fetchone()["total"]

        # ----------------------------------------------------
        # COUNT AUDIT LOGS
        # ----------------------------------------------------

        cursor.execute(
            "SELECT COUNT(*) AS total FROM audit_logs"
        )

        audit_count = cursor.fetchone()["total"]

        # ----------------------------------------------------
        # LATEST DEPLOYMENTS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                id,
                version,
                environment,
                status,
                created_at
            FROM deployments
            ORDER BY id DESC
            LIMIT 10
            """
        )

        deployment_list = cursor.fetchall()

        # ----------------------------------------------------
        # RECENT AUDIT LOGS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                username,
                action,
                status,
                ip_address,
                created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 10
            """
        )

        audit_log_list = cursor.fetchall()

        cursor.close()
        connection.close()

        connection = None
        cursor = None

        # ----------------------------------------------------
        # APPLICATION STATUS
        # ----------------------------------------------------

        application_status = "Healthy"

        # ----------------------------------------------------
        # CONTAINER STATUS
        # ----------------------------------------------------

        container_status = "Running"

        # ----------------------------------------------------
        # AUDIT EVENT
        # ----------------------------------------------------

        create_audit_log(
            username,
            "MONITORING_ACCESS",
            "SUCCESS",
            request.remote_addr
        )

        logger.info(
            "MONITORING DASHBOARD | Username: %s | Status: SUCCESS",
            username
        )

        # ----------------------------------------------------
        # DISPLAY MONITORING PAGE
        # ----------------------------------------------------

        return render_template(
            "monitoring.html",
            application_status=application_status,
            database_status=database_status,
            container_status=container_status,
            user_count=user_count,
            deployment_count=deployment_count,
            audit_count=audit_count,
            deployments=deployment_list,
            audit_logs=audit_log_list
        )

    except mysql.connector.Error as error:

        logger.error(
            "MONITORING ERROR | Username: %s | Error: %s",
            username,
            error
        )

        return f"""
        <h2>❌ Monitoring Error</h2>

        <p>{error}</p>

        <a href="/dashboard">
            Back to Dashboard
        </a>
        """

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    username = session.get(
        "username",
        "Unknown"
    )

    create_audit_log(
        username,
        "LOGOUT",
        "SUCCESS",
        request.remote_addr
    )

    logger.info(
        "LOGOUT | Username: %s | Status: SUCCESS",
        username
    )

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    connection = None

    try:

        connection = get_database_connection()

        connection.close()

        return {
            "application": "healthy",
            "database": "connected",
            "status": "running"
        }

    except Exception as error:

        logger.error(
            "HEALTH CHECK ERROR | Error: %s",
            error
        )

        return {
            "application": "healthy",
            "database": "disconnected",
            "status": "error"
        }, 500


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    logger.info(
        "SecureDevOps application starting..."
    )

    app.run(
        host="0.0.0.0",
        port=5000
    )