from flask import Flask
from flask_session import Session
from flask_login import LoginManager, UserMixin
from config import Config
from routes import get_db_connection, init_routes
import os
from flask_mail import Mail
# Create a User class
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key= "a3f5c9b1e86f4b74f4d0c7e7f5b05f3e6b243892bc3a5e2cbd12d5fa5d09c2d9"

    # Initialize session
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config["UPLOAD_FOLDER"] = "uploads"
     # Configure email settings
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'your_gmail'
    app.config['MAIL_PASSWORD'] = 'your_password'
    app.config['MAIL_DEFAULT_SENDER'] = 'default_mail'
    mail = Mail()
    mail.init_app(app)  # <-- THIS is the key line
    Session(app)
    
    # Initialize login manager
    login_manager = LoginManager()
    login_manager.init_app(app)

    # Redirect to login page if not logged in
    login_manager.login_view = "login"

    # Load user from database
    @login_manager.user_loader
    def load_user(user_id):
        cursor = get_db_connection().cursor()
        cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        print(user)
        
        if user:
            return User(user[0], user[1])  # Return User object
        return None
    
    # Import and register routes
    init_routes(app)

    return app

# Create Flask app instance
app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
