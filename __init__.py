import os
import psycopg2
from flask import Flask
from flask_login import LoginManager
from dotenv import load_dotenv
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer

def create_app():
    app = Flask(__name__)
    

    # Load environment variables from the .env file
    load_dotenv()

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

    # Establish database connection
    connection = psycopg2.connect(
        host=os.getenv('DB_HOST'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD')  # Fetching the password from the .env file
    )
    cursor = connection.cursor()
    app.config['db_connection'] = connection
    app.config['db_cursor'] = cursor

    login_manager = LoginManager()
    login_manager.init_app(app)

    from .routes import main
    from .models import User

    app.register_blueprint(main)

    @login_manager.user_loader
    def load_user(user_id):
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(id=user_data[0], username=user_data[1], email=user_data[4], password=user_data[3], role=user_data[5])
        return None

    login_manager.login_view = 'main.login'

    return app
