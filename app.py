from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, Blueprint, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_manager, login_required  # Corrected import for current_user
from flask_bcrypt import Bcrypt
import adminpanel
from flask_mail import Mail, Message
from markdown2 import markdown
from flask_security import Security, SQLAlchemyUserDatastore, roles_required
from flask_security.datastore import SQLAlchemyUserDatastore
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import Markup
from functools import wraps  # Import for the wraps decorator
import markdown2
import mistune
from markupsafe import Markup
import re
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor
from bleach import clean

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # Use your database URI here
app.secret_key = '5791628bb0b13ce0c676dfde280ba245'  # Set a secret key for sessions
app.config['SECURITY_PASSWORD_SALT'] = 'your_random_salt_here'
app.config['SECURITY_REGISTERABLE'] = True  # Allow user registration
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False  # Disable email confirmation
app.config['SECURITY_RECOVERABLE'] = True
app.config['SECURITY_CHANGEABLE'] = True
app.config['UPLOAD_FOLDER'] = 'static/uploads'
# Configure Flask-Mail with GoDaddy's settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # GoDaddy's SMTP server
app.config['MAIL_PORT'] = 587  # Use port 465 for SSL
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'secon4all@gmail.com'  # Your GoDaddy email address
app.config['MAIL_PASSWORD'] = 'suuq qvbr kqlh ccxs'  # Your GoDaddy email password


# app.config['MAIL_DEFAULT_SENDER'] = 'secon4all@gmail.com'  # Default sender address



def markdownify_filter(text):
    # Sanitize the HTML using bleach
    sanitized_text = clean(text, tags=bleach.sanitizer.ALLOWED_TAGS,
                                  attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES)

    # Convert markdown to HTML
    html_content = markdown(sanitized_text)

    # Remove <p> tags specifically for markdown content
    html_content = html_content.replace('<p>', '').replace('</p>', '')

    # Mark the HTML content as safe
    return Markup(html_content)

app.jinja_env.filters['markdownify_filter'] = markdownify_filter




# Configure Flask-Limiter
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["50 per minute"])
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
mail = Mail(app)
csrf = CSRFProtect(app)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not 'admin' in [role.name for role in current_user.roles]:
            flash('You need to be an admin to access this page.', 'error')
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


# Apply the admin_required decorator to all routes under /admin
def apply_admin_auth_to_routes(app):
    for rule in app.url_map.iter_rules():
        if rule.endpoint.startswith('/admin') or rule.rule.startswith('/admin'):
            app.view_functions[rule.endpoint] = admin_required(app.view_functions[rule.endpoint])


app.jinja_env.filters['markdown'] = markdownify_filter


def init_db():
    # Create the database tables
    with app.app_context():
        db.create_all()


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"  # Set the login view
login_manager.init_app(app)

# Import and configure your routes, models, and other components here
from routes import *

if __name__ == '__main__':
    init_db()
    apply_admin_auth_to_routes(app)
    app.run(debug=True)
