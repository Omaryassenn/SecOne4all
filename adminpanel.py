from flask_admin import Admin, BaseView, expose
from flask_admin.menu import MenuLink
from flask_admin.contrib.sqla import ModelView
from app import app, db, Bcrypt
from models import User, Contact, Post, Role, News, PayloadXSS, CapturedData, PayloadXXE, Comment, XSSModel, Notification, RequestData, Note
from app import *
from forms import RestPasswordForm, UpdatePassword, NewsForm
from flask_security import roles_required

admin = Admin(app, name='Admin Panel', template_mode='bootstrap3')
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)
bcrypt = Bcrypt(app)  # Initialize Flask-Bcrypt


class UserView(ModelView):
    # Other view configurations go here

    def on_model_change(self, form, model, is_created):
        # Check if the password field is present in the form and not empty
        if 'password' in form and form.password.data:
            # Hash the password before saving it to the database
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            model.password = hashed_password
        else:
            # Password not provided or empty, retain the current value in the database
            pass  # Ensure it's not modified


def send_reset_password_email(user):
    try:
        token = secrets.token_hex(16)
        user.reset_password_token = token
        user_datastore.put(user)
        db.session.commit()

        reset_link = url_for('reset_password', token=token, _external=True)

        subject = 'Password Reset'
        sender = 'secon4all@gmail.com'
        recipients = [user.email]

        # Render the HTML template
        html_body = render_template('reset_password_email.html', user=user, reset_link=reset_link)

        msg = Message(subject, sender=sender, recipients=recipients)
        msg.body = f"Click this link to reset your password: {reset_link}"
        msg.html = html_body

        mail.send(msg)
    except Exception as e:
        flash(f'Error sending email: {e}', 'danger')
        app.logger.error(f'Error sending email: {e}')


@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    form = RestPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = user_datastore.get_user(email)

        if user:
            send_reset_password_email(user)
            flash('If the email exists, you will receive a reset link shortly.', 'success')
        else:
            flash('If the email exists, you will receive a reset link shortly.', 'danger')

    return render_template('forgot_password.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def reset_password(token):
    user = User.query.filter_by(reset_password_token=token).first()

    if not user:
        flash('Invalid reset password link.', 'danger')
        return redirect(url_for('login'))

    form = UpdatePassword()

    if form.new_password.data != form.confirm_password.data:
        flash('Passwords do not match.', 'danger')

    if form.validate_on_submit():
        new_password = form.new_password.data
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.reset_password_token = None
        user_datastore.put(user)
        db.session.commit()
        flash('Password reset successfully!', 'success')
        return redirect(url_for('login'))  # Redirect to login page after successful password reset

    return render_template('reset_password.html', form=form, token=token)
# Create Admin User
# Create a route to create an admin user with the "admin" role
@app.route('/create/admin', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
#@roles_required('admin')
def create_admin():
    form = Register()
    if form.validate_on_submit():
        # Check if the username or email is already in use
        existing_user = User.query.filter(
            (User.username == form.username.data) | (User.email == form.email.data)
        ).first()
        if existing_user:
            flash('Username or email is already in use.', 'error')
            return render_template('register.html', form=form)
        # Create a new user object and add it to the database
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        if form.image.data:
            picture_file = save_picture(form.image.data)

        admin_role = Role.query.filter_by(name='admin').first()

        if not admin_role:
            admin_role = Role(name='admin', description='Administrator')
            db.session.add(admin_role)
            db.session.commit()

        # Create the admin user
        admin_user = User.query.filter_by(email='admin@example.com').first()
        if not admin_user:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            admin_user = user_datastore.create_user(
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                username=form.username.data,
                email=form.email.data,
                password=hashed_password,
            )
            user_datastore.add_role_to_user(admin_user, admin_role)
            db.session.commit()
            # Send confirmation email
            confirm_url = url_for('confirm_email', token=admin_user.email_confirm_token, _external=True)
            send_confirmation_email(admin_user.email, confirm_url)
            flash('Registration successful. Please check your email to confirm your account.', 'success')
            return redirect(url_for('login'))
    return render_template('create_admin.html', form=form)





# Add the UserView to the admin panel
admin.add_view(UserView(User, db.session))
admin.add_view(UserView(Contact, db.session))
admin.add_view(UserView(Post, db.session))
admin.add_view(UserView(News, db.session))
admin.add_view(UserView(CapturedData, db.session))
admin.add_view(UserView(PayloadXSS, db.session))
admin.add_view(UserView(PayloadXXE, db.session))
admin.add_view(UserView(XSSModel, db.session))
admin.add_view(UserView(Notification, db.session))
admin.add_view(UserView(RequestData, db.session))
admin.add_view(UserView(Note, db.session))
admin.add_link(MenuLink(name='Logout', endpoint='logout'))
# Routes