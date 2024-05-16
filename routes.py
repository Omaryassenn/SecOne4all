from flask import render_template, redirect, url_for, flash, request, abort, jsonify
from flask_login import current_user, login_user, logout_user, login_required, login_manager, LoginManager, UserMixin
from forms import Login, Register, ContactForm, PostForm, ChangePasswordForm, UpdateProfileForm, XSSPayloadForm, \
    AddReactionForm, CommentForm, NewsForm, NoteForm, CommentForm
from models import db, User, Contact, Post, Role, News, CapturedData, PayloadXSS, XXE, PayloadXXE, Reaction, Comment, \
    XSSModel, Notification, RequestData, Note
from sqlalchemy.exc import SQLAlchemyError
from app import *
from functools import wraps
import markdown2
import os
import secrets
from datetime import datetime
from PIL import Image
from flask_security import roles_required
from markupsafe import escape
import bleach
from itsdangerous import Serializer
from sqlalchemy.exc import IntegrityError
from bleach import clean
from werkzeug.utils import secure_filename
from sqlalchemy import and_
import hashlib
import socket


@login_manager.user_loader
def load_user(user_id):
    # Load a user object based on the user_id (usually from the session)
    return User.query.get(int(user_id))


@app.route('/', methods=['GET'])
@app.route('/index')  # Add a slash
def home():
    return render_template('index.html')


def add_notification(message):
    users = User.query.all()  # Fetch all users from the database
    for user in users:
        # Create a new notification for each user
        notification = Notification(message=message, user_id=user.id, sent=True, read=False)
        db.session.add(notification)
    db.session.commit()


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        # Redirect authenticated users to another page (e.g., dashboard)
        return redirect(url_for('dashboard'))

    form = Login()  # Use LoginForm from forms.py
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.email_confirmed:
                login_user(user)
                flash('Login successful', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Please confirm your email before logging in.', 'warning')
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)


# Rest of your routes (dashboard, logout) remain the same
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


# Registration route with email confirmation
@app.route('/register', methods=['GET', 'POST'])  # @login_required dont forget!!!

@limiter.limit("10 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = Register()
    if form.validate_on_submit():
        existing_user = User.query.filter(
            (User.username == form.username.data) | (User.email == form.email.data)
        ).first()

        if existing_user:
            flash('Username or email is already in use.', 'error')
            return render_template('register.html', form=form)

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        if form.image.data:
            picture_file = save_picture(form.image.data)

        new_user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            image=picture_file,
            confirmed_at=datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()

        # Send confirmation email
        confirm_url = url_for('confirm_email', token=new_user.email_confirm_token, _external=True)
        send_confirmation_email(new_user.email, confirm_url)

        flash('Registration successful. Please check your email to confirm your account.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


def send_confirmation_email(email, confirm_url):
    subject = 'Confirm Your Email'
    sender = 'secon4all@gmail.com'
    recipients = [email]

    # Render the HTML template
    html_body = render_template('confirmation_email.html', confirm_url=confirm_url)

    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = f"Click this link to confirm your email: {confirm_url}"
    msg.html = html_body

    mail.send(msg)


@app.route('/confirm_email/<token>', methods=['GET', 'POST'])
def confirm_email(token):
    user = User.query.filter_by(email_confirm_token=token).first()

    if user:
        if not user.email_confirmed:
            # Confirm the email
            user.email_confirmed = True
            db.session.commit()
            flash('Email confirmed successfully!', 'success')
        else:
            flash('Email already confirmed.', 'info')
    else:
        flash('Invalid confirmation link.', 'danger')

    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/contact', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def contact():
    form = ContactForm()

    if form.validate_on_submit():
        try:
            # Create a new Contact instance and populate its fields
            contact = Contact(
                name=form.name.data,
                email=form.email.data,
                message=form.message.data
            )

            # Add the new contact to the database
            db.session.add(contact)
            db.session.commit()

            flash('Message sent successfully!', 'success')
            return redirect(url_for('contact'))
        except SQLAlchemyError as e:
            db.session.rollback()  # Roll back the database session in case of an error
            flash('An error occurred while sending the message. Please try again later.', 'error')

    return render_template('contact.html', form=form)


@app.route('/news')
def news():
    page = request.args.get('page', 1, type=int)
    per_page = 3

    news_pagination = News.query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template('news.html', news=news_pagination)


@app.route('/news/<int:id>')
def view_news(id):
    news_article = News.query.get(id)

    if not news_article:
        flash('News article not found', 'danger')
        return redirect(url_for('news', page=request.args.get('page', 1, type=int)))
    news_article.content = escape(news_article.content)
    news_article.summary = escape(news_article.summary)
    news_article.title = escape(news_article.title)
    return render_template('view_news.html', news=news_article)


@app.route('/add_news', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@roles_required('admin')
def add_news():
    form = NewsForm()
    if form.validate_on_submit():
        title = form.title.data
        summary = markdownify_filter(form.summary.data)
        content = form.content.data
        image = form.image.data
        html_content = markdownify_filter(content)

        # Create a new News object and add it to the database
        news_article = News(title=title, summary=summary, content=html_content, image=save_picture(image))
        db.session.add(news_article)
        db.session.commit()

        flash('News article added successfully.', 'success')
        add_notification("A new news titled '{}' has been added.".format(news_article.title))
        return redirect(url_for('news'))    
    return render_template('add_news.html', form=form)


def generate_consistent_hook(user_identifier):
    # Use a stable, user-specific identifier
    base_string = f"{user_identifier}"
    # Hash the identifier to produce a consistent, unique string
    hash_object = hashlib.sha256(base_string.encode())
    consistent_hook = hash_object.hexdigest()
    return consistent_hook


@app.route('/hook/view')
@login_required
def view_webhook():
    hock_value = generate_consistent_hook(current_user.id)
    hostname = socket.gethostname()
    payload = f"https://mubarak.fyi/hock/{hock_value}"  # Fix the payload URL
    all_entries = RequestData.query.filter_by(user_id=current_user.id).all()
    return render_template('hock.html', entries=all_entries, payload=payload)


@app.route('/hock/<hockid>', methods=['GET', 'POST'])
@login_required
def hock(hockid):
    # Extract User-Agent, Referer, and HOST
    print(f"Hook ID: {hockid}")
    user_agent = request.headers.get('User-Agent')
    referer = request.headers.get('Referer', 'None')  # Default to 'None' if not present
    host = request.headers.get('Host')

    # Store request data including User-Agent, Referer, and Host
    if request.method == 'POST':
        data = ', '.join([f"{key}={value}" for key, value in request.args.to_dict().items()])
    else:  # GET request
        data = ', '.join([f"{key}={value}" for key, value in request.args.to_dict().items()])
    new_entry = RequestData(method=request.method, data=data, user_agent=user_agent, referer=referer, host=host,
                            user_id=current_user.id, created_at=datetime.utcnow())
    db.session.add(new_entry)
    db.session.commit()
    return redirect(url_for('view_webhook'))


@app.route('/dashboard/post/add/', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        try:
            # Convert Markdown to HTML
            post_content_html = markdownify_filter(form.description.data)

            # Save the image if it's present
            image_file = form.image.data
            filename = None  # Define filename here to use it outside of the if block
            if image_file:
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.root_path, 'static/uploads', filename)
                if not os.path.exists(os.path.dirname(image_path)):
                    os.makedirs(os.path.dirname(image_path))  # Create the directory if it doesn't exist
                image_file.save(image_path)

            # Create a new Post instance
            post = Post(
                title=form.title.data,
                description=post_content_html,
                user_id=current_user.id,
                image_url=filename  # Now this field exists in the Post model
            )
            db.session.add(post)
            db.session.commit()
            flash('Post added successfully!', 'success')
            add_notification("A new post titled '{}' has been added.".format(post.title))
            return redirect(url_for('display_posts'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding the post: {e}', 'danger')
            app.logger.error(f'Error adding post: {e}')

    return render_template('add_post.html', form=form, title='Add Post')


# Defi
@app.route('/display_posts', methods=['GET', 'POST'])
@login_required
def display_posts():
    posts = Post.query.all()
    forms = {post.id: CommentForm(prefix=str(post.id)) for post in posts}  # Ensure unique form prefixes

    if request.method == 'POST':
        for post_id, form in forms.items():
            # Check which form was submitted
            if form.validate_on_submit() and request.form.get('submit_button') == str(post_id):
                post = Post.query.get(post_id)
                # Correctly escape the comment text to prevent XSS
                comment_text = markdownify_filter(form.text.data)  # Fixed missing parenthesis

                # Create a new comment associated with the current user
                new_comment = Comment(text=comment_text, post=post, user=current_user)
                db.session.add(new_comment)
                db.session.commit()

                # Redirect to the same page to avoid form resubmission issues
                return redirect(url_for('display_posts'))

    return render_template('posts.html', posts=posts, forms=forms)


@app.route('/add_comment/<int:post_id>', methods=['GET', 'POST'])
@login_required
def add_comment_id(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        comment_text = form.text.data

        # Create a new comment associated with the current user
        new_comment = Comment(text=comment_text, post_id=post_id, user=current_user)
        db.session.add(new_comment)
        db.session.commit()
        flash('Your comment has been added successfully!', 'success')
        return redirect(url_for('show_post', post_id=post_id))
    else:
        flash('Failed to add comment. Please try again.', 'danger')
        return redirect(url_for('show_post', post_id=post_id))
        
@app.route('/post/<int:post_id>')
def show_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Assuming 'post_detail.html' is your template for showing a single post's details
    return render_template('post_detail.html', post=post)


@app.route('/post/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)  # Unauthorized access

    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.description = form.description.data
        if form.image.data:
            image_file = save_picture(form.image.data)
            post.image_url = image_file
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('display_posts'))
    if request.method == 'GET':
        form.title.data = post.title
        form.description.data = post.description
        # No need to preload image field
    return render_template('edit_post.html', title='Edit Post', form=form, post=post)


@app.route('/post/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('display_posts'))


@app.route('/search')
def search():
    query = request.args.get('query', '')
    if query:
        # Use ilike for case-insensitive search and % as wildcards
        search_result = Post.query.filter(
            db.or_(
                Post.title.ilike(f'%{query}%'),
                Post.description.ilike(f'%{query}%')
            )
        ).all()
    else:
        search_result = []

    return render_template('search_results.html', posts=search_result, query=query)


@app.route('/search_news')
def search_news():
    query = request.args.get('query', '')
    if query:
        news_items = News.query.filter(
            db.or_(
                News.title.ilike(f'%{query}%'),
                News.content.ilike(f'%{query}%')
            )
        ).all()
    else:
        news_items = []

    return render_template('search_news_results.html', news_items=news_items, query=query)


# notes
@app.route("/note/new", methods=['GET', 'POST'])
@login_required
def new_note():
    form = NoteForm()
    if form.validate_on_submit():
        note = Note(title=form.title.data, content=form.content.data, user_id=current_user.id)
        db.session.add(note)
        db.session.commit()
        flash('Your note has been created!', 'success')
        return redirect(url_for('note', note_id=note.id))
    return render_template('create_note.html', title='New Note', form=form, legend='New Note')


@app.route('/notes')
@login_required
def notes():
    # Assuming 'current_user.id' is the ID of the logged-in user
    user_notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.date_posted.desc()).all()
    return render_template('notes.html', notes=user_notes)


@app.route("/note/<int:note_id>")
@login_required
def note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    return render_template('note.html', title=note.title, note=note)


@app.route("/note/<int:note_id>/update", methods=['GET', 'POST'])
@login_required
def update_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    form = NoteForm()
    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data
        db.session.commit()
        flash('Your note has been updated!', 'success')
        return redirect(url_for('note', note_id=note.id))
    elif request.method == 'GET':
        form.title.data = note.title
        form.content.data = note.content
    return render_template('create_note.html', title='Update Note', form=form, legend='Update Note')


@app.route("/note/<int:note_id>/delete", methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    db.session.delete(note)
    db.session.commit()
    flash('Your note has been deleted!', 'success')
    return redirect(url_for('notes'))


@app.route('/search_notes', methods=['GET'])
def search_notes():
    query = request.args.get('query', '').strip()

    if not query:
        # Optionally, flash a message to let the user know they didn't enter a search query
        flash('Please enter a search query.', 'warning')
        return redirect(url_for('notes.html'))

    notes = Note.query.filter(Note.title.contains(query) | Note.content.contains(query)).all()

    if not notes:
        # Flash a message if no notes were found matching the query
        flash('No notes found matching your query.', 'info')

    return render_template('notes.html', notes=notes, query=query)


# Function to save and resize profile pictures
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/uploads/', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()

    if form.validate_on_submit():
        if form.image.data:
            picture_file = save_picture(form.image.data)
            current_user.image = picture_file

        # Update profile information
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        new_username = form.username.data

        # Check if the new username is unique
        existing_user = User.query.filter(User.username == new_username).first()

        if existing_user and existing_user.id != current_user.id:
            flash('Profile update failed. Username already exists.', 'danger')
        else:
            try:
                # Update the user's profile
                current_user.username = new_username
                db.session.commit()
                flash('Profile updated successfully!', 'success')
            except IntegrityError:
                db.session.rollback()
                flash('Profile update failed. The username might already be taken.', 'danger')

    elif request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.username.data = current_user.username

    else:
        flash('Profile update failed.', 'danger')

    image_file = url_for('static', filename='uploads/' + current_user.image)
    return render_template('profile.html', image_file=image_file, form=form)


# Change password route and view function
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form_password = ChangePasswordForm()

    if request.method == 'POST' and form_password.validate_on_submit():
        # Change password
        new_password = form_password.new_password.data
        current_user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        flash('Password updated successfully', 'success')
        return redirect(url_for('profile'))

    # Prepopulate form field with the current username
    form_password.current_username.data = current_user.username

    return render_template('change_password.html', form_password=form_password)


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(403)
def page_not_found(error):
    return render_template('403.html'), 403


@app.errorhandler(400)
def page_not_found(error):
    return render_template('400.html'), 400


@app.errorhandler(429)
def page_not_found(error):
    return render_template('429.html'), 429


@app.route('/bug-bounty', methods=['GET'])
@login_required
def bugBounty():
    return render_template('bug-bounty.html')


@app.route('/capture', methods=['POST', 'GET'])
def capture():
    data = CapturedData(
        user_agent=request.headers.get('User-Agent', ''),
        referrer=request.headers.get('Referer', ''),
        cookie=request.form.get('cookie', ''),
        screenshot=request.form.get('screenshot', ''),
        vulnerable_url=request.form.get('vulnerable_url', ''),
        vulnerable_html=request.form.get('vulnerable_html', '')
    )
    db.session.add(data)
    db.session.commit()
    return 'Data captured', 200


@app.route('/oc', methods=['GET'])
def store_cookie():
    # Extract data from the request
    cookie = request.args.get('cookie')

    vuln_url = request.args.get('vuln_url')
    # Use the correct header to get the client's IP
    ip = request.headers.get('X-Real-IP') or request.headers.get('X-Forwarded-For') or request.remote_addr

    # Use the request.headers.get('Host') to get the victim's host
    #    host = request.headers.get('Host')
    referer = request.headers.get('Referer')
    user_agent = request.headers.get('User-Agent')

    # Define timestamp
    timestamp = datetime.utcnow()

    # Create a new XSS
    img = request.args.get('img')

    # Create a new XSSModel instance
    html_code = request.args.get('html')

    # Create a new XSSModel instance
    new_log = XSSModel(ip=ip, referer=referer, cookie=cookie, user_agent=user_agent,
                       img=img, html_code=html_code, timestamp=timestamp, vulnerable_url=vuln_url)

    try:
        # Add user agent and vulnerable URL to the new log
        # Add and commit the new log to the database
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        # Handle database error
        return f'Error: {str(e)}'


@app.route('/xss-fire', methods=['GET'])
@roles_required('admin')
@login_required
def view_logs():
    xss_data = XSSModel.query.all()
    return render_template('xss.html', xss_data=xss_data)


@app.route('/payloads-xss', methods=['GET'])
@roles_required('admin')
@login_required
def pxss():
    payloads = PayloadXSS.query.all()
    return render_template('payloads-xss.html', payloads=payloads)


@app.route('/add_payload', methods=['GET', 'POST'])
@roles_required('admin')
@login_required
def add_payload_xss():
    form = XSSPayloadForm()

    if form.validate_on_submit():
        payload = form.payload.data
        notes = form.notes.data

        new_payload = PayloadXSS(payload=payload, notes=notes)

        try:
            db.session.add(new_payload)
            db.session.commit()
            flash('Payload added successfully!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to your dashboard or another route
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

    return render_template('add_payload.html', form=form)


# XXE
# Update the XXE route in routes.py
@app.route('/xxe', methods=['GET'])
def xxe():
    # Extract data from the request
    file = request.args.get('f')

    # Use the correct header to get the client's IP
    ip = request.headers.get('X-Real-IP') or request.headers.get('X-Forwarded-For') or request.remote_addr

    # Use the request.headers.get('Host') to get the victim's host
    referer = request.headers.get('Referer')
    user_agent = request.headers.get('User-Agent')

    # Define timestamp
    timestamp = datetime.utcnow()

    # Create a new XXE instance
    new_xxe = XXE(ip=ip, referer=referer, file=file, user_agent=user_agent, timestamp=timestamp,
                  vulnerable_url=request.url)

    try:
        # Add and commit the new XXE log to the database
        db.session.add(new_xxe)
        db.session.commit()
        return 'Request sent successfully!'
    except Exception as e:
        # Handle database error
        return f'Error: {str(e)}'


@app.route('/payloads-xxe', methods=['GET'])
@roles_required('admin')
@login_required
def pxxe():
    payloads = PayloadXXE.query.all()
    return render_template('payloads-xxe.html', payloads=payloads)


@app.route('/xxe-fire', methods=['GET'])
@roles_required('admin')
@login_required
def view_xxe():
    # Retrieve all cookie logs from the database
    xxes = XXE.query.all()
    return render_template('xxe.html', xxes=xxes)


@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    form = CommentForm()  # Replace with your actual Comment form class
    if form.validate_on_submit():
        comment = Comment(author=current_user, text=form.text.data, post_id=post_id)
        db.session.add(comment)
        db.session.commit()
        flash('Comment added successfully!', 'success')
    else:
        flash('Error adding comment. Please check your input.', 'danger')

    return redirect(url_for('display_posts'))


@app.route('/add_reaction', methods=['POST'])
@login_required
def add_reaction():
    post_id = request.form.get('post_id')
    reaction_type = request.form.get('reaction_type')

    # Check if post_id or reaction_type is None before proceeding
    if not post_id or post_id.strip() == '':
        return jsonify({'error': 'Post ID not provided'}), 400
    if not reaction_type or reaction_type.strip() == '':
        return jsonify({'error': 'Reaction type not provided'}), 400

    try:
        # Convert post_id to integer
        post_id = int(post_id)
    except ValueError:
        # Respond with an error if post_id is not an integer
        return jsonify({'error': 'Invalid post ID'}), 400

    # Now we are sure that reaction_type is not None, we can safely call .upper()
    reaction_type = reaction_type.upper()

    # Check if reaction_type is a valid choice
    if reaction_type not in ['LIKE', 'DISLIKE', 'LOVE']:
        return jsonify({'error': 'Invalid reaction type'}), 400

    # Check if the post exists
    post = Post.query.get(post_id)
    if not post:
        return jsonify({'error': 'Post not found'}), 404

    # Check if the user has already reacted to the post
    existing_reaction = Reaction.query.filter_by(post_id=post_id, user_id=current_user.id).first()
    if existing_reaction:
        # Update the existing reaction type if the user has already reacted
        existing_reaction.reaction_type = reaction_type
    else:
        # Create a new reaction if the user hasn't reacted before
        new_reaction = Reaction(post_id=post_id, user_id=current_user.id, reaction_type=reaction_type)
        db.session.add(new_reaction)

    db.session.commit()

    post.like_count = post.total_reactions()
    db.session.commit()

    # Return a JSON response indicating success
    return jsonify({'success': 'Reaction added successfully', 'like_count': post.like_count})


@app.route('/notifications')
@login_required
def notifications():
    # Assuming 'current_user' is the logged-in user object provided by Flask-Login
    user_id = current_user.id
    notifications = Notification.query.filter_by(user_id=user_id, sent=True, read=False).order_by(
        Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)


@app.route('/notifications/read')
@login_required
def mark_notifications_as_read():
    user_id = current_user.id
    Notification.query.filter_by(user_id=user_id, sent=True).update({'read': True})
    db.session.commit()
    return redirect(url_for('notifications'))
