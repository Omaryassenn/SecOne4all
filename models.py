from app import db
from flask_login import UserMixin
from flask_security import RoleMixin
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from app import app
import secrets
from datetime import datetime, timedelta
from itsdangerous import Serializer
from sqlalchemy import and_

# Association table for the many-to-many relationship between Users and Roles
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
                       )


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    active = db.Column(db.Boolean(), default=True)
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    reset_password_token = db.Column(db.String(100), unique=True)
    image = db.Column(db.String(255), nullable=False, default='default.png')
    reactions = db.relationship('Reaction', back_populates='user', lazy='dynamic')
    comments = db.relationship('Comment', back_populates='user', lazy='dynamic')
    email_confirmed = db.Column(db.Boolean, nullable=False, default=False)
    email_confirm_token = db.Column(db.String(100), unique=True)
    hook = db.Column(db.String(64), index=True, unique=True)


    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        self.email_confirm_token = secrets.token_hex(16)

    def generate_email_confirm_token(self):
        expiration = timedelta(days=1)  # Adjust the expiration time as needed
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration.total_seconds())
        return s.dumps({'user_id': self.id}).decode('utf-8')

    def confirm_email(self, token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            if data.get('user_id') == self.id:
                self.email_confirmed = True
                db.session.commit()
                return True
        except Exception as e:
            app.logger.error(f'Error confirming email: {e}')
        return False

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image}')"


class XSSModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(100))
    referer = db.Column(db.String(500))
    cookie = db.Column(db.Text)
    user_agent = db.Column(db.String(500))
    img = db.Column(db.Text)  # Field for image data
    html_code = db.Column(db.Text)  # Added field for HTML code
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    vulnerable_url = db.Column(db.String(500))

    def __init__(self, ip, referer, cookie, user_agent, img, html_code, timestamp, vulnerable_url):
        self.ip = ip
        self.referer = referer
        self.cookie = cookie
        self.user_agent = user_agent
        self.img = img
        self.html_code = html_code
        self.timestamp = timestamp
        self.vulnerable_url = vulnerable_url

    def __repr__(self):
        return f'<XSSModel {self.id}>'


class CapturedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    captured_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(256))
    referrer = db.Column(db.String(512))
    cookie = db.Column(db.Text)
    screenshot = db.Column(db.Text)  # Base64 encoded image
    vulnerable_url = db.Column(db.String(512))
    vulnerable_html = db.Column(db.Text)

    def __repr__(self):
        return f'<CapturedData {self.id}>'


class XXE(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    ip = db.Column(db.String(15))
    referer = db.Column(db.String(255))
    file = db.Column(db.String(2255))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    vulnerable_url = db.Column(db.String(255))

    def __repr__(self):
        return f'<XXE {self.ip}, {self.referer}, {self.file}, {self.user_agent}, {self.timestamp}, {self.vulnerable_url}>'


class PayloadXXE(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    payload = db.Column(db.String(555), nullable=False)
    notes = db.Column(db.String(555))

    def __repr__(self):
        return f'<PayloadXXE {self.payload}, {self.notes}>'


class PayloadXSS(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    payload = db.Column(db.String(555), nullable=False)
    notes = db.Column(db.String(555))

    def __repr__(self):
        return f'<PayloadXSS {self.payload}, {self.notes}>'


class Contact(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')


class Post(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', back_populates='post', lazy='dynamic', cascade="all, delete-orphan")
    reactions = db.relationship('Reaction', back_populates='post', lazy='dynamic')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    image_url = db.Column(db.String(255), nullable=True)

    def total_reactions(self):
        return len(self.reactions.all())

    def __repr__(self):
        return f'<Post {self.title}>'

    def count_likes(self):
        return len([reaction for reaction in self.reactions if reaction.reaction_type == Reaction.LIKE])


class News(db.Model):
    __tablename__ = 'news'

    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref='news_posts')
    summary = db.Column(db.String(500), nullable=False)  # Ensure this line is indented correctly
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), nullable=True, default='default_news.png')
    publication_date = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<News {self.title}>'


class Reaction(db.Model):
    id = Column(Integer, primary_key=True)
    post_id = Column(Integer, ForeignKey('post.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    reaction_type = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    LIKE = 'LIKE'
    post = relationship('Post', back_populates='reactions')
    user = relationship('User', back_populates='reactions')

    def __repr__(self):
        return f'<Reaction {self.reaction_type} by User {self.user_id} on Post {self.post_id}>'


class Comment(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    text = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', back_populates='comments')
    post = db.relationship('Post', back_populates='comments')

    def __repr__(self):
        return f"Comment('{self.text}')"


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                        nullable=False)  # Ensure this matches your User model's table name and primary key column name
    sent = db.Column(db.Boolean, default=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship (if you have backref on the User model, this might be optional or adjusted)
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))


class RequestData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    method = db.Column(db.String(10))
    data = db.Column(db.String(1000))  # Simplified; adjust as needed
    user_agent = db.Column(db.String(255))
    referer = db.Column(db.String(255))
    host = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, method, data, user_agent, referer, host, user_id, created_at):
        self.method = method
        self.data = data
        self.user_agent = user_agent
        self.referer = referer
        self.host = host
        self.user_id = user_id
        self.created_at = created_at


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Note('{self.title}', '{self.date_posted}')"


