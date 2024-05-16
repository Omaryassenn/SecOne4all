from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SubmitField, URLField, FileField, DateTimeField, \
    RadioField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_wtf.file import FileField, FileAllowed


class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(min=10, max=100)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(min=10, max=100)])
    message = TextAreaField("Message", validators=[DataRequired(), Length(min=10, max=1000)])
    submit = SubmitField("Submit")


class Login(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(min=10, max=100)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=10, max=100)])
    submit = SubmitField("Login")


class Register(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(min=10, max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=10, max=100)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    image = FileField('Profile Image', validators=[FileAllowed(['jpg', 'jpeg', 'png']), DataRequired()])
    submit = SubmitField('Register')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=10, max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=10, max=10000)])
    image = FileField('Post Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    submit = SubmitField('Submit')


class ChangePasswordForm(FlaskForm):
    current_username = StringField('Username', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=10, max=100)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit_password = SubmitField('Change Password')


class UpdateProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    image = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'jpeg', 'png'])])
    submit_profile = SubmitField('Update Profile')


class RestPasswordForm(FlaskForm):
    email = StringField('Email', validators=[Email()])
    rest_password = SubmitField("Rest Password")


class UpdatePassword(FlaskForm):
    new_password = PasswordField("New Password", validators=[
        DataRequired(),
        Length(min=10, max=100)
    ])
    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    update_password = SubmitField("Update Password")


class NewsForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=10, max=100)])
    summary = StringField('Summary', validators=[DataRequired(), Length(min=100, max=10000)])
    content = TextAreaField('Content (Markdown)', validators=[DataRequired(), Length(min=10, max=10000)])
    image = FileField('Image', validators=[FileAllowed(['jpg', 'jpeg', 'png'])])
    publication_date = DateTimeField('Publication Date', format='%Y-%m-%d %H:%M:%S')


class XSSPayloadForm(FlaskForm):
    payload = TextAreaField("XSS Payload", validators=[DataRequired(), Length(min=1)])
    notes = TextAreaField("Notes", validators=[Length(max=500)])
    submit = SubmitField("Add XSS Payload")


class AddReactionForm(FlaskForm):
    # Assuming reactions are predefined strings like 'like', 'love', 'haha', etc.
    reaction = RadioField('Reaction', choices=[('like', 'Like'), ('love', 'Love'), ('haha', 'Haha')],
                          validators=[DataRequired()])
    submit = SubmitField('React')


class CommentForm(FlaskForm):
    # Assuming you want a simple text area for the comment
    text = StringField('Comment', validators=[DataRequired(), Length(min=1, max=500)],
                         render_kw={"placeholder": "Write your comment here..."})

    # The submit button
    submit = SubmitField('Post Comment')


class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

class CommentForm(FlaskForm):
    text = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Add Comment')