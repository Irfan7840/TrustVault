import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from trustvault.models.user import User, UserRole


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=30, message="Username must be between 3 and 30 characters."),
        ],
    )
    email = StringField(
        "Email Address",
        validators=[
            DataRequired(),
            Email(message="Please provide a valid email address.", check_deliverability=False),
            Length(max=120),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128, message="Password must be at least 8 characters."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    role = SelectField(
        "Account Type",
        choices=[
            (UserRole.OWNER, "Document Owner (Can upload and share)"),
            (UserRole.VIEWER, "Viewer (Can view shared documents)"),
        ],
        default=UserRole.OWNER,
        validators=[DataRequired()],
    )
    submit = SubmitField("Create Secure Account")

    def validate_username(self, field):
        # Enforce alphanumeric + underscores
        if not re.match(r"^[a-zA-Z0-9_]+$", field.data):
            raise ValidationError("Username can only contain letters, numbers, and underscores.")
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("This username is already taken. Please choose another.")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError("An account with this email address already exists.")

    def validate_password(self, field):
        pwd = field.data
        if not any(c.isupper() for c in pwd):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in pwd):
            raise ValidationError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in pwd):
            raise ValidationError("Password must contain at least one digit.")


class LoginForm(FlaskForm):
    username = StringField("Username or Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember this device")
    submit = SubmitField("Sign In")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        "Current Password",
        validators=[DataRequired(message="Please provide your current password.")],
    )
    new_password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128, message="New password must be at least 8 characters."),
        ],
    )
    confirm_new_password = PasswordField(
        "Confirm New Password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="New passwords must match."),
        ],
    )
    submit = SubmitField("Update Password")

    def validate_new_password(self, field):
        pwd = field.data
        if not any(c.isupper() for c in pwd):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in pwd):
            raise ValidationError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in pwd):
            raise ValidationError("Password must contain at least one digit.")
