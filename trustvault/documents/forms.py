from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length
from trustvault.models.permission import PermissionLevel


CATEGORIES = [
    ("General", "General"),
    ("Financial", "Financial"),
    ("Legal", "Legal"),
    ("Security", "Security"),
    ("Technical", "Technical"),
    ("Operations", "Operations"),
]


class DocumentUploadForm(FlaskForm):
    title = StringField(
        "Document Title",
        validators=[
            DataRequired(),
            Length(min=2, max=200, message="Title must be between 2 and 200 characters."),
        ],
    )
    category = SelectField(
        "Category",
        choices=CATEGORIES,
        default="General",
        validators=[DataRequired()],
    )
    description = TextAreaField("Description", validators=[Length(max=2000)])
    document_file = FileField(
        "Select File",
        validators=[FileRequired(message="Please select a document file to upload.")],
    )
    submit = SubmitField("Upload Document")


class DocumentEditForm(FlaskForm):
    title = StringField(
        "Document Title",
        validators=[
            DataRequired(),
            Length(min=2, max=200, message="Title must be between 2 and 200 characters."),
        ],
    )
    category = SelectField(
        "Category",
        choices=CATEGORIES,
        default="General",
        validators=[DataRequired()],
    )
    description = TextAreaField("Description", validators=[Length(max=2000)])
    submit = SubmitField("Update Metadata")


class GrantPermissionForm(FlaskForm):
    username_or_email = StringField(
        "Username or Email",
        validators=[
            DataRequired(message="Please enter a username or email address."),
            Length(max=120),
        ],
    )
    permission_level = SelectField(
        "Permission Level",
        choices=[
            (PermissionLevel.READ, "Read (View and Download)"),
            (PermissionLevel.EDIT, "Edit (View, Download, and Edit Metadata)"),
        ],
        default=PermissionLevel.READ,
        validators=[DataRequired()],
    )
    submit = SubmitField("Grant Access")
