from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField
from wtforms.validators import DataRequired
from trustvault.models.user import UserRole


class UserRoleForm(FlaskForm):
    role = SelectField(
        "Role",
        choices=[
            (UserRole.ADMIN, "Administrator"),
            (UserRole.OWNER, "Document Owner"),
            (UserRole.VIEWER, "Viewer"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Update Role")
