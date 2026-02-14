from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    SelectField,
    SelectMultipleField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Length, NumberRange, Optional


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField("Sign in")


class HostForm(FlaskForm):
    name = StringField("Display name", validators=[DataRequired(), Length(max=120)])
    address = StringField("Address", validators=[DataRequired(), Length(max=255)])
    group_name = StringField("Group", validators=[Optional(), Length(max=80)])
    port = IntegerField("SSH port", validators=[DataRequired(), NumberRange(min=1, max=65535)], default=22)
    username = StringField("SSH username", validators=[DataRequired(), Length(max=80)])
    auth_mode = SelectField("Auth mode", choices=[("key", "SSH key"), ("password", "Password")], default="key")
    key_path = StringField("Private key path", validators=[Optional(), Length(max=255)])
    password = PasswordField("SSH password", validators=[Optional(), Length(max=255)])
    strict_host_key = BooleanField("Strict host key validation", default=True)

    use_jump_host = BooleanField("Use jump host")
    jump_address = StringField("Jump host address", validators=[Optional(), Length(max=255)])
    jump_port = IntegerField("Jump host port", validators=[Optional(), NumberRange(min=1, max=65535)], default=22)
    jump_username = StringField("Jump host username", validators=[Optional(), Length(max=80)])
    jump_auth_mode = SelectField("Jump auth mode", choices=[("key", "SSH key"), ("password", "Password")], default="key")
    jump_key_path = StringField("Jump private key path", validators=[Optional(), Length(max=255)])
    jump_password = PasswordField("Jump host password", validators=[Optional(), Length(max=255)])

    is_active = BooleanField("Enabled", default=True)
    submit = SubmitField("Save host")


class CommandForm(FlaskForm):
    command = TextAreaField("Command", validators=[DataRequired(), Length(min=1, max=2000)])
    submit = SubmitField("Run command")


class BulkHostImportForm(FlaskForm):
    csv_rows = TextAreaField(
        "Bulk host rows",
        description=(
            "One host per line: name,address,username,port(optional),auth_mode[key|password],key_path,password,group,strict_host_key"
        ),
        validators=[DataRequired(), Length(max=25000)],
    )
    submit = SubmitField("Import hosts")


class BulkCommandForm(FlaskForm):
    host_ids = SelectMultipleField("Target hosts", coerce=int, validators=[DataRequired()])
    command = TextAreaField("Command", validators=[DataRequired(), Length(min=1, max=2000)])
    submit = SubmitField("Run command on selected hosts")


class ShellCommandForm(FlaskForm):
    command = TextAreaField("Command", validators=[DataRequired(), Length(min=1, max=5000)])
    submit = SubmitField("Execute command")


class BulkShellCommandForm(FlaskForm):
    shell_ids = SelectMultipleField("Target shells", coerce=int, validators=[DataRequired()])
    command = TextAreaField("Command", validators=[DataRequired(), Length(min=1, max=2000)])
    submit = SubmitField("Run command on selected shells")


class ReverseShellForm(FlaskForm):
    name = StringField("Display name", validators=[DataRequired(), Length(max=120)])
    group_name = StringField("Group", validators=[Optional(), Length(max=80)])
    is_active = BooleanField("Enabled", default=True)
    submit = SubmitField("Save shell")
