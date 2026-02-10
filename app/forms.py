from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
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
    key_path = StringField("Private key path", validators=[Optional(), Length(max=255)])
    strict_host_key = BooleanField("Strict host key validation", default=True)
    is_active = BooleanField("Enabled", default=True)
    submit = SubmitField("Save host")


class CommandForm(FlaskForm):
    command = TextAreaField("Command", validators=[DataRequired(), Length(min=1, max=2000)])
    submit = SubmitField("Run command")


class BulkHostImportForm(FlaskForm):
    csv_rows = TextAreaField(
        "Bulk host rows",
        description=(
            "One host per line: name,address,username,port(optional),key_path(optional),group(optional),strict_host_key(optional true/false)"
        ),
        validators=[DataRequired(), Length(max=20000)],
    )
    submit = SubmitField("Import hosts")


class BulkCommandForm(FlaskForm):
    host_ids = SelectMultipleField("Target hosts", coerce=int, validators=[DataRequired()])
    command = TextAreaField("Command", validators=[DataRequired(), Length(min=1, max=2000)])
    submit = SubmitField("Run command on selected hosts")
