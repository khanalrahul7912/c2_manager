from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import BooleanField, IntegerField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, NumberRange, Optional


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField("Sign in")


class HostForm(FlaskForm):
    name = StringField("Display name", validators=[DataRequired(), Length(max=120)])
    address = StringField("Address", validators=[DataRequired(), Length(max=255)])
    port = IntegerField("SSH port", validators=[DataRequired(), NumberRange(min=1, max=65535)], default=22)
    username = StringField("SSH username", validators=[DataRequired(), Length(max=80)])
    key_path = StringField("Private key path", validators=[Optional(), Length(max=255)])
    is_active = BooleanField("Enabled", default=True)
    submit = SubmitField("Save host")


class CommandForm(FlaskForm):
    command = TextAreaField("Command", validators=[DataRequired(), Length(min=1, max=2000)])
    submit = SubmitField("Run command")
