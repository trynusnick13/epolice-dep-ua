from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, TextAreaField
from wtforms import validators
from wtforms.validators import DataRequired, Email


class LoginForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=4, max=20)])
    password = PasswordField('Password', [validators.Length(min=6, max=50)])


class RegistrationForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=4, max=20)])
    email = StringField('Email Address', [Email(message=('Not a valid email address!',)), DataRequired()])
    password = PasswordField(
        'Password (Should have at least one number, have at least one uppercase and one lowercase character, '
        'have at least one special symbol, be between 6 to 20 characters long)', [
            validators.InputRequired(),
            validators.EqualTo('confirm', message='Passwords must match')
        ])
    confirm = PasswordField('Repeat Password')
    key = StringField('Secret code')
    accept_tos = BooleanField('I consent to the processing of my data',
                              [DataRequired()])


class ApplicationForm(FlaskForm):
    first_name = StringField('First name', [validators.Length(min=4, max=60)])
    second_name = StringField('Last name', [validators.Length(min=4, max=60)])
    phone = StringField('Phone')
    location = StringField('Location')
    application = TextAreaField('Details of incident')
    accept_tos = BooleanField('I consent to the processing of my data',
                              [DataRequired()])
