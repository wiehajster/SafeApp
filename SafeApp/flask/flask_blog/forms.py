from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, HiddenField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, DataRequired, StopValidation, Regexp
import email_validator
from flask_blog.models import User
from flask_login import current_user
from flask_blog.validators import Password, Username, validate_password
from flask_wtf.file import FileField, FileAllowed

class RegistrationForm(FlaskForm):
    username = StringField('Nazwa użytkownika',
     validators=[DataRequired(), Length(min=2, max=50), Username()])
    email = StringField('Email', validators=[DataRequired(), Email(message='Niepoprawny adres email.')])
    password = PasswordField('Hasło',
     validators=[DataRequired(), Length(min=8, message='Hasło musi zawierać co najmniej 8 znaków.'), Password()])
    confirm_password = PasswordField('Potwierdź hasło',
     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Zarejestruj') #, render_kw={'disabled':True}

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Nazwa użytkownika jest zajęta. Wybierz inną.')
    
    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('Email jest zajęty. Wybierz inny.')
        
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='Niepoprawny adres email.')])
    password = PasswordField('Hasło',
     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Zaloguj')

class NoteForm(FlaskForm):
    title = StringField('Tytuł', validators=[DataRequired(), Length(max=100, message='Pole nie może zawierać więcej niż 100 znaków.'), Regexp('[^<>\\\/]', message='Użyto niedozwolonych znaków.')])
    content = TextAreaField('Treść', validators=[DataRequired(), Length(max=5000, message='Pole nie może zawierać więcej niż 5000 znaków.'), Regexp('[^<>\\\/]', message='Użyto niedozwolonych znaków.')])
    is_encrypted = BooleanField('Notatka zaszyfrowana')
    is_public = BooleanField('Notatka publiczna')
    submit = SubmitField('Wyślij')
    password = PasswordField('Hasło',
     validators=[validate_password])
    confirm_password = PasswordField('Potwierdź hasło',
     validators=[validate_password])
    share = SelectMultipleField('Udostępnij dla', default=None, coerce=int)

class FileForm(FlaskForm):
    blob = FileField('Wyślij plik', validators=[DataRequired()])
    is_public = BooleanField('Plik publiczny')
    share = SelectMultipleField('Udostępnij dla', default=None, coerce=int)
    submit = SubmitField('Wyślij')
    
class EncryptedNoteForm(FlaskForm):
    note_id = HiddenField('note_id')
    password = PasswordField('Hasło',
     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Odszyfruj')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='Niepoprawny adres email.')])
    submit = SubmitField('Poproś o reset hasła')
'''
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Nie ma konta z takim emailem.')
'''
class ResetPasswordForm(FlaskForm):
    password = PasswordField('Hasło',
     validators=[DataRequired(), Length(min=8, message='Hasło musi zawierać co najmniej 8 znaków.'), Password()])
    confirm_password = PasswordField('Potwierdź hasło',
     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Resetuj hasło')