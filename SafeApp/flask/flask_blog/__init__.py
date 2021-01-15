from flask import Flask, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from datetime import timedelta
import os

app = Flask(__name__) #name of module

with open(app.root_path+'/static/secrets/secret_key.txt') as f:
    app.config['SECRET_KEY'] = f.read()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['UPLOAD_FOLDER'] = 'static/files'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

from flask_blog import routes