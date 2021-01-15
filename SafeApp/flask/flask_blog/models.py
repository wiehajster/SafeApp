from flask_blog import db, login_manager, app
from datetime import datetime
from flask_login import UserMixin
from flask import request
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    notes = db.relationship('Note', backref='author', lazy=True)
    files = db.relationship('File', backref='author', lazy=True)
    ip_addr = db.Column(db.String(50), nullable=False)

    def get_reset_token(self, expires_sec=900):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id' : self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"{self.username}"

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_log = db.Column(db.DateTime, nullable=False, default=datetime.now)
    ip_addr = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.String(120))

class LoginPenalty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_end = db.Column(db.DateTime, nullable=False)
    ip_addr = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_encrypted = db.Column(db.Boolean, nullable=False)
    is_public = db.Column(db.Boolean, nullable=False)
    password = db.Column(db.String(60))

    def __repr__(self):
        return f"Note('{self.title}', '{self.date_posted}')"

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    show_filename = db.Column(db.String(100), nullable=False)
    date_sent = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_public = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return f"File('{self.title}', '{self.date_sent}')"

class Sharing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'))
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Sharing('{self.note_id}', '{self.user_id}')"