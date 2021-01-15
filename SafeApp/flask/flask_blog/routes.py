import os
import re
import time
import uuid
from datetime import datetime, timedelta
from werkzeug.utils import escape
from flask import (abort, flash, jsonify, make_response, redirect,
                   render_template, request, send_file,
                   session, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from flask_blog import app, bcrypt, db
from flask_blog.encrypt import decrypt_with_pass, encrypt_with_pass
from flask_blog.forms import (EncryptedNoteForm, FileForm, LoginForm, NoteForm,
                              RegistrationForm, RequestResetForm,
                              ResetPasswordForm)
from flask_blog.models import (File, LoginAttempt, LoginPenalty, Note, Sharing,
                               User)

HONEYPOTS = ['admin']
TIME_TO_WAIT = 5
MAX_ATTEMPTS = 5
TIME_WINDOW = 5

@app.errorhandler(413)
def request_entity_too_large(error):
    return 'Próbujesz przesłać zbyt duży plik. Maksymalny rozmiar pliku to 16 mb.', 413

@app.route('/')
@app.route('/home')
def home():
    notes = Note.query.filter_by(is_public=True).all()
    files = File.query.filter_by(is_public=True).all()
    return render_template('home.html', notes=notes, files=files)

# Notes

@app.route('/notes/public')
def public_notes():
    notes = Note.query.filter_by(is_public=True).all()
    return render_template('notes.html', notes=notes, legend='Publiczne notatki')

@app.route('/notes/shared')
@login_required
def shared_notes():
    ids = [res[0] for res in Sharing.query.filter_by(user_id=current_user.id).values('note_id')]
    notes = Note.query.filter(Note.id.in_(ids)).all()
    return render_template('notes.html', notes=notes, legend='Udostępnione dla mnie')

@app.route("/notes/private")
@login_required
def my_notes():
    notes = Note.query.filter_by(author=current_user).all()
    return render_template('notes.html', notes=notes, legend='Moje notatki')

@app.route("/note/<int:note_id>")
@login_required
def note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    return render_template('note.html', title=note.title, note=note, note_id=note_id)

@app.route("/note/new", methods=['GET', 'POST'])
@login_required
def new_note():
    users = User.query.filter(User.id != current_user.id).all()
    users = [(user.id, user.username) for user in users]
    form = NoteForm()
    form.share.choices = users

    if form.validate_on_submit():
        # Encrypted note
        if form.is_encrypted.data == True:
            content = form.content.data
            password = form.password.data
            
            encrypted_note, hashed = encrypt_with_pass(password, content)
            note = Note(title=form.title.data, content=encrypted_note, author=current_user,
                     is_encrypted=form.is_encrypted.data, is_public=False, password=hashed)
            db.session.add(note)
            db.session.commit()
        # Public note
        elif form.is_public.data == True:
            note = Note(title=form.title.data, content=form.content.data, author=current_user,
                     is_encrypted=form.is_encrypted.data, is_public=form.is_public.data)
            db.session.add(note)
            db.session.commit()
        # Shared note
        else:
            note = Note(title=form.title.data, content=form.content.data, author=current_user,
                     is_encrypted=False, is_public=False)
            db.session.add(note)
            db.session.commit()

            share_users = form.share.data
            for user_id in share_users:
                sharing = Sharing(note_id=note.id, user_id=user_id)
                db.session.add(sharing)
            db.session.commit()
        flash('Notatka została utworzona.', 'success')
        return redirect(url_for('home'))
    return render_template('create_note.html', title='Nowa notatka',
                         form=form, legend='Nowa notatka')


@app.route("/note/<int:note_id>/delete", methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    Sharing.query.filter_by(note_id=note.id).delete()
    db.session.delete(note)
    db.session.commit()
    flash('Notatka została usunięta.', 'success')
    return redirect(url_for('my_notes'))

@login_required
@app.route("/note/<int:note_id>/decrypt", methods=['GET', 'POST'])
def decrypt_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.author != current_user:
        abort(403)
    form = EncryptedNoteForm()
    if form.validate_on_submit():
        decrypted = decrypt_with_pass(form.password.data, note.content, note.password)
        if decrypted:
            decrypted_note = Note(title=note.title, content=decrypted, author=note.author,
                    is_encrypted=note.is_encrypted, is_public=note.is_public, password="", date_posted=note.date_posted, id=note.id)
            return render_template('note.html', title=decrypted_note.title, note=decrypted_note)
        flash('Hasło niepoprawne.', 'danger')
    return render_template('encrypted_note.html', title=note.title, note=note, form=form)

# Files

@app.route('/files/public')
def public_files():
    files = File.query.filter_by(is_public=True).all()
    return render_template('files.html', files=files, legend='Publiczne pliki')

@app.route('/files/shared')
@login_required
def shared_files():
    ids = [res[0] for res in Sharing.query.filter_by(user_id=current_user.id).values('file_id')]
    files = File.query.filter(File.id.in_(ids)).all()
    return render_template('files.html', files=files, legend='Udostępnione dla mnie')

@app.route("/files/private")
@login_required
def my_files():
    files = File.query.filter_by(author=current_user).all()
    return render_template('files.html', files=files, legend='Moje pliki')

@app.route("/file/upload", methods=['GET', 'POST'])
@login_required
def upload_file():
    users = User.query.filter(User.id != current_user.id).all()
    users = [(user.id, user.username) for user in users]
    form = FileForm()
    form.share.choices = users

    if form.validate_on_submit():
        secure_filename = escape(form.blob.data.filename)
        _, ext = os.path.splitext(secure_filename)
        filename = str(uuid.uuid4()) + ext
        show_filename = secure_filename

        form.blob.data.save(os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename))

        if form.is_public.data:
            new_file = File(filename=filename, show_filename=show_filename, author=current_user, is_public=form.is_public.data)
            db.session.add(new_file)
            db.session.commit()
        else:
            new_file = File(filename=filename, show_filename=show_filename, author=current_user, is_public=False)
            db.session.add(new_file)
            db.session.commit()
            share_users = form.share.data
            for user_id in share_users:
                sharing = Sharing(file_id=new_file.id, user_id=user_id)
                db.session.add(sharing)
            db.session.commit()

        flash('Plik został przesłany.', 'success')
        redirect(url_for('home'))
    return render_template('upload_file.html', title='Upload File',
                         form=form)

@app.route("/file/<int:file_id>/download")
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    sharing = None
    if current_user.is_authenticated:
        sharing = Sharing.query.filter_by(file_id=file.id, user_id=current_user.id).first()
    if not file.is_public and file.author != current_user and not sharing:
        abort(403)
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'],
                               file.filename), as_attachment=True)

@app.route("/file/<int:file_id>/delete", methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.author != current_user:
        abort(403)
    os.remove(os.path.join(app.root_path, app.config['UPLOAD_FOLDER'],
                               file.filename))
    Sharing.query.filter_by(file_id=file.id).delete()
    db.session.delete(file)
    db.session.commit()
    flash('Plik został usunięty.', 'success')
    return redirect(url_for('my_files'))

# Register

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data, 15).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, ip_addr=request.remote_addr)
        db.session.add(user)
        db.session.commit()
        flash(f'Twoje konto zostało utworzone. Teraz możesz się zalogować.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', title='Rejestracja', form=form)

# Login

def check_penalties(user):
    user_penalty = None
    if user:
        user_penalty = LoginPenalty.query.filter_by(user_id=user.id).first()
    ip_penalty = LoginPenalty.query.filter_by(ip_addr=request.remote_addr).first()
    is_penalty = False
    # User penalty
    if user_penalty:
        if datetime.utcnow() < user_penalty.date_end:
            is_penalty = True
        else:
            LoginAttempt.query.filter_by(user_id=user.id).delete()
            db.session.delete(user_penalty)
            db.session.commit()
    # IP penalty
    if ip_penalty:
        if datetime.utcnow() < ip_penalty.date_end:
            is_penalty = True
        else:
            LoginAttempt.query.filter_by(ip_addr=request.remote_addr).delete()
            db.session.delete(ip_penalty)
            db.session.commit()

    return is_penalty

def check_bad_logins(user):
    before_date = datetime.utcnow() - timedelta(minutes=TIME_WINDOW)
    user_bad_logins = []
    if user:
        user_bad_logins = LoginAttempt.query.filter(LoginAttempt.date_log >= before_date, LoginAttempt.user_id==user.id).all()
        LoginAttempt.query.filter(LoginAttempt.date_log < before_date, LoginAttempt.user_id==user.id).delete()
    ip_bad_logins = LoginAttempt.query.filter(LoginAttempt.date_log >= before_date, LoginAttempt.ip_addr==request.remote_addr).all()
    LoginAttempt.query.filter(LoginAttempt.date_log < before_date, LoginAttempt.ip_addr==request.remote_addr).delete()
    db.session.commit()

    is_penalty = False

    if len(user_bad_logins) >= MAX_ATTEMPTS:
        date_end = datetime.utcnow() + timedelta(minutes=TIME_TO_WAIT)
        penalty = LoginPenalty(date_end=date_end, user_id=user.id)
        db.session.add(penalty)
        db.session.commit()
        is_penalty = True
    
    if len(ip_bad_logins) >= MAX_ATTEMPTS:
        date_end = datetime.utcnow() + timedelta(minutes=TIME_TO_WAIT)
        penalty = LoginPenalty(date_end=date_end, ip_addr=request.remote_addr)
        db.session.add(penalty)
        db.session.commit()
        is_penalty = True

    return is_penalty

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        # Check honeypots
        if user and user.username in HONEYPOTS:
            print('Potencjalny atak na aplikację!')
        
        # Check login penalties
        is_penalty = check_penalties(user)

        if is_penalty:
            flash('Zbyt wiele błędnych prób logowania. Poczekaj zanim spróbujesz zalogować się ponownie.', 'danger')
            return render_template('login.html', title='Logowanie', form=form)

        time.sleep(2)
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if request.remote_addr != user.ip_addr:
                print('Logowanie z nowego adresu ip: ', request.remote_addr) # wysłałabym to w emailu
            session.permanent = True # sprawdzić czy to zostawić
            login_user(user)
            flash('Zostałeś zalogowany.', 'success')
            return redirect_dest('home')
        else:
            # Add bad login attempt
            if user:
                login = LoginAttempt(user_id=user.id, ip_addr=request.remote_addr)
            else:
                login = LoginAttempt(ip_addr=request.remote_addr)
            db.session.add(login)
            db.session.commit()

            # Check number of bad logins
            is_penalty = check_bad_logins(user)
            if is_penalty:
                flash('Zbyt wiele błędnych prób logowania. Poczekaj zanim spróbujesz zalogować się ponownie.', 'danger')
            flash('Logowanie nie powiodło się. Sprawdź email i hasło.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Reset password

def send_reset_email(user):
    token = user.get_reset_token()
    message = 'Aby zresetować hasło, odwiedź poniższy link: {}'.format(url_for('reset_token', token=token, _external=True))
    print(message)

@app.route("/reset_password/new", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('Na twojego emaila została przesłana wiadomość z dalszymi instrukcjami.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('Nieprawidłowy lub nieważny token.', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data, 15).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'Hasło zostało zmienione.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)
    
def redirect_dest(fallback):
    dest = request.args.get('next')
    if dest is not None:
        dest = re.sub('/', '', dest)
    try:
        dest_url = url_for(dest)
    except:
        return redirect(fallback)
    return redirect(dest_url)
