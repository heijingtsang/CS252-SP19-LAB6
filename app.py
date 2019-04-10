import datetime, os
from flask import Flask, render_template, redirect, flash, url_for, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_login import current_user, login_user, login_manager, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor, upload_success, upload_fail


app = Flask(__name__)
Talisman(app)
db = SQLAlchemy(app)
login_manager = login_manager(app)
# login_manager.init_app(app)
ckeditor = CKEditor(app)
app.secret_key = "CS252 Spring 2019 Lab 6"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cs252sp19lab6.db'
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_HEIGHT'] = 400
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'


class Admin(db.Model):
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email


class Secrets(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(250), nullable=False)
    content = db.Column(db.Text, nullable=False)
    submit_time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())
    post_time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())

    def __init__(self, title, content):
        self.title = title
        self.content = content


class Queue(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(250), nullable=False)
    content = db.Column(db.text, nullable=False)
    submit_time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())

    def __init__(self, title, content):
        self.title = title
        self.content = content


class Reported(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(250), nullable=False)
    content = db.Column(db.text, nullable=False)
    reason = db.Column(db.text, nullable=False)
    count = db.Column(db.Integer, nullable=False)

    def __init__(self, title, content, reason, count):
        self.title = title
        self.content = content
        self.reason = reason
        self.count = count


db.create_all()


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/wall')
def wall():
    return render_template('wall.html', secrets=Secrets.query.all())


@app.route('/add', methods=['POST', 'GET'])
def add():
    return render_template('add.html')


@app.route('/report', methods=['POST', 'GET'])
def report():
    if request.method == 'POST':
        if not request.form['id'] or not request.form['reason']:
            flash('Please enter all the fields', 'error')
        else:
            id = request.form['id']
            secret = Secrets.query.filter_by(id=id).first()
            report = Reported(sid=secret)

            db.session.add(report)
            db.session.commit()
            flash('Report has been sent to the administrator.')
            return redirect(url_for('wall'))

    return render_template('report.html')


@app.route('/admin', methods=['POST', 'GET'])
def adminLogin():
    if current_user.is_authenticated:
        return redirect(url_for('adminQueue'))

    if request.method == 'POST':
        if not request.form['username'] or not request.form['password']:
            flash('Please enter both your username and password.', 'error')
        else:
            user = Admin.get(request.form['username'])

            if user.check_password(request.form['password']):
                login_user(user)
                return redirect(url_for('adminQueue'))
            else:
                flash('Invalid login.', 'error')

    return render_template('admin_login.html')


@app.route('/admin/reported', methods=['POST', 'GET'])
@login_required
def adminReported():
    return render_template('admin_reported.html', report=Reported.query.all())


@app.route('/admin/queue', methods=['POST', 'GET'])
@login_required
def adminQueue():
    return render_template('admin_queue.html', queue=Queue.query.all())


@app.route('/admin/logout')
@login_required
def adminLogout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/files/<path:filename>')
def uploaded_files(filename):
    path = '/bin'
    return send_from_directory(path, filename)


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('upload')
    extension = f.filename.split('.')[1].lower()

    if extension not in ['jpg', 'gif', 'png', 'jpeg']:
        return upload_fail(message='Image only.')

    f.save(os.path.join('/bin', f.filename))
    url = url_for('uploaded_files', filename=f.filename)

    return upload_success(url=url)


if __name__ == '__main__':
    app.run()
