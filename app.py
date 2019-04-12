import datetime, os, uuid
from flask import Flask, render_template, redirect, flash, url_for, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_login import current_user, login_user, LoginManager, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor, upload_success, upload_fail

basedir = os.path.dirname(__file__)

app = Flask(__name__)
app.secret_key = "CS252 Spring 2019 Lab 6"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cs252sp19lab6.db'
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_HEIGHT'] = 400
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
#Talisman(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.session_protection = "strong"
ckeditor = CKEditor(app)
blacklist = []


class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    password = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def __init__(self, username, email):
        self.username = username
        self.email = email


class Secrets(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    content = db.Column(db.Text, nullable=False)
    submit_time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())
    post_time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())

    def __init__(self, content):
        self.content = content


class Queue(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    content = db.Column(db.Text, nullable=False)
    submit_time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())

    def __init__(self, content):
        self.content = content


class Reported(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    count = db.Column(db.Integer, nullable=False)

    def __init__(self, id, content, reason, count):
        self.id = id
        self.content = content
        self.reason = reason
        self.count = count


db.create_all()
# master_admin = Admin('admin', 'tsangh@purdue.edu')
# master_admin.set_password('password')
# db.session.add(master_admin)
# db.session.commit()


# first parameter (String): the text that may contain to-be-censored words
# second parameter (List) : the list of blacklist words
# return (String)         : the text with words censored in asterisks
def censorBySubstring(text, blacklist):
    # String in python are immutable
    # iterate for each blacklistedWord in blacklist
    for blacklistedWord in blacklist:
        if text.find(blacklistedWord) != -1:
            text = text.replace(blacklistedWord, "*" * len(blacklistedWord))

    return text


# first parameter (String): the name of the file to import the blacklists from
# return (List of Strings): list of blacklist words from the imported file
def getBlacklistWordsFromFile(fileName):
    with open(fileName) as f:
        content = f.readlines()

    # remove leading and trailing white spaces
    content = [x.strip() for x in content]

    return content


# first parameter (String): the text that is going to be be posted depending on the return value of this function
# return (Boolean): return true if the text doesn't contain any asterisks, return fals if the text contains at least one asterisks
# Make sure the user doesn't write any asterisks since it will be regarded as a censored character
def isPostable(text):
    count = 0

    for c in text:
        if c == '*':
            count+=1

    return (count == 0)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/wall')
def wall():
    secrets = Secrets.query.order_by(Secrets.id.desc()).all()
    return render_template('wall.html', secrets=secrets)


@app.route('/wall/<int:sid>')
def secret_details(sid):
    return render_template('secret_details.html', secret=Secrets.query.filter_by(id=sid).first())


@app.route('/add', methods=['POST', 'GET'])
def add():
    if request.method == 'POST':
        if not request.form.get('ckeditor'):
            flash('Post cannot be empty.', 'error')
        else:
            content = request.form.get('ckeditor')

            blacklist = getBlacklistWordsFromFile("blacklist.txt")
            content = censorBySubstring(content, blacklist)

            # censorBySubstring is recommended over censorByWords because
            # for example: '<p>fuck' or 'fuck</p>' does not get filtered out
            # UNLESS we are able to get rid of the wrapping tags

            # Redirect to either the admin or the DB
            if isPostable(content):
                post = Secrets(content=content)
                db.session.add(post)
                db.session.flush()
                db.session.commit()
                flash('Post Success!')
                return redirect(url_for('wall'))
            else:
                post = Queue(content=content)
                db.session.add(post)
                db.session.flush()
                db.session.commit()
                flash('Post has been sent to the administrator.')
                return redirect(url_for('wall'))

    return render_template('add.html')


@app.route('/report', methods=['POST', 'GET'])
def report():
    if request.method == 'POST':
        if not request.form['id'] or not request.form['reason']:
            flash('Please enter all the fields', 'error')
        else:
            id = request.form['id']
            secret = Secrets.query.filter_by(id=id).first()
            reason = request.form['reason']
            if not secret:
                flash('Invalid ID.', 'error')
            elif not Reported.query.filter_by(id=id).first():
                report = Reported(id=id, content=secret.content, reason=reason, count=1)
                db.session.add(report)
                db.session.commit()
                flash('Report has been sent to the administrator.')
                return redirect(url_for('wall'))
            else:
                report = Reported.query.filter_by(id=id).first()

                count = report.count + 1
                reason = report.reason + ', ' + request.form['reason']
                new_report = Reported(id=id, content=secret.content, reason=reason, count=count)

                db.session.delete(report)
                db.session.flush()
                db.session.add(new_report)
                db.session.flush()
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
            username = request.form['username']
            user = Admin.query.filter_by(username=username).first()
            password = request.form['password']
            if user is None:
                flash('User not found.', 'error')
            elif user.check_password(password):
                login_user(user)
                return redirect(url_for('adminQueue'))
            else:
                flash('Invalid login.', 'error')

    return render_template('admin_login.html')


@app.route('/admin/reported', methods=['POST', 'GET'])
@login_required
def adminReported():
    reports = Reported.query.order_by(Reported.count.desc()).all()
    return render_template('admin_reported.html', reports=reports)


@app.route('/admin/queue', methods=['POST', 'GET'])
@login_required
def adminQueue():
    return render_template('admin_queue.html', queue=Queue.query.all())


@app.route('/admin/logout')
@login_required
def adminLogout():
    logout_user()
    return redirect(url_for('adminLogin'))


@app.route('/admin/reported/<int:sid>/delete')
@login_required
def deleteFromReported(sid):
    s_post = Secrets.query.filter_by(id=sid).first()
    r_post = Reported.query.filter_by(id=sid).first()
    db.session.delete(s_post)
    db.session.flush()
    db.session.delete(r_post)
    db.session.flush()
    db.session.commit()
    flash('Post was successfully deleted.')

    return redirect(url_for('adminReported'))


@app.route('/admin/reported/<int:sid>/ignore')
@login_required
def ignoreReported(sid):
    post = Reported.query.filter_by(id=sid).first()
    db.session.delete(post)
    db.session.flush()
    db.session.commit()
    message = 'Report of #' + str(sid) + ' has been ignored.'
    flash(message)

    return redirect(url_for('adminReported'))



@app.route('/admin/queue/<int:qid>/delete')
@login_required
def deleteFromQueue(qid):
    post = Queue.query.filter_by(id=qid).first()
    db.session.delete(post)
    db.session.flush()
    db.session.commit()
    flash('Post was successfully deleted.')

    return redirect(url_for('adminQueue'))


@app.route('/admin/queue/<int:qid>/migrate')
@login_required
def migrateFromQueue(qid):
    q_post = Queue.query.filter_by(id=qid).first()
    content = q_post.content
    s_post = Secrets(content=content)
    s_post.post_time = datetime.datetime.utcnow()
    db.session.add(s_post)
    db.session.flush()
    db.session.delete(q_post)
    db.session.flush()
    db.session.commit()
    flash('Post was approved, and pushed to the wall.')

    return redirect(url_for('adminQueue'))


@app.route('/files/<path:filename>')
def uploaded_files(filename):
    path = basedir + '/bin/'
    return send_from_directory(path, filename)


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('upload')
    extension = f.filename.rsplit('.', 1)[1].lower()

    if extension not in ['jpg', 'gif', 'png', 'jpeg']:
        return upload_fail(message='Image only.')
    unique_filename = str(uuid.uuid4())
    f.filename = unique_filename + '.' + extension
    bin_path = basedir + '/bin/'
    f.save(os.path.join(bin_path, f.filename))
    url = url_for('uploaded_files', filename=f.filename)

    return upload_success(url=url)


@login_manager.user_loader
def getAdmin(id):
    return Admin.query.get(int(id))


if __name__ == '__main__':
    app.run()

