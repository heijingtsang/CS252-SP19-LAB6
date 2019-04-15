import datetime, os, uuid
from flask import Flask, render_template, redirect, flash, url_for, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
#from flask_talisman import Talisman
from flask_login import current_user, login_user, LoginManager, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor, upload_success, upload_fail
from flask_wtf.csrf import CSRFProtect
#from flask_sslify import SSLify
from flask_mail import Mail, Message
import password

basedir = os.path.dirname(__file__)
blacklist = []

app = Flask(__name__)
app.secret_key = "CS252 Spring 2019 Lab 6"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cs252sp19lab6.db'
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_ENABLE_CSRF'] = True
app.config['CKEDITOR_EXTRA_PLUGINS'] = ['image2']
app.config['SECRET_KEY'] = 'CS252 Spring 2019 Lab 6'
app.config['CKEDITOR_HEIGHT'] = 400
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
#Talisman(app)
#sslify = SSLify(app)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.session_protection = "strong"
ckeditor = CKEditor(app)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'purdueSecrets2019@gmail.com'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)
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
    email = db.Column(db.Text)

    def __init__(self, content):
        self.content = content

    def __init__(self, content, email):
        self.content = content
        self.email = email

class Reported(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    count = db.Column(db.Integer, nullable=False)
    email = db.Column(db.Text)

    def __init__(self, id, content, reason, count):
        self.id = id
        self.content = content
        self.reason = reason
        self.count = count

    def __init__(self, id, content, reason, count, email):
        self.id = id
        self.content = content
        self.reason = reason
        self.count = count
        self.email = email

db.create_all()
#master_admin = Admin('admin', 'tsangh@purdue.edu')
#master_admin.set_password('password')
#db.session.add(master_admin)
#db.session.commit()


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
            count += 1

    return count == 0


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
            blpath = basedir + "/blacklist.txt"
            blacklist = getBlacklistWordsFromFile(blpath)
            content = censorBySubstring(content, blacklist)
            flag = True
            if content.find(".jpg") != -1 or content.find(".jpeg") != -1 or content.find(".gif") != -1 or content.find(".png") != -1:
                flag = False

            email = request.form.get('emailTextFieldAdd')
            emailFlag = False
            if email == "":
                emailFlag = False
                # flash("email field is empty!")
            else:
                emailFlag = True
                # flash("email field is not empty" + email)

            # censorBySubstring is recommended over censorByWords because
            # for example: '<p>fuck' or 'fuck</p>' does not get filtered out
            # UNLESS we are able to get rid of the wrapping tags

            # Redirect to either the admin or the DB
            if isPostable(content) and flag and emailFlag is False:
                post = Secrets(content=content)
                db.session.add(post)
                db.session.flush()
                db.session.commit()
                flash('Post Success!')
                return redirect(url_for('wall'))
            else:
                post = Queue(content=content, email=email)
                db.session.add(post)
                db.session.flush()
                db.session.commit()
                flash('Post has been sent to the administrator.')
                return redirect(url_for('wall'))

    return render_template('add.html')


@app.route('/report', methods=['POST', 'GET'])
def report():
    if request.method == 'POST':
        if not request.form['id'] or not request.form.get('ckeditor'):
            flash('Please enter all the fields', 'error')
        else:
            id = request.form['id']
            secret = Secrets.query.filter_by(id=id).first()
            reason = request.form.get('ckeditor')
            email = request.form.get("emailTextFieldReport")
            emailFlag = False
            if email == "":
                emailFlag = False
            else:
                emailFlag = True

            blpath = basedir + "/blacklist.txt"
            blacklist = getBlacklistWordsFromFile(blpath)
            reason = censorBySubstring(reason, blacklist)

            if not secret:
                flash('Invalid ID.', 'error')
            elif not Reported.query.filter_by(id=id).first():
                if emailFlag:
                    report = Reported(id=id, content=secret.content, reason=reason, count=1, email=email)
                else:
                    report = Reported(id=id, content=secret.content, reason=reason, count=1)

                db.session.add(report)
                db.session.commit()
                flash('Report has been sent to the administrator.')
                return redirect(url_for('wall'))
            else:
                report = Reported.query.filter_by(id=id).first()

                count = report.count + 1
                reason = report.reason + ', ' + reason
                new_report = Reported(id=id, content=secret.content, reason=reason, count=count) # not sure about the email attribute here

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
def deleteFromReported(sid, email):
    r_post = Reported.query.filter_by(id=sid).first()

    if r_post is None:
        flash('This post has already been handled.', 'info')
        return redirect(url_for('adminReported'))

    emailDest = Reported.query.filter_by(email=email).first()

    s_post = Secrets.query.filter_by(id=sid).first()
    db.session.delete(s_post)
    db.session.flush()
    db.session.delete(r_post)
    db.session.flush()
    db.session.commit()
    flash('Post was successfully deleted.')

    if emailDest != "":
        msg = Message('Hello from Purdue Secrets!', sender='purdueSecrets2019@gmail.com', recipients=[emailDest])
        msg.body = """We are sending this email to inform that your post has been reported by other users 
        and after the examinations from the admins, we decided to delete your post"""
        mail.send(msg)

    return redirect(url_for('adminReported'))


@app.route('/admin/reported/<int:sid>/ignore')
@login_required
def ignoreReported(sid, email):
    post = Reported.query.filter_by(id=sid).first()

    if post is None:
        flash('This post has already been handled.', 'info')
        return redirect(url_for('adminReported'))

    emailDest = Reported.query.filter_by(email=email).first()

    db.session.delete(post)
    db.session.flush()
    db.session.commit()
    message = 'Report of #' + str(sid) + ' has been ignored.'
    flash(message)

    if emailDest != "":
        msg = Message('Hello from Purdue Secrets!', sender='purdueSecrets2019@gmail.com', recipients=[emailDest])
        msg.body = """We are sending this email to inform that your post has been reported by other users 
            and after the examinations from the admins, we decided to keep your post on the wall"""
        mail.send(msg)

    return redirect(url_for('adminReported'))



@app.route('/admin/queue/<int:qid>/delete')
@login_required
def deleteFromQueue(qid, email):
    post = Queue.query.filter_by(id=qid).first()

    if post is None:
        flash('This post has already been handled.', 'info')
        return redirect(url_for('adminQueue'))

    emailDest = Queue.query.filter_by(email=email).first()

    db.session.delete(post)
    db.session.flush()
    db.session.commit()
    flash('Post was successfully deleted.')

    if emailDest != "":
        msg = Message('Hello from Purdue Secrets!', sender='purdueSecrets2019@gmail.com', recipients=[emailDest])
        msg.body = """We are sending this email to inform that after the examinations from the admins, we decided to delete your post"""
        mail.send(msg)

    return redirect(url_for('adminQueue'))


@app.route('/admin/queue/<int:qid>/migrate')
@login_required
def migrateFromQueue(qid, email):
    q_post = Queue.query.filter_by(id=qid).first()

    if q_post is None:
        flash('This post has already been handled.', 'info')
        return redirect(url_for('adminQueue'))

    emailDest = Queue.query.filter_by(email=email).first()
    postID = q_post.id

    content = q_post.content
    s_post = Secrets(content=content)
    s_post.post_time = datetime.datetime.utcnow()
    db.session.add(s_post)
    db.session.flush()
    db.session.delete(q_post)
    db.session.flush()
    db.session.commit()
    flash('Post was approved, and pushed to the wall.')

    if emailDest != "":
        msg = Message('Hello from Purdue Secrets!', sender='purdueSecrets2019@gmail.com', recipients=[emailDest])
        msg.body = """We are sending this email to inform that after the examinations from the admins, we decided to approve your post.\n
        The link to your approve post: https://tsangh.pythonanywhere.com/wall/""" + str(postID)
        mail.send(msg)

    return redirect(url_for('adminQueue'))


@app.route('/admin/create_account', methods=['POST', 'GET'])
@login_required
def createAccount():
    if request.method == 'POST':
        if not request.form['username'] or not request.form['password'] or not request.form['confirm_password'] or not request.form['email']:
            flash('Please enter all the fields accordingly.', 'error')
        elif not request.form['password'] == request.form['confirm_password']:
            message = 'Passwords don\'t match. Please enter again.'
            flash(message, 'error')
        else:
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            admin = Admin(username, email)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            flash('New account has been created.')
            return redirect(url_for('adminQueue'))

    return render_template('create_account.html')


@app.route('/admin/password', methods=['POST', 'GET'])
@login_required
def changePassword():
    if request.method == 'POST':
        if not request.form['cur_pass'] or not request.form['new_pass'] or not request.form['confirm_pass']:
            flash('Please enter all the fields accordingly.', 'error')
        else:
            admin = current_user
            if not admin.check_password(request.form['cur_pass']):
                flash('Wrong password, please enter again.', 'error')
            elif not request.form['new_pass'] == request.form['confirm_pass']:
                flash('New passwords not matching, please enter again.', 'error')
            else:
                admin.set_password(request.form['confirm_pass'])
                db.session.add(admin)
                db.session.commit()
                flash('Password has been successfully updated.')
                return redirect(url_for('adminQueue'))

    return render_template('change_password.html')


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

