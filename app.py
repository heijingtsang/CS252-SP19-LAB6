import datetime, os
from flask import Flask, render_template, redirect, flash, url_for, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_login import current_user, login_user, LoginManager, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_ckeditor import CKEditor, upload_success, upload_fail

dirname = os.path.dirname(__file__)

app = Flask(__name__)
#Talisman(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
ckeditor = CKEditor(app)
app.secret_key = "CS252 Spring 2019 Lab 6"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cs252sp19lab6.db'
app.config['CKEDITOR_SERVE_LOCAL'] = True
app.config['CKEDITOR_HEIGHT'] = 400
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
blacklist = []


class Admin(db.Model):
    username = db.Column(db.String(64), nullable=False, primary_key=True, unique=True)
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

    def __init__(self, content, reason, count):
        self.content = content
        self.reason = reason
        self.count = count


db.create_all()

"""
Python user defined functions
"""
## first parameter (String): the text that may contain to-be-censored words
## second parameter (List) : the list of blacklist words
## return (String)         : the text with words censored in asterisks
# def censorByWord(text, blacklist):
#     textWords    = text.split()
#     censoredText = []
#     flag         = False
#
#     # iterate for each word in textWords
#     for word in textWords:
#         # iterate for each censored word in blacklist
#         for blacklistedWord in blacklist:
#             if word == blacklistedWord:
#                 # replace the word with asterisk
#                 censoredText.append("*" * len(word))
#                 flag = True
#                 break
#             else:
#                 # continue to the next iteration
#                 continue
#
#         # if word is not a blacklisted word
#         if flag == False:
#             censoredText.append(word)
#
#         flag = False # set the flag to default
#
#     # return the list censoredText as a string with spaces between each censoredText elements
#     return " ".join(censoredText)


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


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/wall')
def wall():
    secrets = Secrets.query.order_by(Secrets.id.desc()).all()
    return render_template('wall.html', secrets=secrets)


@app.route('/add', methods=['POST', 'GET'])
def add():
    if request.method == 'POST':
        if not request.form.get('ckeditor'):
            flash('Post cannot be empty.', 'error')
        else:
            content = request.form.get('ckeditor')
            '''
            TODO: filtering part, now assume everything is clean.
            '''
            blacklist = getBlacklistWordsFromFile("blacklist.txt")
            content = censorBySubstring(content, blacklist)

            # censorBySubstring is recommended over censorByWords because
            # for example: '<p>fuck' or 'fuck</p>' does not get filtered out
            # UNLESS we are able to get rid of the wrapping tags

            post = Secrets(content=content)
            db.session.add(post)
            db.session.commit()
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
                report = Reported(id=id, reason=reason, count=1)
                db.session.add(report)
                db.session.commit()
                flash('Report has been sent to the administrator.')
                return redirect(url_for('wall'))
            else:
                report = Reported.query.filter_by(id=id).first()
                data = report.data
                data['count'] = data['count'] + 1
                data['reason'] = data['reason'] + '\n' + request.form['reason']
                report.data = data
                db.session.merge(report)
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
    path = dirname + '/bin/'
    return send_from_directory(path, filename)


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('upload')
    extension = f.filename.rsplit('.', 1)[1].lower()

    if extension not in ['jpg', 'gif', 'png', 'jpeg']:
        return upload_fail(message='Image only.')
    bin_path = dirname + '/bin/'
    f.save(os.path.join(bin_path, f.filename))
    url = url_for('uploaded_files', filename=f.filename)

    return upload_success(url=url)


if __name__ == '__main__':
    app.run()