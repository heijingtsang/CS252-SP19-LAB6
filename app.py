import datetime
from flask import Flask, render_template, redirect, flash, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_login import current_user, login_user, login_manager, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
Talisman(app)
app.secret_key = "CS252 Spring 2019 Lab 6"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cs252sp19lab6.db'
db = SQLAlchemy(app)
login_manager = login_manager()
login_manager.init_app(app)


class Admin(db.Model):
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(64), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)





@app.route('/')
def home():
    return render_template('home.html')


@app.route('/wall')
def wall():
    return render_template('wall.html')


@app.route('/add', methods=['POST', 'GET'])
def add():
    return render_template('add.html')


@app.route('/report', methods=['POST', 'GET'])
def report():
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

            if user is not None and user.check_password(request.form['password']):
                login_user(user)
                return redirect(url_for('adminQueue'))
            else:
                flash('Invalid login.', 'error')

    return render_template('admin_login.html')


@app.route('/admin/reported', methods=['POST', 'GET'])
@login_required
def adminReported():
    return render_template('admin_reported.html')


@app.route('/admin/queue', methods=['POST', 'GET'])
@login_required
def adminQueue():
    return render_template('admin_queue.html')


@app.route('/admin/logout')
@login_required
def adminLogout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run()
