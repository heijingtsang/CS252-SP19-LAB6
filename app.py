import datetime
from flask import Flask, render_template, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_login import current_user, login_user, login_manager, logout_user, login_required


app = Flask(__name__)
Talisman(app)
app.secret_key = "CS252 Spring 2019 Lab 6"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cs252sp19lab6.db'
db = SQLAlchemy(app)
login = login_manager(app)
login.login_view = 'login'



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
