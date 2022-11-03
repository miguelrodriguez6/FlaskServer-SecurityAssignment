from http import HTTPStatus
from flask import Flask, abort, request, send_from_directory, make_response, render_template, session
import apsw
from app import app
from apsw import Error
from json import dumps, loads
import html
from app import conn, user_loader
from datetime import datetime
import flask_login
from flask_login import login_required, login_user
from flask_login import logout_user
from login_form import LoginForm
from markupsafe import escape
import bcrypt
import hashlib
import flask


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.is_submitted():
        print(f'Received form: {"invalid" if not form.validate() else "valid"} {form.form_errors} {form.errors}')
        print(request.form)
    if form.validate_on_submit():
        # TODO: we must check the username and password
        username = html.escape(form.username.data)
        password = html.escape(form.password.data)

        salt = "5gz"
        # Adding salt at the last of the password
        dataBase_password = password+salt
        # Encoding the password
        hashed = hashlib.md5(dataBase_password.encode())
        hexhashed = hashed.hexdigest()

        stmt = f"select password from users where email=? AND password=?"
        c = conn.execute(stmt, (username, hexhashed))
        rows = c.fetchall()
        c.close()

        if len(rows)>0:
            #Check that the password is correct
            if hexhashed==rows[0][0]:

                user = user_loader(username)

                # automatically sets logged in session cookie
                login_user(user)

                flask.flash('Logged in successfully.')

                next = flask.request.args.get('next')

                # is_safe_url should check if the url is safe for redirects.
                # See http://flask.pocoo.org/snippets/62/ for an example.
                if False and not is_safe_url(next):
                    return flask.abort(400)

                return flask.redirect(next or flask.url_for('index_html') or flask.url_for('index'))
        print('Incorrect password')
    return render_template('./login.html', form=form)

@app.route('/logout')
@login_required
def log_out():
    logout_user()
    stmt = f"UPDATE users SET loged=0 WHERE email=?"
    c = conn.execute(stmt, (session['username'],))
    return flask.redirect(flask.url_for('login'))

def password_check(passwd):
    val = True
    if len(passwd) < 6:
        print('length should be at least 6')
        val = False
    if len(passwd) > 20:
        print('length should be not be greater than 8')
        val = False
    if not any(char.isdigit() for char in passwd):
        print('Password should have at least one numeral')
        val = False
    if not any(char.isupper() for char in passwd):
        print('Password should have at least one uppercase letter')
        val = False
    if not any(char.islower() for char in passwd):
        print('Password should have at least one lowercase letter')
        val = False
    return val

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email=html.escape(request.form.get('email'))
            password=html.escape(request.form.get('password'))

            if not email or not password:
                print(f'ERROR: missing email or password')
                return render_template('./register.html')
            stmt = f"INSERT INTO users (email, password, loged) values (?, ?, ?);"
            if password_check(password)==False:
                return f"Password is not secure"
            # adding 5gz as password
            salt = "5gz"
            # Adding salt at the last of the password
            dataBase_password = password+salt
            # Encoding the password
            hashed = hashlib.md5(dataBase_password.encode())
            try:
                conn.execute(stmt, (email, hashed.hexdigest(), 0))
            except Error as e:
                print('Not successfully registration')
                return render_template('./register.html')

            flask.flash('Successfully registration.')
            print('Registered')
            next = flask.request.args.get('next')
            # is_safe_url should check if the url is safe for redirects.
            # See http://flask.pocoo.org/snippets/62/ for an example.
            if False and not is_safe_url(next):
                return flask.abort(400)

            return flask.redirect(next or flask.url_for('login'))
        except Error as e:
            return f'Not successfully registrated. ERROR: {e}'

    return render_template('./register.html')
