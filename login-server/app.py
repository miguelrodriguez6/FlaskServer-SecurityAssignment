from http import HTTPStatus
from flask import Flask, abort, request, send_from_directory, make_response, render_template
from werkzeug.datastructures import WWWAuthenticate
import flask
from login_form import LoginForm
from json import dumps, loads
from base64 import b64decode
import sys
import apsw
from apsw import Error
from pygments import highlight
from pygments.lexers import SqlLexer
from pygments.formatters import HtmlFormatter
from pygments.filters import NameHighlightFilter, KeywordCaseFilter
from pygments import token;
from threading import local
from markupsafe import escape
import bcrypt
import hashlib
from flask_login import logout_user
from os import urandom
import time
from datetime import datetime
from flask import session
import html



tls = local()
inject = "'; insert into messages (sender,message) values ('foo', 'bar');select '"
cssData = HtmlFormatter(nowrap=True).get_style_defs('.highlight')
conn = None

# Set up app
app = Flask(__name__)


# Declaring size
size = 5
# Using os.urandom() method
# The secret key enables storing encrypted session data in a cookie (make a secure random key for this!)
app.secret_key = urandom(size)



# Add a login manager to the app
import flask_login
from flask_login import login_required, login_user
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

#import messages

# Class to store user info
# UserMixin provides us with an `id` field and the necessary
# methods (`is_authenticated`, `is_active`, `is_anonymous` and `get_id()`)
class User(flask_login.UserMixin):
    pass



# This method is called whenever the login manager needs to get
# the User object for a given user id
@login_manager.user_loader
def user_loader(user_id):

    session['username'] = user_id
    #Get the user's email which email=user_id, it should be only one
    stmt = f"select email from users where email=?"
    c = conn.execute(stmt, (user_id,))
    rows = c.fetchall()
    extractedemail = dumps(rows) #only one row
    c.close()

    if f'[["{user_id}"]]'!=extractedemail:
        return

    # For a real app, we would load the User from a database or something
    user = User()
    user.id = user_id
    stmt = f"UPDATE users SET loged=1 WHERE email=?"
    c = conn.execute(stmt, (user_id,))
    return user


# This method is called to get a User object based on a request,
# for example, if using an api key or authentication token rather
# than getting the user name the standard way (from the session cookie)
@login_manager.request_loader
def request_loader(request):
    # Even though this HTTP header is primarily used for *authentication*
    # rather than *authorization*, it's still called "Authorization".
    auth = request.headers.get('Authorization')

    # If there is not Authorization header, do nothing, and the login
    # manager will deal with it (i.e., by redirecting to a login page)
    if not auth:
        return

    (auth_scheme, auth_params) = auth.split(maxsplit=1)
    auth_scheme = auth_scheme.casefold()
    if auth_scheme == 'basic':  # Basic auth has username:password in base64
        (uid,passwd) = b64decode(auth_params.encode(errors='ignore')).decode(errors='ignore').split(':', maxsplit=1)
        print(f'Basic auth: {uid}:{passwd}')
        u = users.get(uid)
        if u: # and check_password(u.password, passwd):
            return user_loader(uid)
    elif auth_scheme == 'bearer': # Bearer auth contains an access token;
        # an 'access token' is a unique string that both identifies
        # and authenticates a user, so no username is provided (unless
        # you encode it in the token – see JWT (JSON Web Token), which
        # encodes credentials and (possibly) authorization info)
        print(f'Bearer auth: {auth_params}')
        for uid in users:
            if users[uid].get('token') == auth_params:
                return user_loader(uid)
    # For other authentication schemes, see
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication

    # If we failed to find a valid Authorized header or valid credentials, fail
    # with "401 Unauthorized" and a list of valid authentication schemes
    # (The presence of the Authorized header probably means we're talking to
    # a program and not a user in a browser, so we should send a proper
    # error message rather than redirect to the login page.)
    # (If an authenticated user doesn't have authorization to view a page,
    # Flask will send a "403 Forbidden" response, so think of
    # "Unauthorized" as "Unauthenticated" and "Forbidden" as "Unauthorized")
    abort(HTTPStatus.UNAUTHORIZED, www_authenticate = WWWAuthenticate('Basic realm=inf226, Bearer'))

def pygmentize(text):
    if not hasattr(tls, 'formatter'):
        tls.formatter = HtmlFormatter(nowrap = True)
    if not hasattr(tls, 'lexer'):
        tls.lexer = SqlLexer()
        tls.lexer.add_filter(NameHighlightFilter(names=['GLOB'], tokentype=token.Keyword))
        tls.lexer.add_filter(NameHighlightFilter(names=['text'], tokentype=token.Name))
        tls.lexer.add_filter(KeywordCaseFilter(case='upper'))
    return f'<span class="highlight">{highlight(text, tls.lexer, tls.formatter)}</span>'

@app.route('/favicon.ico')
def favicon_ico():
    return send_from_directory(app.root_path, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/favicon.png')
def favicon_png():
    return send_from_directory(app.root_path, 'favicon.png', mimetype='image/png')


@app.route('/')
@app.route('/index.html')
@login_required
def index_html():
    return send_from_directory(app.root_path,
                        'index.html', mimetype='text/html')

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
            #email = form.username.data
            #password = form.password.data

            if not email or not password:
                print(f'ERROR: missing email or password')
                return render_template('./register.html')
            stmt = f"INSERT INTO users (email, password, loged) values (?, ?, ?);"
            if password_check(password)==False:
                return f"Password is not secure"
            #result = f"Query: {pygmentize(stmt)}\n"
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


#SEARCH AND SEND
@app.route('/send', methods=['POST','GET'])
def send():
    try:
        #sender = request.args.get('sender') or request.form.get('sender')
        sender = session['username']
        recipient = request.args.get('recipient') or request.form.get('recipient')
        if recipient!=None:
            recipient = html.escape(recipient)

        #Check that the recipient exists
        try:
            c = conn.execute('SELECT email from users;')
            rows = c.fetchall()
            validRecipient = False
            for row in rows:
                if recipient==row[0] or recipient=='everyone':
                    validRecipient = True
            c.close()
            if validRecipient==False:
                return "This recipient does not exist"
        except Error as e:
            return (f'ERROR: {e}', 500)

        message = html.escape(request.args.get('message') or request.args.get('message'))
        if message!=None:
            message = html.escape(message)

        now = datetime.now()
        time_var = now.strftime("%d/%m/%Y %H:%M:%S")
        replyid = request.args.get('reply') or request.args.get('reply')
        print(type(replyid))
        if replyid!='':
            replyid = int(replyid)
        else:
            replyid=(-1)


        if not sender or not message:
            return f'ERROR: missing one or more parameters'
        stmt = f"INSERT INTO messages (sender, recipient, timestamp, replyid, message) values (?, ?, ?, ?, ?);"
        conn.execute(stmt, (sender, recipient, time_var, replyid, message))
        return f'Message [{message}] sent to {recipient} at {time_var} replying to MessageID {replyid}.'
    except Error as e:
        return f"Couldn't send the message. ERROR: {e}"


@app.get('/search')
def search():
    query = html.escape(request.args.get('q') or request.form.get('q') or '*')

    if query=='sender':
        stmt = f"SELECT * FROM messages WHERE sender GLOB ? ORDER BY id DESC"
    elif query=='recipient':
        stmt = f"SELECT * FROM messages WHERE recipient GLOB ? OR recipient GLOB 'everyone' ORDER BY id DESC"
    elif query=='*':
        stmt = f"SELECT * FROM messages WHERE (recipient GLOB ? OR recipient GLOB 'everyone' OR sender GLOB ?) ORDER BY id DESC"
    elif query.isdigit():
        stmt = f"SELECT * FROM messages where id GLOB ? AND (recipient GLOB ? OR recipient GLOB 'everyone' OR sender GLOB ?)"
    else:
        stmt = f"SELECT * FROM messages WHERE message GLOB ? AND (recipient GLOB ? OR recipient GLOB 'everyone' OR sender GLOB ?) ORDER BY id DESC"


    try:

        if query=='sender':
            c = conn.execute(stmt, (session['username'],))
        elif query=='recipient':
            c = conn.execute(stmt, (session['username'],))
        elif query=='*':
            c = conn.execute(stmt, (session['username'],session['username']))
        elif query.isdigit():
            c = conn.execute(stmt, (query, session['username'], session['username']))
        else:
            c = conn.execute(stmt, (query, session['username'], session['username']))

        rows = c.fetchall()
        result = 'Messages:\n'
        if len(rows)==0:
            return f"No messages found."

        for row in rows:
            result = f'{result}      MessageID {dumps(row[0])} from {dumps(row[1])} to {dumps(row[2])} at {dumps(row[3])} replying to MessageID {dumps(row[4])}. Content: {dumps(row[5])}\n'
        c.close()
        return result
    except Error as e:
        return (f'Not possible to search. ERROR: {e}', 500)


@app.get('/announcements')
def announcements():
    try:
        stmt = f"SELECT author,text FROM announcements;"
        c = conn.execute(stmt)
        anns = []
        for row in c:
            anns.append({'sender':escape(row[0]), 'message':escape(row[1])})
        return {'data':anns}
    except Error as e:
        return {'error': f'{e}'}

@app.get('/coffee/')
def nocoffee():
    abort(418)

@app.route('/coffee/', methods=['POST','PUT'])
def gotcoffee():
    return "Thanks!"

@app.get('/highlight.css')
def highlightStyle():
    resp = make_response(cssData)
    resp.content_type = 'text/css'
    return resp

try:
    conn = apsw.Connection('./tiny.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id integer PRIMARY KEY,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        replyid integer,
        message TEXT NOT NULL);''')
    c.execute('''CREATE TABLE IF NOT EXISTS announcements (
        id integer PRIMARY KEY,
        author TEXT NOT NULL,
        text TEXT NOT NULL);''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id integer PRIMARY KEY,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        loged INTEGER,
        CONSTRAINT email_unique UNIQUE (email));''')

except Error as e:
    print(e)
    sys.exit(1)
