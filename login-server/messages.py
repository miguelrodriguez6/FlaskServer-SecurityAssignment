from http import HTTPStatus
from flask import Flask, abort, request, send_from_directory, make_response, render_template, session
import apsw
from app import app
from apsw import Error
from json import dumps, loads



@app.route('/send', methods=['POST','GET'])
def send():
    try:
        #sender = request.args.get('sender') or request.form.get('sender')
        sender = session['username']
        recipient = request.args.get('recipient') or request.form.get('recipient')

        #Check that the recipient exists
        try:
            c = conn.execute('SELECT email from users;')
            rows = c.fetchall()
            validRecipient = False
            for row in rows:
                if recipient==row[0]:
                    print('Valid recipient')
                    validRecipient = True
            c.close()
            if validRecipient==False:
                print("Recipient doesn't exists")
                return flask.redirect(flask.url_for('index_html'))
        except Error as e:
            return (f'ERROR: {e}', 500)

        message = request.args.get('message') or request.args.get('message')

        time_var = str(time.time());
        now = datetime.now()
        print(now)
        replyid = 0;

        print(recipient)

        if not sender or not message:
            return f'ERROR: missing sender or message'
        stmt = f"INSERT INTO messages (sender, recipient, timestamp, replyid, message) values (?, ?, ?, ?, ?);"
        conn.execute(stmt, (sender, recipient, time_var, replyid, message))
        return f'Message sent to {recipient}.'
    except Error as e:
        return f"Couldn't send the message. ERROR: {e}"


@app.get('/search')
def search():
    query = request.args.get('q') or request.form.get('q') or '*'
    see = ('sender', 'recipient')
    stmt = f"SELECT * FROM messages WHERE message GLOB ? AND {see[1]} GLOB ? ORDER BY id DESC"
    #result = f"Query: {pygmentize(stmt)}\n"

    try:
        c = conn.execute(stmt, (query, session['username']))
        rows = c.fetchall()
        result = 'Result:\n'
        for row in rows:
            result = f'{result}    {dumps(row)}\n'
        c.close()
        return result
    except Error as e:
        return (f'{result}ERROR: {e}', 500)
