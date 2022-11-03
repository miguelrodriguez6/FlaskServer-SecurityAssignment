from http import HTTPStatus
from flask import Flask, abort, request, send_from_directory, make_response, render_template, session
import apsw
from app import app
from apsw import Error
from json import dumps, loads
import html
from app import conn
from datetime import datetime

@app.route('/send', methods=['POST','GET'])
def send():
    try:
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
        if replyid!='':
            replyid = int(html.escape(replyid))
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
