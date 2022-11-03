INF226 Compulsory Assignment 2 (Fall 2022),     Miguel Rodríguez Martínez

 -> Part 2A – Implementation
Initially we had a very simple and insecure server. We needed to modify it and convert it to a secure server. It should be protected from the main attacks (SQL injections, XSS, CSRF, etc).

First of all, we need to take a look to the structure of the code. Everything is mixed is one file. We should implement the different functionalities of the server in different files. This way it's easier to understand how it works and find the part of the programs that we want to see faster. Also the maintenance is going to be less hard as we can restructure or change code without having a rough idea of which and how functionalities are implemented on another part of the code.

We should restructure the functionalities of the server into differents files where the ones that have a relation between them can go together in the same file. For example, in this case we can separate the the search and send functions to another file. Also we may create a new file for the login and registration(new).

/** PROBLEM WHEN THE CODE IS RESTRUCTURED, I COULDN'T SOLVE IT. IT GIVES ME THE FOLLOWING ERROR. I COULDN'T FIND ANY OVERWRITTEN FUNCTION**/
/**Traceback (most recent call last):
  File "messages.py", line 4, in <module>
    from app import app
  File "/home/miguel/Documents/ssec/login-server/app.py", line 405, in <module>
    import messages
  File "/home/miguel/Documents/ssec/login-server/messages.py", line 11, in <module>
    def send():
  File "/home/miguel/.local/lib/python3.8/site-packages/flask/scaffold.py", line 449, in decorator
    self.add_url_rule(rule, endpoint, f, **options)
  File "/home/miguel/.local/lib/python3.8/site-packages/flask/scaffold.py", line 50, in wrapper_func
    return f(self, *args, **kwargs)
  File "/home/miguel/.local/lib/python3.8/site-packages/flask/app.py", line 1358, in add_url_rule
    raise AssertionError(
AssertionError: View function mapping is overwriting an existing endpoint function: send**/
 
 We keep using the same database type(sqlite3). We have 3 tables. A table of messages, a table of announcements and a table of users. The second one is not used and not useful for the project but we didn't delete it.
 
 For each message we stored an id, a sender, a recipient, the time when it was sent, the id of the message to which we are answering and the content of the message.
 For each announcement we stored the id, the author and the content.
 For each user we stored the id, the email (unique), the password and if he/she is loged into the server at the moment.
 
 All the information stored in the database passes through a process of sanitization to avoid for example a message with a XSS attack (in this case using html.escape()).
 
 Now, a simple explanation of how the server works. The first page that appears to us is the login page. Here we can enter the email and password of a registered user(it won't work with user alice or bob). To register an user we have to click on 'Register new user.'. We will be redirect to a registration page. Here we can register an user into the application using an email and a secure password (must contain more than 6 characters, at least one number and an uppercase). We can also go back to the login page clicking on 'Login'. Once we have submitted the form we are redirected to the login page (I recommend to register a few users to send messages between them). Once we have at least one user we can acces to the messaging page. 
 First of all, to log out we can click the link below called 'Log out' and we are going to be redirected again to the login page being the user loged out. There are a few buttons. 
 The button 'Search!' will show us the messages where we are the sender or the recipient and the message is the one written in the box corresponding to 'Search:'. If we put an '*' all the messages are going to be shown. If we click the button 'Show all' all the messages where we are the sender or the recipients are going to be showed.
 We can also search for a message using its id. But to see it we also must be the sender or the recipient. Just put the id number in the 'Search ID:' box and the message is going to be showed if it exists and we have acces to it.
 Lastly, we have the posibility to send new messages to an user. We should specify all the values. In 'To:' box we have to write the email of the recipient or 'everyone' if we want to send the message to all the users. In 'Message:' box we write the content of the message and in 'Replying to:' we need to write the id of the message we are answering to.


 -> Part 2B – Documentation

Write a README.md with:

a brief overview of your design considerations from Part A,
the features of your application,
instructions on how to test/demo it,
technical details on the implementation,
answers to the questions below




Questions


Threat model – who might attack the application? What can an attacker do? What damage could be done (in terms of confidentiality, integrity, availability)? Are there limits to what an attacker can do? Are there limits to what we can sensibly protect against?

What are the main attack vectors for the application?

What should we do (or what have you done) to protect against attacks?

What is the access control model?

How can you know that you security is good enough? (traceability)

