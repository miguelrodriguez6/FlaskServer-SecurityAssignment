INF226 Compulsory Assignment 2 (Fall 2022),     Miguel Rodríguez Martínez

Initially we had a very simple and insecure server. We needed to modify it and convert it to a secure server. It should be protected from the main attacks (SQL injections, XSS, CSRF, etc.).

First, we need to take a look to the structure of the code. Everything is mixed is one file. We should implement the different functionalities of the server in different files. This way it's easier to understand how it works and find the part of the programs that we want to see faster. Also, the maintenance is going to be less hard as we can restructure or change code without having a rough idea of which and how functionalities are implemented on another part of the code.

We should restructure the functionalities of the server into different files where the ones that have a relation between them can go together in the same file. For example, in this case we can separate the search and send functions to another file. Also, we can create a new file for the login and registration (new) and so on with the rest of the functionalities.

------------------------------------------------------------------------------------------------
IMPORTANT

//**BECAUSE OF THE RESTRUCTURE WHEN I COMPILE THE NEW FILES ALONE THEY GIVE ME AN ERROR BUT ALL WORKS CORRECTLY**//
//**IF THERE IS ANY ERROR PLEASE PUT ALL TOGETHER IN app.py AND COMMENT THE FILE IMPORTS AT THE END**//

------------------------------------------------------------------------------------------------

How the application works and how to test it.

We keep using the same database type(sqlite3). We have 3 tables. A table of messages, a table of announcements and a table of users. The second one is not used and not useful for the project, but we didn't delete it.

For each message we stored an id, a sender, a recipient, the time when it was sent, the id of the message to which we are answering and the content of the message. For each announcement we stored the id, the author, and the content. For each user we stored the id, the email (unique), the password and if he/she is logged into the server at that moment.

All the information stored in the database passes through a process of sanitization to avoid for example a message with a XSS attack (in this case using html.escape()).

Now, a simple explanation of how the server works. The first page that appears to us is the login page. Here we can enter the email and password of a registered user (it won't work with user alice or bob). To register a user, we have to click on 'Register new user.'. We will be redirect to a registration page. Here we can register a user into the application using an email and a secure password (must contain more than 6 characters, at least one number and an uppercase). We can also go back to the login page clicking on 'Login'. Once we have submitted the form, we are redirected to the login page (I recommend to register a few users to send messages between them. For example: email: user@user, password: User1000). It should be at least two users created. They will be (email: user@user, password: User1000) and (email: user2@user, password: User2000). If not is very easy to create a new user and use its credentials. Like in the example before. Once we have at least one user we can access to the messaging page. First, to log out we can click the link below called 'Log out' and we are going to be redirected again to the login page being the user logged out. There are a few buttons. The button 'Search!' will show us the messages where we are the sender, or the recipient and the message is the one written in the box corresponding to 'Search:'. If we put an '*' all the messages are going to be shown. The buttons received and sent will also do the same but only show the messages that the user is the recipient or the sender. If we click the button 'Show all' all the messages where we are the sender, or the recipients are going to be showed. We can also search for a message using its id. But to see it we also must be the sender or the recipient. Just put the id number in the 'Search ID:' box and the message is going to be showed if it exists and we have access to it. If the id is not specified all the messages are showed. Lastly, we have the possibility to send new messages to a user. We should specify all the values. In 'To:' box we have to write the email of the recipient or 'everyone' if we want to send the message to all the users. In 'Message:' box we write the content of the message and in 'Replying to:' we need to write the id of the message we are answering to.


--------------------------------------------------------------------------------------

Some important technical details on the implementation:

•	I stablished app.secrect_key as a random value.

•	I converted all the SQL statements to prepared statements to avoid SQL injection (using ?).

•	I used html.escape() function to avoid for example an XSS attack.

•	I used a csrf token to avoid cross site request forgery attack (CSRF).

•	When you try to create a user the program checks if it's secure enough.

•	The password is encrypted when is stored in the database.

•	The column id is unique in the users' table.

------------------------------------------------------------------------------------------------

  o	Threat model – who might attack the application? What can an attacker do? What damage could  be done (in terms of confidentiality, integrity, availability)? Are there limits to what an attacker can do? Are there limits to what we can sensibly protect against?
  
  Threat modeling is a structured approach of identifying and prioritizing potential threats to a system and determining the value that potential mitigations would have in reducing or neutralizing those threats. Attackers are people that normally commits these attacks for money (It could be one or a group of people). They can do many types of attacks. Some examples are steal privacy data, find the way to enter the database of a bank and modify it or even just attack a server and make it not working anymore. 
  
  -> Confidentiality measures protect information from unauthorized access and misuse. Someone could access the data and use it against us.
  
  -> Integrity measures protect information from unauthorized alteration. An unauthorized person can’t change the content stored on the database.
  
  -> Availability. In order for an information system to be useful it must be available to authorized users. Availability measures protect timely and uninterrupted access to the system.
  
The truth is that we don't know the limits of what an attacker can do. Over the years new ways of attacks are appearing so we are never going to know how much an attacker can and will do. We just should be worried about that and try the best we can to protect our system of external attacks. The limits of our protections are in the limits of our knowledge about how an attacker can attack the system.

------------------------------------------------------------------------------------------------

  o	What are the main attack vectors for the application? 
  
Compromised Credentials:
-	Usernames and password are the most common type of access credential and can give the unfettered access.

Weak Credentials:
-	Weak passwords and reused passwords mean one data breach can result in many more. We should have secure passwords in our application and use a password manager. 

Insider Threats:
-	Disgruntled employees or malicious insiders can expose private information or provide information about vulnerabilities.

Missing or Poor Encryption:
-	Missing or poor encryption for data at rest can mean that sensitive data or credentials are exposed in the event of a data breach or data leak.

Ransomware:
-	Ransomware is a form of extortion where data is deleted or encrypted unless a ransom is paid.

Phishing:
-	Phishing attacks are social engineering attacks where the target is contacted by email, telephone, or text message by someone who is posing to be a legitimate colleague or institution to trick them into providing sensitive data, credentials, or personally identifiable information.

Vulnerabilities:
-	New security vulnerabilities are added to the CVE every day and zero-day vulnerabilities are found just as often. If a developer has not released a patch for a zero-day vulnerability before an attack can exploit it, it can be hard to prevent zero-day attacks.

Brute Force:
-	Brute force attacks are based on trial and error. Attackers may continuously try to gain access to your organization until one attack works.

Distributed Denial of Service:
-	DDoS attacks are cyber-attacks against networked resources like data centers, servers, websites, or web applications and can limit the availability of a computer system.

SQL Injections:
-	Many of the servers that store sensitive data use SQL to manage the data in their database. An SQL injection uses malicious SQL to get the server to expose information it otherwise wouldn't.

Trojans:
-	Trojan horses are malware that misleads users by pretending to be a legitimate program and are often spread via infected email attachments or fake malicious software.

Cross-Site Scripting (XSS):
-	XSS attacks involve injecting malicious code into a website but the website itself is not being attacked, rather it aims to impact the website's visitors. A common way attackers can deploy cross-site scripting attacks is by injecting malicious code into a comment.

Session Hijacking:
-	When you log into a service, it generally provides your computer with a session key or cookie, so you don't need to log in again. This cookie can be hijacked by an attacker who uses it to gain access to sensitive information.

Man-in-the-Middle Attacks:
-	Public Wi-Fi networks can be exploited to perform man-in-the-middle attacks and intercept traffic that was supposed to go elsewhere.

Information from: https://www.upguard.com/blog/attack-vector#:~:text=The%20most%20common%20attack%20vectors,text%20messages%2C%20and%20social%20engineering.

------------------------------------------------------------------------------------------------

  o	What should we do (or what have you done) to protect against attacks?

I concentrated my efforts above all to protect the application from 3 attacks. These are SQL Injections, Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF). We must also do this on top of a secure design of the application beforehand.

To avoid the SQL Injections, we should create prepared statements. Here we can see an example:
-	cursor = conn.execute('SELECT * FROM people WHERE firstName = ?', (name,))

To avoid Cross-Site Scripting (XSS), I implemented a input sanitization using the escape function from html library (html.escape(parameter)). The return of this function is a string of ascii character script from html, so we are not going to insert for example JavaScript code to our application.

Last, to avoid Cross-Site Request Forgery I’m using a csrf token that allow my application to distinguish between legitimate and forged HTTP requests.

------------------------------------------------------------------------------------------------

  o	What is the access control model?

The access control model enables you to control the ability of a process to access securable objects or to perform various system administration tasks.
There are two basic parts of the access control model. Access tokens, which contain information about a logged-on user. Security descriptors, which contain the security information that protects a securable object.

When a user logs on, the system authenticates the user's account name and password. If the logon is successful, the system creates an access token. Every process executed on behalf of this user will have a copy of this access token. The access token contains security identifiers that identify the user's account and any group accounts to which the user belongs. The token also contains a list of the privileges held by the user or the user's groups. The system uses this token to identify the associated user when a process tries to access a securable object or perform a system administration task that requires privileges.

When a securable object is created, the system assigns it a security descriptor that contains security information specified by its creator, or default security information if none is specified. Applications can use functions to retrieve and set the security information for an existing object.

Information from: https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-model 

---------------------------------------------------------------------------

  o	How can you know that your security is good enough? (traceability)

Traceability in software engineering is the ability to trace work items across the development lifecycle. It’s used to keep track of what’s going on in the development lifecycle — and show what’s happened. Achieving regulatory compliance is a common purpose for traceability in software engineering.

Maybe we will never say for sure that our security is good enough. We should make as sure as we can. If we try to have a good traceability we could see where we are having risk and try to solve the problem. Also, we can use some software that will try to crash our application.


