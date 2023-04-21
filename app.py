from sqlite3.dbapi2 import Cursor, connect
from flask import Flask, config, jsonify, render_template, request, g, session, url_for, redirect
from flask_mail import Mail, Message
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect
app = Flask(__name__)
app.config['SECRET_KEY'] = 'GvFVhSsCBsGu4ZPRhvDxzqZzDyiMT3oz'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

mail = Mail(app)
DATABASE='database.db'


@app.route("/")
def home():
    return render_template('welcome.html')

@app.route("/login", methods=['post'])
def login():
    form = request.form
    username = form.get('user')
    password = form.get('pass')

    user=query_db('SELECT * FROM users WHERE username = ?', [username], True)

    if user and check_password_hash(user['password'], password):
        session['logged_in'] = True
        session['username'] = username

        return redirect(url_for('posts'))


    return render_template('welcome.html', message='Incorrect Credentials', type='error', user = user)

@app.route("/logout")
def logout():
    session.pop('username')
    return redirect(url_for('home')) 

@app.route("/profile")
def profile():
    if not session.get('username'):
        return redirect(url_for('home'))
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)

    user_posts=query_db('SELECT * FROM posts WHERE by_user = ? ORDER BY created_at DESC', [session['username']])
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM posts WHERE by_user = ?", [session['username']])
    post_count = cursor.fetchone()[0]

    return render_template('profile.html', user = user, user_posts = user_posts, post_count = post_count)

@app.route("/index")
def posts():
   if not session.get('username'):
    return redirect(url_for('home'))
   page = request.args.get('page', 0, int)
   if page == 0:
        offset = 0
   else:
        offset = 5 * page
   reported = request.args.get('reported', 0, int)
   posts=query_db('SELECT * FROM posts ORDER BY created_at DESC LIMIT 5 OFFSET ?', [offset])
   user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
   conn = sqlite3.connect(DATABASE)
   cursor = conn.cursor()
   cursor.execute("SELECT COUNT(*) FROM posts WHERE by_user = ?", [session['username']])
   post_count = cursor.fetchone()[0]
   return render_template('index.html', posts = posts, user = user, post_count = post_count, reported = reported)

@app.route("/load_posts")
def load_posts():
   page = request.args.get('page', 0, int)
   if page == 0:
        offset = 0
   else:
        offset = 5 * page
   posts=query_db('SELECT * FROM posts ORDER BY created_at DESC LIMIT 5 OFFSET ?', [offset])
   html = render_template('posts.html', posts = posts)
   return html



@app.route("/register", methods=['post'])
def register():
    form = request.form
    username = form.get('user')
    password = form.get('pass')
    email = form.get('email')
    hashed_password = generate_password_hash(password)

    insert_db('INSERT INTO users (username, password, email, user_type, blacklisted, whitelisted) VALUES (?, ?, ?, "user", "no", "no")', (username, hashed_password, email))

    return render_template('welcome.html', message='User Registered', type='success')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']

        msg = Message(subject=subject, sender=email, recipients=['your-email@gmail.com'])
        msg.body = f"From: {name} ({email})\n\n{message}"
        mail.send(msg)
        return redirect(url_for('posts'))

    return redirect(url_for('posts'))


@app.route("/account_settings")
def account_settings():
    if not session.get('username'):
        return redirect(url_for('home'))
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    return render_template("account_settings.html", user = user)

covid_pattern = r"(covid|pandemic|coronavirus|virus|5g|face mask|SARS-CoV-2|omicron|delta|alpha).*(hoax|fake|autism|doesn't exist|bioweapon|manmade|engineered|simulation|surveillance|chinese weapon)"
vaccine_pattern = r"(vaccine|pfizer|moderna|novavax).*(autism|fake|hoax|doesn't work|don't work|dna|microchip|kills|miscarriage|fail|infects)"
tests_pattern = r"(lateral flow|antigen|pcr).*(doesn't work|don't work|fake|hoax|false)"
cures_pattern = r"(ivermectin|antibiotics|colloidal silver|garlic|miracle mineral solution|vitamin c|essential oil|quercetin|bleach).*(helps|cures|works|cure|covid|treats|prevents)"


def flag_covid_misinformation(text):
    match = re.search(covid_pattern, text, re.IGNORECASE)
    return match is not None
def flag_vaccine_misinformation(text):
    match = re.search(vaccine_pattern, text, re.IGNORECASE)
    return match is not None
def flag_tests_misinformation(text):
    match = re.search(tests_pattern, text, re.IGNORECASE)
    return match is not None
def flag_cures_misinformation(text):
    match = re.search(cures_pattern, text, re.IGNORECASE)
    return match is not None

@app.route("/post_submit", methods=['post'])
def post_submit():
    post_content = request.form['content']
    user = session['username']  

    list=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)

    if list['whitelisted'] == "yes":
        insert_db('INSERT INTO posts (content, by_user) VALUES (?, ?)', (post_content, user))
        return redirect(url_for('posts'))

    if list['blacklisted'] == "yes":
        if flag_covid_misinformation(post_content):
            insert_db('INSERT INTO posts (content, by_user, flag_covid, blacklisted) VALUES (?, ?, ?, ?)', (post_content, user, "yes", "yes"))
            return redirect(url_for('posts'))
        elif flag_vaccine_misinformation(post_content):
            insert_db('INSERT INTO posts (content, by_user, flag_vaccine, blacklisted) VALUES (?, ?, ?, ?)', (post_content, user, "yes", "yes"))
            return redirect(url_for('posts'))
        elif flag_tests_misinformation(post_content):
            insert_db('INSERT INTO posts (content, by_user, flag_tests, blacklisted) VALUES (?, ?, ?, ?)', (post_content, user, "yes", "yes"))
            return redirect(url_for('posts'))
        elif flag_cures_misinformation(post_content):
            insert_db('INSERT INTO posts (content, by_user, flag_cures, blacklisted) VALUES (?, ?, ?, ?)', (post_content, user, "yes", "yes"))
            return redirect(url_for('posts'))
        else:
            insert_db('INSERT INTO posts (content, by_user, blacklisted) VALUES (?, ?, ?)', (post_content, user, "yes"))
            return redirect(url_for('posts'))


    if flag_covid_misinformation(post_content):
        insert_db('INSERT INTO posts (content, by_user, flag_covid) VALUES (?, ?, ?)', (post_content, user, "yes"))
        return redirect(url_for('posts'))
    elif flag_vaccine_misinformation(post_content):
        insert_db('INSERT INTO posts (content, by_user, flag_vaccine) VALUES (?, ?, ?)', (post_content, user, "yes"))
        return redirect(url_for('posts'))
    elif flag_tests_misinformation(post_content):
        insert_db('INSERT INTO posts (content, by_user, flag_tests) VALUES (?, ?, ?)', (post_content, user, "yes"))
        return redirect(url_for('posts'))
    elif flag_cures_misinformation(post_content):
        insert_db('INSERT INTO posts (content, by_user, flag_cures) VALUES (?, ?, ?)', (post_content, user, "yes"))
        return redirect(url_for('posts'))
    else:
        insert_db('INSERT INTO posts (content, by_user) VALUES (?, ?)', (post_content, user))
        return redirect(url_for('posts'))

@app.route("/password_update", methods=['post'])
def password_update():
    form = request.form
    username = session['username']
    old_pass = form.get('old_pass')
    new_pass = form.get('new_pass')
    c_new_pass = form.get('c_new_pass')
    hashed_password = generate_password_hash(new_pass)
    user=query_db('SELECT * FROM users WHERE username = ?', [username], True)

    if check_password_hash(user['password'], old_pass):
        if c_new_pass == new_pass: 
            insert_db('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
            session.pop('username')
            session.pop('logged_in')
            return render_template('welcome.html', message="Credentials updated.", type='update_success')
        else:
            return render_template('account_settings.html', message='Passwords dont match!', type='newpass_error', user = user)
    else:
        return render_template('account_settings.html', message="Current password doesn't match!", type='oldpass_error', user = user)

@app.route("/email_update", methods=['post'])
def email_update():
    form = request.form
    username = session['username']
    new_email = form.get('new_email')
    c_new_email = form.get('c_new_email')
    user=query_db('SELECT * FROM users WHERE username = ?', [username], True)

    if new_email == c_new_email:
        insert_db('UPDATE users SET email = ? WHERE username = ?', (new_email, username))
        session.pop('username')
        session.pop('logged_in')
        return render_template('welcome.html', message="Credentials updated.", type='update_success')
    else:
        return render_template('account_settings.html', message="E-mails don't match!", type='email_error', user = user)

@app.route("/admin")
def admin():
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    if not user['user_type'] == "admin":
        return redirect(url_for('home'))
    return render_template("admin.html", user = user)

@app.route ("/admin/reports")
def admin_reports():
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    if not user['user_type'] == "admin":
        return redirect(url_for('home'))
    report_table=query_db('SELECT * FROM posts WHERE reported = 1 ORDER BY created_at DESC')
    return render_template("report_database.html", report_table=report_table, user = user)

@app.route("/admin/user")
def admin_user():
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    if not user['user_type'] == "admin":
        return redirect(url_for('home'))
    user_table=query_db('SELECT * FROM users')
    return render_template("user_database.html", user_table = user_table, user = user)

@app.route("/admin/posts")
def admin_posts():
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    if not user['user_type'] == "admin":
        return redirect(url_for('home'))
    post_table=query_db('SELECT * FROM posts ORDER BY created_at DESC')
    return render_template("post_database.html", post_table = post_table, user = user)

@app.route("/admin/edit_user/<int:user_id>", methods=['GET', 'POST'])
def edit_user(user_id):
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    if not user['user_type'] == "admin":
        return redirect(url_for('home'))
    form = request.form
    user_id = request.form.get('user_id')
    username = request.form['username']
    email = request.form['email']
    user_type = request.form['user_type']
    blacklisted = request.form['blacklisted']
    whitelisted = request.form['whitelisted']
    insert_db('UPDATE users SET username=?, email=?, user_type=?, blacklisted=?, whitelisted=? WHERE ID=?', (username, email, user_type, blacklisted, whitelisted, user_id))

    user_table=query_db('SELECT * FROM users')
    return render_template('user_database.html', user = user, user_table = user_table, message='User entry edited', type='edited')

@app.route("/report_review/<int:post_id>", methods=['GET', 'POST'])
def report_review(post_id):
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    if not user['user_type'] == "admin":
        return redirect(url_for('home'))
    form = request.form
    post_id = request.form.get('post_id')
    flag_covid = request.form['flag_covid']
    flag_vaccine = request.form['flag_vaccine']
    flag_tests = request.form['flag_tests']
    flag_cures = request.form['flag_cures']
    insert_db('UPDATE posts SET flag_covid=?, flag_vaccine=?, flag_tests=?, flag_cures=?, reported=?, report_message=? WHERE ID=?', (flag_covid, flag_vaccine, flag_tests, flag_cures, "0", "", post_id))

    report_table=query_db('SELECT * FROM posts WHERE reported = 1 ORDER BY created_at DESC')
    return render_template("report_database.html", report_table=report_table, user = user, message='Report reviewed', type='reviewed')

@app.route("/delete_user", methods=['POST'])
def delete_user():
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    if not user['user_type'] == "admin":
        return redirect(url_for('home'))
    user_id = request.form['user_id']
    insert_db('DELETE FROM users WHERE ID = ?', (user_id,))

    user_table=query_db('SELECT * FROM users')
    return render_template('user_database.html', user = user, user_table = user_table, message='User deleted', type='deleted')

@app.route("/delete_post", methods=['POST'])
def delete_post():
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    if not user['user_type'] == "admin":
        return redirect(url_for('home'))
    post_id = request.form['post_id']
    insert_db('DELETE FROM posts WHERE ID = ?', (post_id,))

    post_table=query_db('SELECT * FROM posts ORDER BY created_at DESC')
    return render_template("post_database.html", post_table = post_table, user = user, message='Post deleted', type='deleted')

@app.route('/user/<username>')
def user_profile(username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user_row = cursor.fetchone()
    conn.close()

    user = {
        'id': user_row[0],
        'username': user_row[1],
        'email': user_row[3],
        'blacklisted': user_row[6],
        'whitelisted': user_row[5]
    } if user_row else None

    user_posts=query_db('SELECT * FROM posts WHERE by_user = ? ORDER BY created_at DESC', (username,))

    return render_template('user_profile.html', user=user, user_posts=user_posts)

@app.route('/post_report/<int:post_ID>', methods=['POST'])
def post_report(post_ID):
    post_ID = request.form['post_ID']
    report_message = request.form['report_message']

    insert_db('UPDATE posts SET reported = ?, report_message = ? WHERE ID = ?', (1, report_message, post_ID))
    return redirect(url_for('posts') + '?reported=1')

@app.route('/discard_report', methods=['POST'])
def discard_report():
    post_ID = request.form['post_ID']
    insert_db('UPDATE posts SET reported=?, report_message=? WHERE ID = ?', (0, "", post_ID))   
    return redirect(url_for('admin_reports'))

@app.route('/search')
def search_posts():
    query = request.args.get('query')
    posts = ('%' + query + '%')
    post_search = query_db('SELECT * FROM posts WHERE content LIKE ? ORDER BY created_at DESC', (posts,))
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    return render_template('post_search.html', post_search=post_search, user = user)


def insert_db(query, args):
    db = g._database = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(query, args)
    db.commit()

    

def query_db(query, args=(), one=False):
    con = g._database = sqlite3.connect(DATABASE)
    con.row_factory = sqlite3.Row
    cur = con.execute(query, args)
    rv = cur.fetchall()
    cur.close()

    return (rv[0] if rv else None) if one else rv
