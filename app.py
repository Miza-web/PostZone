from sqlite3.dbapi2 import Cursor, connect
from flask import Flask, config, render_template, request, g, session, url_for, redirect
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect
app = Flask(__name__)
app.config['SECRET_KEY'] = 'GvFVhSsCBsGu4ZPRhvDxzqZzDyiMT3oz'

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

    return render_template('profile.html', user = user, user_posts = user_posts)

@app.route("/index")
def posts():
   if not session.get('username'):
    return redirect(url_for('home'))
   posts=query_db('SELECT * FROM posts ORDER BY created_at DESC')
   user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
   return render_template('index.html', posts = posts, user = user)


@app.route("/register", methods=['post'])
def register():
    form = request.form
    username = form.get('user')
    password = form.get('pass')
    email = form.get('email')
    hashed_password = generate_password_hash(password)

    insert_db('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))

    return render_template('welcome.html', message='User Registered', type='success')

@app.route("/news")
def news():
    if not session.get('username'):
        return redirect(url_for('home'))
    return render_template('news.html')

@app.route("/account_settings")
def account_settings():
    if not session.get('username'):
        return redirect(url_for('home'))
    user=query_db('SELECT * FROM users WHERE username = ?', [session['username']], True)
    return render_template("account_settings.html", user = user)

@app.route("/post_submit", methods=['post'])
def post_submit():
    form = request.form
    title = form.get('title')
    post_content = form.get('content')
    user = session['username']  
    keywords = ['vaccine', 'hoax', 'covid']

    if re.compile('|'.join(keywords),re.IGNORECASE).search(post_content):
        return redirect(url_for('posts'))
    else:
        insert_db('INSERT INTO posts (title, content, by_user) VALUES (?, ?, ?)', (title, post_content, user))
        return redirect(url_for('posts'))

@app.route("/account_update", methods=['post'])
def account_update():
    form = request.form
    username = form.get('user')
    user = session['username']
    password = form.get('pass')
    email = form.get('email')
    hashed_password = generate_password_hash(password)

    insert_db('UPDATE users SET username = ?, password  = ?, email = ? WHERE username = ?', (username, hashed_password, email, user))

    session.pop('username')
    return redirect(url_for('home')) 

@app.route("/admin")
def admin():
    if not session.get('username'):
        return redirect(url_for('home'))
    return render_template("admin.html")

@app.route("/admin/user")
def admin_user():
    if not session.get('username'):
        return redirect(url_for('home'))
    user_table=query_db('SELECT * FROM users')
    return render_template("user_database.html", user_table = user_table)

@app.route("/admin/posts")
def admin_posts():
    if not session.get('username'):
        return redirect(url_for('home'))
    post_table=query_db('SELECT * FROM posts ORDER BY created_at DESC')
    return render_template("post_database.html", post_table = post_table)

@app.route("/admin/edit_user")
def edit_user():
    user_entry=query_db('SELECT FROM users WHERE username = user.username')
    return redirect(url_for('user_database.html'), user_entry = user_entry)

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
