import os

from dotenv import load_dotenv
from flask import Flask, render_template, g
import sqlite3

load_dotenv()
JWT_SECRET = os.getenv("JWP_SECRET")
JWT_EXP_TIME = os.getenv("JWT_EXP_TIME")

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.secret_key = os.getenv("SECRET_KEY")


def init_db() -> None:
    def get_db():
        db = getattr(g, '_database', None)
        if db is None:
            try:
                db = g._database = sqlite3.connect('database.db')
            except Exception:
                print('Could not connect to database')
        return db

    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.route('/')
def home():
    return render_template("home.html")


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/register')
def register():
    return render_template("register.html")


@app.route('/add_note')
def add_note():
    return render_template("add_note.html")

@app.route('/notes/<type>')
def show_notes(type):
    return render_template("notes.html", type=type)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)