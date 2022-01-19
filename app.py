import os

from dotenv import load_dotenv
from flask import Flask, render_template, g

load_dotenv()
JWT_SECRET = os.getenv("JWP_SECRET")
JWT_EXP_TIME = os.getenv("JWT_EXP_TIME")

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.secret_key = os.getenv("SECRET_KEY")


@app.route('/')
def home():
    return render_template("home.html")


@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/register')
def register():
    return render_template("register.html")


if __name__ == '__main__':
    app.run(debug=True)