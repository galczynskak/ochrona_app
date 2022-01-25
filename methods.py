import sqlite3, os, jwt

from flask import g
from dotenv import load_dotenv
from datetime import datetime, timedelta

from logout import release_session

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_EXP_TIME = os.getenv("JWT_EXP_TIME")


def parse_token(token):
    decoded = decode_jwt_data(token)
    if decoded != {}:
        if decoded['exp'] > int((datetime.now().timestamp())):
            g.user = decoded
        else:
            release_session(decoded['login'])
            g.user = {}
    else:
        g.user = {}
    return g.user, token


def decode_jwt_data(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except Exception as e:
        return {}


def encode_jwt_data(login, master_password):
    try:
        token = jwt.encode({
            'login': login,
            'master_password': master_password,
            'last_login': datetime.now().isoformat(),
            'exp': int((datetime.now() + timedelta(seconds=int(JWT_EXP_TIME))).timestamp())
        }, JWT_SECRET, algorithm='HS256')
        return token
    except Exception as e:
        return None


def check_session_registered(token, login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from sessions where session_token_hash = ?', [token])
            current_user = cursor.fetchone()
            return current_user is not None and current_user[2] == login
    except Exception as e:
        raise e
