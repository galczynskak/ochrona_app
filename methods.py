import sqlite3
import re
import uuid
import os
import jwt
import passlib.hash
from flask import jsonify, make_response, g

from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

JWT_SECRET = os.getenv("JWP_SECRET")
JWT_EXP_TIME = os.getenv("JWT_EXP_TIME")


def register_user_session(login, token, current_host):
    token_hash = passlib.hash.apr_md5_crypt.hash(token)
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('insert into sessions (user_name, session_token_hash) values (?,?)', [login, token_hash])
            cursor.execute('select * from users where login = ?', [login])
            user = cursor.fetchone()
            if current_host not in user[5]:
                new_hosts = user[5] + f'{current_host};'
                tran.cursor().execute('update users set bound_hosts=(?) where login = ?', [new_hosts, login])
            tran.commit()
    except Exception as e:
        print(e)
        raise e


def release_session(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('delete from sessions where user_name = ?', ['login'])
            tran.commit()
    except Exception as e:
        pass


def check_login_available(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.execute('select * from users where login = ?', [login])
            if cursor.fetchone() is None:
                return True
            else:
                return False
    except Exception as e:
        return False


def check_email_available(email):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.execute('select * from users where email = ?', [email])
            if cursor.fetchone() is None:
                return True
            else:
                return False
    except Exception as e:
        return False


def check_password_strength(password):
    pattern1 = re.compile('[A-Z]+')
    pattern2 = re.compile('[a-z]+')
    pattern3 = re.compile('[0-9]+')
    pattern4 = re.compile('[!@#$%^&*()]+')
    strength = (bool(re.search(pattern1, password)) and
                bool(re.search(pattern2, password)) and
                bool(re.search(pattern3, password)) and
                bool(re.search(pattern4, password)) and
                len(password) > 8)
    return strength


def register_user(email, login, password, host):
    enc = generate_password_hash(password=password, method='pbkdf2:sha256:100000')
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('insert into users (email, login, password_hash, master_password, bound_hosts) values (?,?,?,?,?)',
                           [email, login, enc, str(uuid.uuid4()), f'{host};'])
            tran.commit()
    except Exception as e:
        print(e)
        raise e


def parse_token(token):
    decoded = decode_jwt_data(token)
    if decoded != {}:
        if decoded['exp'] > int((datetime.now().timestamp())):
            g.user = decoded
        else:
            release_session(decoded['login'])
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
            'exp': int((datetime.now() + timedelta(sencods=int(JWT_EXP_TIME))).timestamp())
        }, JWT_SECRET, algorithm='HS256')
        return token
    except Exception as e:
        print(e)
        return None


def check_session_registered(token, login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from sessions where session_token_hash = ?', [token])
            current_user = cursor.fetchone()
            return current_user is not None and current_user[1] == login
    except Exception as e:
        raise e


def verify_user(login, password):
    try:
        g.db = sqlite3.connect('database.db')
        cursor = g.db.execute('select * from users where login = ?', [login])
        current_user = cursor.fetchone()
        return check_password_hash(current_user[3], password)
    except Exception as e:
        return False


def get_master_password(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from users where login = ?', [login])
            current_user = cursor.fetchone()
            return current_user[4]
    except Exception as e:
        raise e