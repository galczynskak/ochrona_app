import sqlite3
import re
import uuid

from werkzeug.security import generate_password_hash


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
                len(password) > 7)
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
        raise e