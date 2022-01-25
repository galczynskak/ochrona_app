import sqlite3
from werkzeug.security import check_password_hash
from flask import g


def register_user_session(login, token, current_host): #TODO hash token with salt
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from users where login = ?', [login])
            user = cursor.fetchone()
            user_id = user[0]
            cursor.execute('insert into sessions (user_id, user_name, session_token_hash) values (?, ?,?)', [user_id, login, token])
            if current_host not in user[5]:
                new_hosts = user[5] + f'{current_host};'
                tran.cursor().execute('update users set bound_hosts=(?) where login = ?', [new_hosts, login])
            tran.commit()
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