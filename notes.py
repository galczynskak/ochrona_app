import sqlite3
import base64
import hashlib

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def get_no_created(user):
    login = user['login']
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select count(*) from notes where owner_login = ?', [login])
            no_created = cursor.fetchone()
            return no_created
    except Exception as e:
        raise e


def get_no_shared(user):
    login = user['login']
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute("select count(*) from notes where (owner_login != ?) and "
                           "((allowed_viewers = 'all') or (allowed_viewers like ?))", [login, ('%'+login+'%')])
            no_created = cursor.fetchone()
            return no_created
    except Exception as e:
        raise e


def get_user_id(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from users where login = ?', [login])
            current_user = cursor.fetchone()
            return current_user[0]
    except Exception as e:
        raise e


def insert_note(user, title, content, privacy, password):
    try:
        login = user['login']

        if privacy == 'private':
            allowed_viewers = login
        elif privacy == 'public':
            allowed_viewers = 'all'
        else:
            allowed_viewers = str(login + ', ' + privacy)

        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('insert into notes (owner_login, title, content, allowed_viewers, note_password) values (?, ?, ?, ?, ?)', [login, title, content, allowed_viewers, password])
            tran.commit()
    except Exception as e:
        raise e


def get_my_notes(user):
    login = user['login']
    user_id = get_user_id(login)
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select * from notes where owner_login == ?', [login])
            notes = cursor.fetchall()
            return notes
    except Exception as e:
        raise e


def get_shared_notes(user):
    login = user['login']
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute("select * from notes where (owner_login != ?) and "
                           "((allowed_viewers = 'all') or (allowed_viewers like ?))", [login, ('%'+login+'%')])
            notes = cursor.fetchall()
            return notes
    except Exception as e:
        raise e


def get_note_content(note_id, password):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('select content from notes where id = ? and note_password = ?', [note_id, password])
            note = cursor.fetchone()
            return note
    except Exception as e:
        raise e