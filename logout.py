import sqlite3


def release_session(login):
    try:
        with sqlite3.connect('database.db') as tran:
            cursor = tran.cursor()
            cursor.execute('delete from sessions where user_name = ?', [login])
            tran.commit()
    except Exception as e:
        pass

