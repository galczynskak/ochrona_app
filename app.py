from flask import Flask, render_template, redirect, request, make_response, jsonify
from time import sleep
import ssl
from OpenSSL import SSL

from methods import *
from notes import *
from login import *
from register import *
from logout import *

load_dotenv()
app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = True
app.secret_key = os.getenv("SECRET_KEY")

# context = SSL.Context(SSL.TLSv1_2_METHOD)
# context.use_privatekey_file('ochrona.key')
# context.use_certificate_file('ochrona.crt')
# context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# context.load_cert_chain('ochrona.crt', 'ochrona.key')


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


@app.before_request
def check_auth():
    try:
        token = request.headers['Cookie']
        token = token.replace('token=', '')
    except Exception:
        token = ''
    g.user, token = parse_token(token)
    try:
        if not check_session_registered(token, g.user['login']):
            g.user = {}
    except Exception as e:
        pass


@app.after_request
def modify_header_security(res):
    res.headers['Server'] = 'Obviously there is a server, it\'s confidential though'
    return res


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/')
def home():
    if g.user != {}:
        created = get_no_created(g.user)[0]
        shared = get_no_shared(g.user)[0]
    else:
        created = 0
        shared = 0
    return render_template("home.html", user=g.user, no_created=created, no_shared=shared)


@app.route('/logout', methods=['GET'])
def logout():
    if request.method == 'GET':
        if g.user != {}:
            release_session(g.user['login'])
            g.user = {}
            res = make_response(jsonify({
                'message': 'Logged out successfully'
            }), 301)
        else:
            res = make_response(jsonify({
                'message': 'You are already logged out apparently'
            }), 301)
        res.headers['Location'] = "/"
        res.set_cookie('token', '', expires=0)
        return res


@app.route('/login', methods=['GET', 'POST'])
def log_in():
    if request.method == 'GET':
        if g.user != {}:
            return redirect("/")
        else:
            return render_template("login.html", user=g.user)
    elif request.method == 'POST':
        data = request.get_json()
        login = data['login']
        password = data['password']
        pattern = re.compile(r'([a-zA-Z]|[0-9]|-|_){1,128}')
        if None in [login, password] or ' ' in login or ' ' in password or \
            bool(pattern.match(login)) is False or verify_user(login, password) is False:
            sleep(1)
            res=make_response(jsonify({
                'message': 'Invalid credentials'
            }), 400)
        else:
            try:
                master_password = get_master_password(login)
                jwt_token = encode_jwt_data(login, master_password)
                if jwt_token is not None:
                    if 'X-Forwarded-For' in request.headers:
                        host = request.headers['X-Forwarded-For']
                    else:
                        host = request.remote_addr
                    register_user_session(login, jwt_token, host)
                    res = make_response(jsonify({
                        'message': 'Login successful',
                        'token': jwt_token
                    }), 200)
                    app.config.update(
                        SESSION_COOKIE_SECURE=True,
                        SESSION_COOKIE_HTTPOLNY=True,
                        SESSION_COOKIE_SAMESITE='Strict'
                    )
                    res.set_cookie('token', jwt_token, secure=True, httponly=True, samesite='Strict', path='/')
                else:
                    res = make_response(jsonify({
                        'message': 'Could not log in. Unknown error happened while attempting to write token'
                    }), 403)
            except Exception as e:
                res = make_response(jsonify({
                    'message': 'Something bad happened... Like, really bad :('
                }), 403)
        res.headers['Content-Type'] = 'application/json'
        return res




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        if g.user != {}:
            return redirect('/')
        else:
            return render_template("register.html", user=g.user)
    elif request.method == 'POST':
        data = request.get_json()
        email = data['email']
        login = data['login']
        password = data['password']
        password_repeated = data['passwordRepeated']
        email_pattern = re.compile(r'([a-zA-Z]|[0-9]|_|-)+@([a-zA-Z]|[0-9]|[.])+[.][a-zA-Z]{1,128}')
        login_pattern = re.compile(r'([a-zA-Z]|[0-9]|-|_){1,128}')
        if None in [login, email] or ' ' in login or ' ' in email or ' ' in password or \
            (bool(email_pattern.search(email)) is False) or (bool(login_pattern.search(login)) is False):
            res = make_response(jsonify({
                'message':'Wrong data provided'
            }), 400)
            res.headers['Content-Type'] = "application/json"
            return res
        elif not check_email_available(email):
            res = make_response(jsonify({
                'message': 'Email taken'
            }), 400)
            res.headers['Content-Type'] = "application/json"
            return res
        elif not check_login_available(login):
            res = make_response(jsonify({
                'message': 'Login taken'
            }), 400)
            res.headers['Content-Type'] = "application/json"
            return res
        elif password != password_repeated:
            res = make_response(jsonify({
                'message': 'Passwords don\'t match'
            }), 400)
            res.headers['Content-Type'] = "application/json"
            return res
        elif not check_password_strength(password):
            res = make_response(jsonify({
                'message': 'Password is too weak. Good password must consist of at least 8 characters and include '
                           'at least one capital letter, one number and one special character from !@#$%^&*()-_'
            }), 400)
            res.headers['Content-Type'] = "application/json"
            return res
        else:
            try:
                if 'X-Forwarded-For' in request.headers:
                    host = request.headers['X-Forwarded-For']
                else:
                    host = request.remote_addr
                register_user(email, login, password, host)
                res = make_response(jsonify({
                    'message': 'Registered successfully, now you will be redirected to log in'
                }), 200)
                return res
            except Exception as e:
                res = make_response(jsonify({
                    'message': 'Unknown error happened while trying to register'
                }), 403)
                res.headers['Content-Type'] = "application/json"
                return res


@app.route('/add_note', methods=['GET', 'POST'])
def add_note():
    if request.method == 'GET':
        if g.user == {}:
            return redirect('/')
        else:
            return render_template("add_note.html", user=g.user)
    elif request.method == 'POST':
        data = request.get_json()
        note_title = data['noteTitle']
        note_content = data['null']
        note_privacy = data['radio_value']
        note_password = data['notePassword']
        note_password_repeated = data['notePasswordRepeated']
        note_recipients = data['noteRecipients']

        if note_title:
            if note_content:
                if note_privacy == 'privacyRestricted' and note_recipients == "":
                    res = make_response(jsonify({
                        'message': 'Provide recipients for restricted note'
                    }), 403)
                    res.headers['Content-Type'] = "application/json"
                    return res
                elif note_privacy == 'privacyRestricted' and note_recipients != "":
                    privacy_setting = note_recipients
                elif note_privacy == 'privacyPrivate':
                    privacy_setting = 'private'
                elif note_privacy == 'privacyPublic':
                    privacy_setting = 'public'

                if note_password:
                    if (note_password != note_password_repeated):
                        res = make_response(jsonify({
                            'message': 'Passwords need to match'
                        }), 403)
                        res.headers['Content-Type'] = "application/json"
                        return res
                insert_note(g.user, note_title, note_content, privacy_setting, note_password)
                res = make_response(jsonify({
                    'message': 'Note successfully added, you will be redirected to your notes'
                }), 200)
                res.headers['Content-Type'] = "application/json"
                return res
            else:
                res = make_response(jsonify({
                    'message': 'Note content required'
                }), 403)
                res.headers['Content-Type'] = "application/json"
                return res
        else:
            res = make_response(jsonify({
                'message': 'Note title required'
            }), 403)
            res.headers['Content-Type'] = "application/json"
            return res


@app.route('/notes/<note_type>', methods=['GET'])
def show_notes(note_type):
    if g.user != {}:
        if note_type == "my":
            selected_notes = get_my_notes(g.user)
        elif note_type == "shared":
            selected_notes = get_shared_notes(g.user)
        return render_template("notes.html", type=note_type, user=g.user, notes=selected_notes)
    else:
        return redirect('/')


@app.route('/note/auth', methods=['POST'])
def auth_note():
    data = request.get_json()

    note_id = data['noteId']
    note_password = data["notePassword"]
    note = get_note_content(note_id, note_password)

    if not note:
        res = make_response(jsonify({
            'message': 'Note password incorrect'
        }), 403)
        res.headers['Content-Type'] = "application/json"
        return res
    else:
        res = make_response(jsonify({
            'content': note
        }), 200)
        res.headers['Content-Type'] = "application/json"
        return res



if __name__ == '__main__':
    init_db()
    # context = ('ochrona.crt', 'ochrona.key')
    app.run(debug=True, ssl_context='adhoc')
