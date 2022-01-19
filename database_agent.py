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