create table if not exists users (
    id integer primary key autoincrement,
    email text unique not null,
    login text unique not null,
    password_hash text not null, -- hash
    master_password text not null, -- do odzyskiwania hasła, hasło pomocnicze / blokowo?
    bound_hosts text not null
);

create table if not exists sessions (
    id integer primary key autoincrement,
    user_id id not null,
    user_name text not null,
    session_token_hash text,
    foreign key(user_id) references users(id),
    foreign key(user_name) references users(login)
);

create table if not exists notes (
    id integer primary key autoincrement,
    owner_login text not null,
    title text not null,
    content text not null,
    allowed_viewers text,                       -- tablica użytkowników dla których dostępne wyświetlanie (w ustawieniu private puste, dla public "all")
    note_password text, -- hash
    foreign key(owner_login) references users(login)
);