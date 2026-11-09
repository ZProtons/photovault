import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "photovault.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS photos;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            caption TEXT DEFAULT '',
            is_private INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        );
        """
    )
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", "alice123"))
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", "hunter2"))
    conn.commit()
    conn.close()
