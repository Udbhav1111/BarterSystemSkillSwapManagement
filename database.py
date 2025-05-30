import sqlite3

def create_tables():
    conn = sqlite3.connect("instance/db.sqlite3")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        upi_id TEXT  -- New column to store the UPI ID of the user
    )
""")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS skills (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            video_path TEXT DEFAULT NULL,  -- Allow NULL values instead of NOT NULL
            amount REAL NOT NULL DEFAULT 0.0,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );"""
    )
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS skill_swaps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        requester_id INTEGER NOT NULL,
        requested_skill_id INTEGER NOT NULL,
        offered_skill_id INTEGER NOT NULL,
        status TEXT CHECK(status IN ('pending', 'approved', 'rejected')) DEFAULT 'pending',
        FOREIGN KEY (requester_id) REFERENCES users (id),
        FOREIGN KEY (requested_skill_id) REFERENCES skills (id),
        FOREIGN KEY (offered_skill_id) REFERENCES skills (id)
        )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS completed_swaps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        requester_id INTEGER NOT NULL,
        requested_skill_id INTEGER NOT NULL,
        offered_skill_id INTEGER NOT NULL,
        swap_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (requester_id) REFERENCES users (id),
        FOREIGN KEY (requested_skill_id) REFERENCES skills (id),
        FOREIGN KEY (offered_skill_id) REFERENCES skills (id)
    );

    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        creator_id INTEGER NOT NULL,
        video_id INTEGER NOT NULL,  -- Linking to videos instead of skills
        amount REAL NOT NULL,
        status TEXT DEFAULT "pending",
        payment_proof TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (creator_id) REFERENCES users (id),
        FOREIGN KEY (video_id) REFERENCES videos (id) -- Track purchases at video level
    );

    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        skill_id INTEGER,
        title TEXT NOT NULL,
        amount REAL NOT NULL,
        video_path TEXT NOT NULL,  -- Ensure this column exists
        FOREIGN KEY (skill_id) REFERENCES skills(id)
    );
    """
    )
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        token TEXT NOT NULL,
        expiry_time TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_tables()
    print("Database and tables created successfully!")
