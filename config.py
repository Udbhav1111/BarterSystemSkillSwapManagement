import os

class Config:
    SECRET_KEY = 'your_secret_key'  # Change this to a random secure key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite3'  # SQLite database path
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
