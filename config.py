# config.py
class Config:
    SECRET_KEY = "your_secret_key_here"
    SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://root:your_mysql_password@localhost/encryptedmed"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
