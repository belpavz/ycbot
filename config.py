# config.py
import os
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    PARTNER_TOKEN = os.environ.get('PARTNER_TOKEN')
    API_KEY = os.environ.get('YCLIENTS_API_KEY')
    APPLICATION_ID = os.environ.get('APPLICATION_ID')
    WEBHOOK_URL = os.environ.get('WEBHOOK_URL')
    DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f'postgresql://ycbotuser:{DATABASE_PASSWORD}@localhost/ycbase?sslmode=require&keepalives=1&keepalives_idle=60&keepalives_interval=10&keepalives_count=5'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    YCLIENTS_CLIENT_ID = os.environ.get('YCLIENTS_CLIENT_ID')
    YCLIENTS_CLIENT_SECRET = os.environ.get('YCLIENTS_CLIENT_SECRET')
    OAUTH_REDIRECT_URI = os.environ.get('OAUTH_REDIRECT_URI')
