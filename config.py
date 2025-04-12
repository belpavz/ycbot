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
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.timeweb.ru')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in [
        'true', '1', 't']
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in [
        'true', '1', 't']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get(
        'MAIL_DEFAULT_SENDER') or os.environ.get('MAIL_USERNAME')
