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
        'postgresql://ycbotuser:{DATABASE_PASSWORD}@localhost/ycbase'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
