# config.py
import os
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    PARTNER_TOKEN = os.environ.get('PARTNER_TOKEN')
    API_KEY = os.environ.get('YCLIENTS_API_KEY')
    # ID вашего приложения в YCLIENTS
    APPLICATION_ID = os.environ.get('APPLICATION_ID')
    WEBHOOK_URL = os.environ.get('WEBHOOK_URL')  # URL для вебхуков
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
