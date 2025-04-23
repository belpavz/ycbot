import subprocess
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO)


def send_test_email():
    # Получаем актуальный путь к PHP
    try:
        which_result = subprocess.run(
            ['which', 'php'], capture_output=True, text=True)
        php_path = which_result.stdout.strip()
        if not php_path:
            php_path = '/usr/bin/php'  # Запасной вариант
    except Exception:
        php_path = '/usr/bin/php'  # Запасной вариант

    php_script = '/home/belpav/ycbot/mail_app/send_email.php'
    recipient = 'i@belpav.ru'
    subject = 'Тестовое письмо после обновления PHP'
    body = '<html><body><p>Это тестовое письмо после обновления PHP до версии 8.1.</p></body></html>'

    logging.info(f"Используем PHP по пути: {php_path}")

    try:
        logging.info(
            f"Отправка тестового письма на {recipient} через PHP-скрипт")
        cmd = [php_path, php_script, recipient, subject, body]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60)

        logging.info(f"Результат выполнения команды: {result.returncode}")
        logging.info(f"Вывод: {result.stdout}")

        if result.stderr:
            logging.error(f"Ошибки: {result.stderr}")

        if result.returncode == 0:
            logging.info(f"Письмо успешно отправлено: {result.stdout.strip()}")
            return True
        else:
            logging.error(
                f"Ошибка при отправке письма: {result.stderr.strip() or result.stdout.strip()}")
            return False
    except subprocess.TimeoutExpired:
        logging.error(
            f"Превышено время ожидания при отправке письма на {recipient}")
        return False
    except Exception as e:
        logging.error(f"Ошибка при отправке письма: {str(e)}")
        return False


send_test_email()
