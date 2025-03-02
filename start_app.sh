    #!/bin/bash
    set -x  # ¬ключаем отладочный вывод
    source /home/belpav/ycbot/venv/bin/activate
    echo "Virtualenv activated"
    /home/belpav/ycbot/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:8000 app:app
    echo "Gunicorn started" #Ёта строка может не успеть выполнитс€, если gunicorn падает
    