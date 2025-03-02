    #!/bin/bash
    set -x
    source /home/belpav/ycbot/venv/bin/activate
    echo "Virtualenv activated"
    exec /home/belpav/ycbot/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:8000 app:app
    echo "Gunicorn started" 
    