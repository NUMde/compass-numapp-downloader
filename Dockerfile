FROM python:3.7

COPY / .

RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    swig \
    && pip install -r requirements.txt

CMD [ "python", "./downloader.py" ]