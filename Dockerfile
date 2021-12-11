FROM python:3.8.12
ADD . /python-flask
WORKDIR /python-flask
RUN python -m pip install --upgrade pip
RUN pip install -r requirements.txt

RUN adduser --disabled-login myuser
USER myuser

# Run the app.  CMD is required to run on Heroku
# $PORT is set by Heroku
CMD gunicorn run:app