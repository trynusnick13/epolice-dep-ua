import logging
from flask import Flask

from config import Config
from flask_cors import CORS

logging.getLogger().setLevel(logging.DEBUG)
app = Flask(__name__)
app.config.from_object(Config)

CORS(app)
app.debug = True

from app import routes
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
