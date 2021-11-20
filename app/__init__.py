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
app.run()