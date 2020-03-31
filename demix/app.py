import os
from flask import Flask, jsonify
from flask_cors import CORS

from demix.handlers.auth import auth
from demix.handlers.upload import upload
import demix.queue

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
CORS(app)
app.register_blueprint(auth)
app.register_blueprint(upload)