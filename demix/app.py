# TODO: REMOVE FILE AFTER PROCESSING
# TODO WRITE MIDDLEWARE THAT LOGS ANY WEBPAGE VISIT TO A TABLE
# TODO WRITE LIMIT TO /upload endpoint only 10 per user

import os
from flask import Flask, flash, request, redirect, url_for, jsonify, send_file
from flask_cors import CORS
from spleeter.separator import Separator
from werkzeug.utils import secure_filename
import requests
import json
from oauthlib.oauth2 import WebApplicationClient
import shutil
import re
import datetime
import hashlib
import urllib.parse

from demix.auth import encode, decode
from demix.config import get_cfg
from demix.utils.directory import current_directory
from demix.db import get_db, ObjectId
from demix.utils.logging import logger_factory

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
ALLOWED_EXTENSIONS = {'mp3', 'wav'}
MAX_FREE_FILE_UPLOADS = 15
IN_FOLDER = current_directory(__file__) + "/raw/in"
OUT_FOLDER = current_directory(__file__) + "/raw/out"
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
cfg = get_cfg('google')
pattern = re.compile(r'(.+?)\.[^.]*$|$')

def init_seperator():
    return Separator('spleeter:4stems-16kHz')

app = Flask(__name__)
CORS(app)
separator = init_seperator()

client = WebApplicationClient(cfg['client_id'])
db = get_db()
logger = logger_factory(__name__)
           
def auth_failed():
    return jsonify({"error":'auth failed'})

def current_user():
    token = request.headers.get('token')
    try:
        auth_data = decode(token)
        if auth_data['user']:
            return auth_data
        else:
            return None
    except Exception:
        return None


def protected(func):
    def wrapper(**kwargs):
        user = current_user()
        if user is not None:
            return func(**kwargs)
        else:
            return auth_failed()
    wrapper.__name__ = func.__name__
    return wrapper

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def custom_error(error_str):
    return jsonify({"error": error_str})

def upload_file_error():   
    return custom_error('file incorrect')    

@app.route('/api/files', methods=['GET'])
@protected
def get_files():
    user = current_user()
    email = user['user']
    uploaded_files = list(db.uploaded_file.find({"user": email}))
    return jsonify(list(map(lambda x: {"_id": str(x['_id']), "filename": x['secure_filename'], "date": x['datetime']}, uploaded_files)))

def get_file_count_for_user(user):
    return db.uploaded_file.count({'user': user})

@app.route('/api/post_file', methods=['POST'])
@protected
def upload_file():
    # check if the post request has the file part
    if 'file' not in request.files:
        return upload_file_error()
    fil = request.files['file']
    # if user does not select file, browser also
    # submit an empty part without filename
    if fil.filename == '':
        return upload_file_error()
    if fil and allowed_file(fil.filename):
        # file succeded
        email = current_user()['user']
        logger.info("email-> %s" % email)
        if get_file_count_for_user(email) >= MAX_FREE_FILE_UPLOADS:
            logger.info("reached limit")
            return custom_error("reached file upload limit")
        filename = secure_filename(fil.filename)
        name = pattern.match(filename).group(1)
        logger.info("NAME of file: "+ name)
        logger.info('OUTFOLDER: %s/%s' % (OUT_FOLDER, name))
        folder = '%s/%s' % (OUT_FOLDER, name)
        output_file = os.path.join(IN_FOLDER, filename)
        content = fil.read()
        md5 = hashlib.md5(content).hexdigest()
        existing_files = db.uploaded_file.find_one({"user": email, "md5": md5})
        if existing_files is not None:
            logger.info("File already uploaded %s" % str(existing_files))
            return custom_error("file already uploaded")
        with open(output_file, 'wb') as f:
            f.write(content)
        data={
            "secure_filename": filename, 
            "datetime": datetime.datetime.now(),
            "local_filename": output_file,
            "processed_output": folder,
            "user": email,
            "md5": md5
        }
        data_id = db.uploaded_file.insert_one(data).inserted_id
        separator.separate_to_file(output_file, OUT_FOLDER, bitrate='16k')
        shutil.make_archive(folder, 'zip', folder)
        return jsonify({"data_id" : str(data_id)})
    return upload_file_error()

@app.route('/api/result/<result_id>')
def get_result(result_id):
    result = db.uploaded_file.find_one({"_id": ObjectId(result_id)})
    folder = result['processed_output']
    return send_file("%s.zip" % folder)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/api/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=cfg['google_redirect_url'],
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/api/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(token_endpoint,
        authorization_response=request.url,
        redirect_url=cfg['google_redirect_url'],
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(cfg['client_id'], cfg['client_secret']),
    )
    client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    data = userinfo_response.json()
    if userinfo_response.json().get("email_verified"):
        user_id = db.user.update_one(data, {"$set": data}, upsert=True)
        db.logins.insert_one({"user": data, "date": datetime.datetime.now()})
        encoded=urllib.parse.quote(encode(data['email']))
        logger.info(encoded)
        logger.info("USER logged in")
        logger.info(data)
        return redirect("%s?access=%s" % (cfg['redirect_url'], encoded))
    else:
        return "User email not available or not verified by Google.", 400