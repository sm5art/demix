import os
from flask import Flask, flash, request, redirect, url_for, jsonify, send_file
from spleeter.separator import Separator
from werkzeug.utils import secure_filename
import requests
import json
from oauthlib.oauth2 import WebApplicationClient
import shutil
import re

from demix.auth import encode, decode
from demix.config import get_cfg
from demix.utils.directory import current_directory
from demix.db import get_db

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

ALLOWED_EXTENSIONS = {'mp3', 'wav'}
IN_FOLDER = current_directory(__file__) + "/raw/in"
OUT_FOLDER = current_directory(__file__) + "/raw/out"
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
cfg = get_cfg('google')
pattern = re.compile(r'(.+?)\.[^.]*$|$')

print("CFG+++++++++++++++++++"+str(cfg))
app = Flask(__name__)
separator = Separator('spleeter:4stems-16kHz')
client = WebApplicationClient(cfg['client_id'])
db = get_db()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
           
#TODO WRITE MIDDLEWARE THAT LOGS ANY WEBPAGE VISIT TO A TABLE
#TODO WRITE BLACKLIST FOR LOGOUT FUNCTIONALIY
def auth_failed():
    return jsonify({"error":'auth failed'})

def protected(func):
    def wrapper():
        token = request.headers.get('token')
        try:
            auth_data = decode(token)
            print(auth_data)
            if auth_data['user']:
                return func()
            else:
                return auth_failed()
        except Exception:
            return auth_failed()
    return wrapper

        

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        fil = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if fil.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if fil and allowed_file(fil.filename):
            # file succeded
            filename = secure_filename(fil.filename)
            name = pattern.match(filename).group(1)
            print(name)
            print('%s/%s' % (OUT_FOLDER, name))
            output_file = os.path.join(IN_FOLDER, filename)
            fil.save(output_file)
            separator.separate_to_file(output_file, OUT_FOLDER)
            folder = '%s/%s' % (OUT_FOLDER, name)
            shutil.make_archive(folder, 'zip', folder)
            return send_file("%s.zip" % folder)
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    print(google_provider_cfg)
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
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
        encoded=encode(data['email'])
        return "ENCODED:\n%s\nDECODED:\n%s" % (encoded, decode(encoded))
    else:
        return "User email not available or not verified by Google.", 400

@app.route("/protected")
@protected
def test():
    return "this is a flag"