
from flask import Blueprint, request, redirect, jsonify
import urllib.parse
import requests
from oauthlib.oauth2 import WebApplicationClient
import datetime
import json

from demix.utils.logging import logger_factory
from demix.auth import encode
from demix.config import get_cfg
from demix.db import get_db
from demix.utils.flask import protected, current_user, custom_error

GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)
auth = Blueprint('auth', __name__,)
cfg = get_cfg('google') # stores google secret info
client = WebApplicationClient(cfg['client_id']) # needed for google
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()
google_provider_cfg = get_google_provider_cfg()
logger = logger_factory(__name__)
db = get_db()

@auth.route("/api/me")
@protected
def me():
    user = current_user()
    del user['_id']
    return jsonify({"data": user })

@auth.route("/api/login")
def login():
    # Find out what URL to hit for Google login
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=cfg['google_redirect_url'],
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@auth.route("/api/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
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
        user = db.user.find_one({"email": data['email']})
        if user is None:
            user_id = str(db.user.insert_one({"google": data, "email": data['email'], "premium": False}).inserted_id)
        else:
            user_id = str(user['_id'])
        db.logins.insert_one({"user": user_id, "date": datetime.datetime.now()})
        encoded=urllib.parse.quote(encode(user_id))
        logger.info(encoded)
        logger.info("USER logged in")
        logger.info(data)
        return redirect("%s?access=%s" % (cfg['redirect_url'], encoded))
    else:
        return "User email not available or not verified by Google.", 400