import jwt
import datetime

from demix.config import get_cfg

SECRET = get_cfg('jwt')['secret']
DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
# returns JWT from username
def encode(email):
    return jwt.encode({'user': email, 'time':datetime.datetime.now().strftime(DATE_FORMAT)}, SECRET, algorithm='HS256').decode('utf-8')

# returns username from token
def decode(token):
    return jwt.decode(token, SECRET, algorithms=['HS256'])

