from flask import request, jsonify
from demix.auth import decode
from demix.db import get_db, ObjectId

db = get_db()

def custom_error(error_str):
    return jsonify({"error": error_str})

def current_user():
    token = request.headers.get('token')
    try:
        auth_data = decode(token)
        if auth_data['user']:
            user = db.user.find_one({'_id': ObjectId(auth_data['user'])})
            return user
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
            return custom_error('auth failure')
    wrapper.__name__ = func.__name__
    return wrapper