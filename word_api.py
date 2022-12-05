import time
from functools import wraps

from flask import Flask, request, jsonify, make_response

import numpy as np
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'aaa555'


class User:
    id = '123456789'
    user_name = 'username'
    password = 'password'
    token = None

    @staticmethod
    def generate_auth_token(expires_in=500):
        return jwt.encode(
            {'id': User.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.id == data['id']

    @staticmethod
    def verify_password(username, password):
        # first try to authenticate by token
        return username==User.user_name and password == User.password

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorator():
        token = None
        # ensure the jwt-token is passed with the headers
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token: # throw error if no token provided
            return make_response(jsonify({"message": "A valid token is missing!"}), 401)
        try:
           # decode the token to obtain user public_id
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return make_response(jsonify({"message": "Invalid token!"}), 401)
         # Return the user information attached to the token
        if data['id'] == User.id:
            word_list = request.get_json().get('word_list')
            return f(word_list)
    return decorator


@app.route('/login', methods=['GET'])
def login():
    auth = request.get_json()
    if not auth or not auth.get('username', None) or not auth.get('password', None):
        return make_response('Could not verify! (have to send username and password)', 401)


    if User.verify_password(auth.get('username'), auth.get('password')):
        token = User.generate_auth_token()
        return make_response(jsonify({'token': token}), 201)

    return make_response('Could not verify password or username!', 403)

@app.route("/wordcount", methods=['GET'])
@token_required
def wordcount(word_list):
    if word_list is None:
        return make_response(jsonify({"message": "There is no word_list in Json's keys"}), 401)
    words, counts = np.unique(word_list, return_counts=True)
    return make_response(jsonify({word: int(count) for word, count in zip(words, counts)}), 201)


if __name__ == '__main__':
    app.run()
