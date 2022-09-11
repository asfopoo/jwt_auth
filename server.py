import uuid
import time
import json
import math
from flask import Flask, request
import jwt
 
# Flask constructor takes the name of
# current module (__name__) as argument.
app = Flask(__name__)

# NOTE: both secrets must be different for better security
access_secret = 'some_secret'
refresh_secret = 'some_refresh_secret'
 
# The route() function of the Flask class is a decorator,
# which tells the application which URL should call
# the associated function.
@app.route('/login', methods=['GET', 'POST'])
def login():

    # TODO: validate username and password, plus whatever else here

    now = math.trunc((time.time()))
    user_id = uuid.uuid4()
    jti = uuid.uuid4()

    access_payload = {
        # issued at
        'iat': now,
        # expires after 15 mins.
        "exp": now + 900,
        "user_id": str(user_id),
    }

    # TODO: save all of the refresh fields in the database so we can revoke access by username at anytime
    # at most a bad actor will have 15 mins of access cinse we sign the jwt with 15 min exp claim
    refresh_payload = {
        # issued at
        'iat': now,
        # expires after 3 months.
        "exp": now + 2628288,
        # jwt ID
        "jti": str(jti),
        "user_id": str(user_id),
    }

    # encode both jwt's
    access_jwt = jwt.encode(access_payload, access_secret, algorithm="HS256")
    refresh_jwt = jwt.encode(refresh_payload, refresh_secret, algorithm="HS256")

    # return response and 200 response code
    response = {"access_jwt": access_jwt, "refresh_jwt": refresh_jwt}
    return response, 200

"""
Params
token: refresh token
user: user_id or email 
"""
@app.route('/refresh_expired_access_token', methods=['POST'])
def refresh_expired_access_token():

    # get the params from the request
    r = json.loads(request.data)

    # TODO validate this is the correct token for this user - from DB

    # decode the refresh jwt, throw execptions on failure
    try:
        jwt.decode(r["token"], refresh_secret, algorithms=['HS256'])
        print("Token is still valid and active")
    except jwt.exceptions.ExpiredSignatureError:
        # client should redirect to login
        response = {"reponse": "expired token"}
        return response, 403
    except jwt.InvalidTokenError:
        response = {"reponse": "invalid token"}
        return response, 403
    except:
        raise("unknown")

    # create new access token with new iat and exp claims
    now = time.time()
    user_id = uuid.uuid4()

    access_payload = {
        # issued at
        'iat': now,
        # expires after 15 mins.
        "exp": now + 900,
        "user_id": str(user_id),
    }

    # encode the new jwt
    access_jwt = jwt.encode(access_payload, access_secret, algorithm="HS256")

    response = {"access_jwt": access_jwt}
    return response, 200
    
 
# main driver function
if __name__ == '__main__':
 
    # run() method of Flask class runs the application
    # on the local development server.
    app.run()