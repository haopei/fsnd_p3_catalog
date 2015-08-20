import os

# import models from db_setup
from db_setup import Base, User, Category, Event, Image

# sqlalchemy
from sqlalchemy import create_engine, asc

# flask for templating
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify, send_from_directory, g

# utility functions
from util import *

# for image/file uploads
from werkzeug import secure_filename

# sessions
from sqlalchemy.orm import sessionmaker

# flask's version of sessions
#   already has 'session' so we need import as 'login_session'
from app import login_session
# Used for generating state token
import random
import string

# create flow object from client_secret.json file
from oauth2client.client import flow_from_clientsecrets

# handles error during exchange of authorization code for access token
from oauth2client.client import FlowExchangeError

import httplib2
import json
import requests

# Feeds
from urlparse import urljoin
from werkzeug.contrib.atom import AtomFeed

from functools import wraps

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']


# define app
#   __name__ is "__main__"
app = Flask(__name__)


# file upload configurations
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
# FILE_UPLOAD_FOLDER = os.path.join(APP_ROOT, 'uploads/')
# FILE_UPLOAD_FOLDER = os.path.join(APP_ROOT, 'uploads/')
app.config['ALLOWED_EXTENSIONS'] = set(['png', 'jpg', 'jpeg', 'gif'])
app.config['FILE_UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

# Connect to db
#   creates a new Engine instance
engine = create_engine('sqlite:///events.db')
Base.metadata.bind = engine

# Generate new Session object
#   using sessionmaker factory
#   and binding session to the engine connection
db_session = sessionmaker(bind=engine)

# used for querying the db
session = db_session()

# gconnect functionality
# auth code and state token are sent here
@app.route('/gconnect', methods=['POST'])
def gconnect():

    # get state param from url
    state = request.args.get('state')
    app.logger.debug(state)

    # Handle mismatching state tokens
    #   by comparing the the one passed by login.html via ajax
    #   with the original one inside login_session['state']
    if state != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # the auth code sent from the login.html's ajax request:
    #   data: authResult['code']
    #   to be used for upgrading into a credentials object
    code = request.data
    print "request.data: ", request.data

    try:
        # upgrade authorization code for credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)  # credentials contain the access token for the app
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token

    # used to validate access_token via the google api server
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)

    h = httplib2.Http()
    # print 'httplib2.Http(): ', h

    # after the credentials.access_token is sent for validating
    #   the google api server returns this result object
    result = json.loads(h.request(url, 'GET')[1])

    # print result
    #   {
    #     u'issued_to': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com',
    #     u'user_id': u'114033218199153796061',
    #     u'expires_in': 3594,
    #     u'access_type': u'offline',
    #     u'audience': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com',
    #     u'scope': u'https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.email',
    #     u'email': u'haopeibox@gmail.com',
    #     u'verified_email': True
    #   }

    # Difference between credentials object and result object
    # *******************************************************
    #   credentials: created via flow_from_clientsecrets, step2_exchange(auth_code)
    #       - This auth_code is returned to signInCallback(authResult) after "Approve".
    #       - Then, credentials.access_token is to be verified
    #   result: this object is returned after the credentials.access_token is verified

    # If the credentials.access_token validation fails, it returns an error
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # verify that access_token is intended for user
    #   by making sure that user_id inside credentials
    #   matches the user_id in the result object
    gplus_id = credentials.id_token['sub']  # {u'sub': u'114033218199153796061', u'iss': u'accounts.google.com', u'email_verified': True, u'at_hash': u'RsxVDBH-C7xq5nLFmgprmQ', u'exp': 1436635996, u'azp': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com', u'iat': 1436632396, u'email': u'haopeibox@gmail.com', u'aud': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com'}
    if result['user_id'] != gplus_id:       # result: {u'issued_to': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com', u'user_id': u'114033218199153796061', u'expires_in': 3594, u'access_type': u'offline', u'audience': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com', u'scope': u'https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.email', u'email': u'haopeibox@gmail.com', u'verified_email': True}
        response = make_response(json.dumps('Token\'s user ID does not match given user ID'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check if user is already logged in, by
    #   checking if existing credentials.access_token object exists
    #   and, comparing user_id_inside_login_session == user_id_inside_credentials
    stored_credentials = login_session.get('credentials')  # this is the access_token: ya29.rQGUXho4-MVcB2vVRf-XZm2tzuQfyCDJUY1XPi_l8j6r1wDwcVDs0-mUQVfFydrMHap0
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # store the access token in the session for later use.
    login_session['gplus_id'] = gplus_id

    # the entire credentials object is actually not serializable, so this is not possible
    # see: http://stackoverflow.com/questions/29565392/error-storing-oauth-credentials-in-session-when-authenticating-with-google
    # and: http://stackoverflow.com/questions/22915461/google-login-server-side-flow-storing-credentials-python-examples
    # login_session['credentials'] = credentials

    # Instead, we can just store the access_token
    login_session['access_token'] = credentials.access_token
    # print "159: login_session['access_token']: ", login_session['access_token']

    # get info about user
    #   using the access token and userinfo url
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    # same as data = answer.json()
    #  via the python requests library
    data = json.loads(answer.text)
    #   answer.text:  {
    #       "id": "114033218199153796061",
    #       "email": "haopeibox@gmail.com",
    #       "verified_email": true,
    #       "name": "Haopei Yang",
    #       "given_name": "Haopei",
    #       "family_name": "Yang",
    #       "link": "https://plus.google.com/114033218199153796061",
    #       "picture": "https://lh3.googleusercontent.com/-XdUIqdMkCWA/AAAAAAAAAAI/AAAAAAAAAAA/4252rscbv5M/photo.jpg",
    #       "gender": "male"
    #   }
    # json.loads(answer.text): {u'family_name': u'Yang', u'name': u'Haopei Yang', u'picture': u'https://lh3.googleusercontent.com/-XdUIqdMkCWA/AAAAAAAAAAI/AAAAAAAAAAA/4252rscbv5M/photo.jpg', u'gender': u'male', u'email': u'haopeibox@gmail.com', u'link': u'https://plus.google.com/114033218199153796061', u'given_name': u'Haopei', u'id': u'114033218199153796061', u'verified_email': True}

    # store the user info that you are interested in
    #   inside the local login_session object
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # create new user, if user does not exist
    user_id = get_user_id_by_email(login_session['email'])
    # print '191: user_id:', user_id
    if not user_id:
        print "User id does not exist, creating new user."
        user_id = create_user(login_session)

    # add user_id into the login_session
    #   this is the serial user_id for the User accounts; not the gplus_id
    login_session['user_id'] = user_id

    # print "Logging in with user_id: ", user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/logout')
def logout():

    # check if user is logged in
    #   by checking if credentials object exists in login_session object
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('User is not logged in.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # revoke access token, if it exists
    print 'access_token: ', access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result: ', result

    # delete user's session
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['user_id']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        flash('You have logged out. Come back soon!')
        response = redirect(url_for('homePage'))
        return response
    else:
        # if token is invalid
        response = make_response(json.dumps('Disconnect failed: unable to revoke access token.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response
