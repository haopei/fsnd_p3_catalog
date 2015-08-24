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
from flask import session as login_session

# create flow object from client_secret.json file
from oauth2client.client import flow_from_clientsecrets

# handles error during exchange of authorization code for access token
from oauth2client.client import FlowExchangeError

import httplib2
import json
import requests

# Feeds
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


# Decorator function
#   requires authentication of user before proceeding
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not login_session.get('user_id'):
            return make_response(json.dumps('You aint logged in'), 300)
        return func(*args, **kwargs)
    return wrapper


# Decorator function
#   ensure user is authorized to perform a task
def logged_in_as_author_required(func):
    @wraps(func)
    def wrapper(event_id):
        event = session.query(Event).filter_by(id=event_id).one()
        if login_session.get('user_id') != event.creator_id:
            return make_response(json.dumps('You are not authorized to do this.'), 300)
        return func(event_id)
    return wrapper


# Decorated function
#   Injects a different state token to templates for gconnect
def inject_state_token(func):
    @wraps(func)
    def wrapper(*arg, **kwargs):
        if login_session.get('user_id'):
            g.user = session.query(User).filter_by(id=login_session.get('user_id')).one()
        state = generate_random_string(32)
        login_session['state'] = state
        g.state = state
        return func(*arg, **kwargs)
    return wrapper


# Specify a list of paths which do not require CSRF protection.
NO_CSRF_REQUIRED = ['/gconnect']


# CSRF Protection
#   Guide: http://flask.pocoo.org/snippets/3/

# Before a POST request is made, run this function
@app.before_request
def csrf_protect():
    if request.method == "POST" and request.path not in NO_CSRF_REQUIRED:
        token = login_session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            return make_response(json.dumps('there is no token or the token does not match.'), 300)


# Generates the '_csrf_token'
#   to be used in hidden input during form submission
def generate_csrf_token():
    if '_csrf_token' not in login_session:
        # if no _csrf_token exists, create one
        login_session['_csrf_token'] = generate_random_string(32)
    return login_session['_csrf_token']

# Make generate_csrf_token() available within templates
#   so that html forms can access it
app.jinja_env.globals['generate_csrf_token'] = generate_csrf_token


# Gconnect: sign in with Google+
#   Handles ajax POST request from signInCallback() in base.html
#   request contains state token
#   and auth_code that was returned from Google
@app.route('/gconnect', methods=['POST'])
def gconnect():

    # get state token from url param
    state = request.args.get('state')

    # Handle mismatching state tokens
    #   by comparing the token passed by the html form via ajax
    #   with the token inside login_session['state'] (created during @inject_state_token)
    if state != login_session['state']:
        response = make_response(json.dumps('Error: State tokens do not match.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # The authResult['code'] data sent via signInCallback()
    #   which is the same code returned by Google servers
    #   after clicking "Sign In" button
    auth_code = request.data

    # Try to upgrade auth code for 'credentials' object (AKA: the oauth2client.client.OAuth2Credentials object)
    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(auth_code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code into credentials object.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # extract access_token from credentials object
    access_token = credentials.access_token

    # used to validate access_token via the google api server
    access_token_validation_url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)

    h = httplib2.Http()
    # print 'httplib2.Http(): ', h

    # after the credentials.access_token is sent for validating
    #   the google api server returns this result object
    access_token_validation_result = json.loads(h.request(access_token_validation_url, 'GET')[1])

    # access_token_validation_result: {u'issued_to': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com', u'user_id': u'114033218199153796061', u'expires_in': 3594, u'access_type': u'offline', u'audience': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com', u'scope': u'https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.email', u'email': u'haopeibox@gmail.com', u'verified_email': True}

    # Handle access token validation error
    if access_token_validation_result.get('error') is not None:
        response = make_response(json.dumps(access_token_validation_result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that access_token is intended for right user
    #   by making sure that user_id inside credentials
    #   matches the user_id in the access_token_validation_result object
    gplus_id = credentials.id_token['sub']  # {u'sub': u'114033218199153796061', u'iss': u'accounts.google.com', u'email_verified': True, u'at_hash': u'RsxVDBH-C7xq5nLFmgprmQ', u'exp': 1436635996, u'azp': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com', u'iat': 1436632396, u'email': u'haopeibox@gmail.com', u'aud': u'110779018634-1alavf5cs7svqo8hh4rq2ifq71pg9r9o.apps.googleusercontent.com'}
    if access_token_validation_result['user_id'] != gplus_id:
        response = make_response(json.dumps('Token\'s user ID does not match given user ID'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if user is already logged in,
    #   by checking if existing credentials.access_token object exists
    #   and by comparing login_session['access_token'] == login_session['gplus_id']
    stored_credentials = login_session.get('access_token')  # this is the access_token: ya29.rQGUXho4-MVcB2vVRf-XZm2tzuQfyCDJUY1XPi_l8j6r1wDwcVDs0-mUQVfFydrMHap0
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # If user is not already logged in,
    #   store the access token in the session for later use.
    login_session['gplus_id'] = gplus_id

    # The credentials object is actually not serializable and store inside login_session,
    #   so we are just serializing access_token to authorization
    # see: http://stackoverflow.com/questions/29565392/error-storing-oauth-credentials-in-session-when-authenticating-with-google
    # and: http://stackoverflow.com/questions/22915461/google-login-server-side-flow-storing-credentials-python-examples
    login_session['access_token'] = credentials.access_token

    # Request info about user
    #   using the access token and userinfo url
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    # same as data = answer.json()
    #  via the python requests library
    user_data = json.loads(answer.text)  # {u'family_name': u'Yang', u'name': u'Haopei Yang', u'picture': u'https://lh3.googleusercontent.com/-XdUIqdMkCWA/AAAAAAAAAAI/AAAAAAAAAAA/4252rscbv5M/photo.jpg', u'gender': u'male', u'email': u'haopeibox@gmail.com', u'link': u'https://plus.google.com/114033218199153796061', u'given_name': u'Haopei', u'id': u'114033218199153796061', u'verified_email': True}

    # The create_user() uses this login_session to creates a new user.
    login_session['username'] = user_data['name']
    login_session['picture'] = user_data['picture']
    login_session['email'] = user_data['email']

    # Check to see if a user already exists by this email.
    #   If not, create a new user
    user_id = get_user_id_by_email(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)

    # Store the user_id of the current user inside the session object
    #   Used during the session for validating authorization
    #   during content creation and modification.
    login_session['user_id'] = user_id

    flash("You are now logged in as %s" % login_session['username'])
    return make_response(json.dumps('Login via gconnect successful.'), 200)


@app.route('/logout')
def logout():

    # Check if user is logged in
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('User is not logged in.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # If access_token exists, revoke using url
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # If the access_token is revoked in Google servers,
    #   delete the local session within the login_session object
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
        # Handle invalid token
        response = make_response(json.dumps('Disconnect failed: unable to revoke access token.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
@inject_state_token
def homePage():
    all_categories = session.query(Category).order_by(Category.name).all()
    all_events = session.query(Event).order_by(asc(Event.title)).all()
    return render_template('home.html', all_events=all_events, all_categories=all_categories)


# User Page
@app.route('/u/<int:user_id>')
@inject_state_token
def userPage(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    events = []
    if user:
        events = session.query(Event).filter_by(creator_id=user.id).all()
    return render_template('user-page.html', user=user, events=events)


# Create Event
@app.route('/event/create/', methods=['GET', 'POST'])
@inject_state_token
@login_required
def createEvent():
    categories = session.query(Category).all()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category_id = request.form['category_id']
        new_event = Event(
            title=title,
            description=description,
            creator_id=login_session['user_id'],
            category_id=category_id)
        session.add(new_event)
        session.commit()
        flash('New event created: %s' % new_event.title)
        return redirect(url_for('showEvent', event_id=new_event.id))
    elif request.method == 'GET':
        return render_template('event-create.html', categories=categories)


# Event Edit
@app.route('/event/<int:event_id>/edit/', methods=['GET', 'POST'])
@inject_state_token
@logged_in_as_author_required
def editEvent(event_id):
    event = session.query(Event).filter_by(id=event_id).one()
    categories = session.query(Category).all()
    if request.method == 'POST':
        event.title = request.form['title']
        event.description = request.form['description']
        event.category_id = request.form['category_id']
        session.commit()
        flash('Event saved: %s' % event.title)
        return redirect(url_for('showEvent', event_id=event_id))
    elif request.method == 'GET':
        return render_template('event-edit.html', event=event, categories=categories)


# Event Delete
@app.route('/event/<int:event_id>/delete/', methods=['GET', 'POST'])
@inject_state_token
@logged_in_as_author_required
def deleteEvent(event_id):
    event_to_delete = session.query(Event).filter_by(id=event_id).one()
    if request.method == 'POST':
        session.delete(event_to_delete)
        # Delete images associated with this event
        images = session.query(Image).filter_by(event_id=event_to_delete.id).all()
        if images:
            try:
                # Delete Image object from database and file system
                for img in images:
                    session.delete(img)
                    os.remove(img.serving_url)
            except:
                return make_response(json.dumps('Failed to delete event images'), 500)
        session.commit()
        flash('Event deleted: %s' % event_to_delete.title)
        return redirect(url_for('homePage'))
    elif request.method == 'GET':
        return render_template('event-delete.html', event=event_to_delete)


# Event Page
@app.route('/event/<int:event_id>/')
@inject_state_token
def showEvent(event_id):
    event = session.query(Event).filter_by(id=event_id).one()
    event_images = session.query(Image).filter_by(event_id=event_id).all()
    if login_session.get('user_id') and event.creator_id == login_session['user_id']:
        return render_template('event-page.html', event=event, event_images=event_images)
    else:
        return render_template('public-event-page.html', event=event, event_images=event_images)


# Category create
@app.route('/category/create/', methods=['GET', 'POST'])
@inject_state_token
@login_required
def categoryCreate():
    if request.method == 'POST':
        category_name = request.form['name']
        category = Category(name=category_name)
        session.add(category)
        session.commit()
        return redirect(url_for('categoryCreate'))
    elif request.method == 'GET':
        categories = session.query(Category).order_by(asc(Category.name)).all()
        return render_template('category-create.html', categories=categories)


# Category page
#   Lists all events per category
@app.route('/category/<int:category_id>/')
@inject_state_token
def categoryPage(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    if category:
        events = session.query(Event).filter_by(category_id=category.id).all()
        all_categories = session.query(Category).order_by(Category.name).all()
        return render_template('category-page.html', category=category, events=events, all_categories=all_categories)
    else:
        response = make_response(json.dumps('Cannot find category id: %s' % category_id), 404)
        return response


# Handles upload of images, per event
@app.route('/upload/<int:event_id>/', methods=['POST'])
@logged_in_as_author_required
def upload(event_id):
    event = session.query(Event).filter_by(id=event_id).one()
    if event:
        uploaded_file = request.files['file']
        # rename the uploaded file's filename to be unique
        uploaded_file.filename = rename_file(uploaded_file.filename, str(event_id))

        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            file_url = os.path.join(app.config['FILE_UPLOAD_FOLDER'], filename)
            uploaded_file.save(file_url)

            # If there is no existing image, create a new Image object
            image = session.query(Image).filter_by(event_id=event.id).all()
            if len(image) is 0:
                image = Image(event_id=event.id, serving_url=file_url)
            else:
                # Else if image exists, delete it from system
                #   and change the serving url to the newly uploaded one
                image = image[0]
                os.remove(image.serving_url)
                image.serving_url = file_url
            session.add(image)
            session.commit()
            return redirect(url_for('showEvent', event_id=event_id))
        return make_response(json.dumps('Error uploading file'), 500)
    else:
        return make_response(json.dumps('The event for which this image is uploaded does not exist.'), 400)


# Serve an uploaded file
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['FILE_UPLOAD_FOLDER'], filename)


# Atom feeds
@app.route('/recent_atom/')
def recent_atom():
    app.logger.debug(request.url_root)
    feed = AtomFeed('Recent Events', feed_url=request.url, url=request.url_root)
    events = session.query(Event).all()
    for e in events:
        feed.add(id=e.id, title=e.title, content_type='html', updated=e.created)
    return feed.get_response()


# JSON format of all events
@app.route('/recent_json/')
def recent_json():
    events = session.query(Event).all()
    return jsonify(Events=[e.serialize for e in events])


# JSON format of all categories
@app.route('/categories_json')
def categories_json():
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


# JSON Endpoint per event
@app.route('/event/<int:event_id>/JSON/')
def eventJSON(event_id):
    event = session.query(Event).filter_by(id=event_id).all()
    return jsonify(EventItem=[e.serialize for e in event])


@app.route('/categories/JSON/')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[cat.serialize for cat in categories])


# Create new user using a login_session
#   returns: user.id
def create_user(login_session):
    new_user = User(username=login_session['username'], email=login_session['email'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()  # Use email since it is common across google+, fb, twitter, etc.
    return user.id


# Get the user's id given his email
def get_user_id_by_email(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Checks to see if an uploaded file's filename is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

# if we are 'executing' app.py
#   run this app on the selected port
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'  # flask uses this to create sessions
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
