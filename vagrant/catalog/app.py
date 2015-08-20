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
# from urlparse import urljoin
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

# Rubric:
#  [x] Student researches and implements this function using POST requests and nonces to prevent cross-site request forgeries (CSRF).
#  [x] implement json endpoint with all required content.
#       [x] U: implement additional api endpoints
#          [x] atom
#          [x] rss
#  [x] U: add image that reads from db
#  [x] U: new item form includes image input
#  [x] U: Include item images.
#  [] readme doc
#  [x] U: Uses nonces to avoid cross-site request forgeries (CSRF)
#  [x] page reads category and item info from db.
#  [x] Add new items.
#  [x] Page includes edit/update functionality.
#  [x] Delete functionality.
#  [x] Implement a third party authorization and authentication process.
#  [x] CRUD operations should consider authorization status prior to execution.
#       [x] create events
#       [x] delete own events, and not other events
#       [x] edit own events, and not other events
#  [x] code quality is neatly formatted
#  [x] code comments
#  [x] Understood python decorators
#  [x] can login at any page which injects state token

## CHECKS
# [x] login with google
# [x] logout of google
# [x] create event
# [x] edit event
# [x] upload pics per event
# [x] edit pics per event (file renamed; previous pic is deleted)
# [x] categories; events per category
# [x] delete event
# [x] JSON/ATOM of all events
# [x] JSON of individual events
# [x] JSON of categories
# [x] all categories on front page
# [x] prettify the page


# Atom
@app.route('/recent_atom/')
def recent_atom():
    app.logger.debug(request.url_root)
    feed = AtomFeed('Recent Events', feed_url=request.url, url=request.url_root)
    events = session.query(Event).all()
    for e in events:
        feed.add(id=e.id, title=e.title, content_type='html', updated=e.created)
    return feed.get_response()


# XML
@app.route('/recent_rss/')
def recent_rss():
    events = session.query(Event).all()
    response = make_response(render_template('feeds/feed.xml', events=events))
    response.headers['Content-Type'] = 'application/xml'
    return response


@app.route('/recent_json/')
def recent_json():
    events = session.query(Event).all()
    return jsonify(Events=[e.serialize for e in events])


@app.route('/categories_json')
def categories_json():
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


# Decorated function injects a different state token to templates
# for gconnect
def inject_state_token(func):
    @wraps(func)
    def wrapper(*arg, **kwargs):
        if login_session.get('user_id'):
            g.user = session.query(User).filter_by(id=login_session.get('user_id')).one()
        # state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
        state = generate_random_string(32)
        login_session['state'] = state
        g.state = state
        return func(*arg, **kwargs)
    return wrapper


# Before each POST request, csrf_protect() is run.
# These paths are do not require CSRF protection.
NO_CSRF_REQUIRED = ['/gconnect']


# CSRF Protection
# http://flask.pocoo.org/snippets/3/
@app.before_request
def csrf_protect():
    if request.method == "POST" and request.path not in NO_CSRF_REQUIRED:
        token = login_session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            return make_response(json.dumps('there is no token or the token does not match.'), 300)


# generates the csrf token for form submission
def generate_csrf_token():
    if '_csrf_token' not in login_session:
        # if no token exists already, create one
        login_session['_csrf_token'] = generate_random_string(32)
        app.logger.debug('_csrf_token does not exist inside login_session. Creating one now: {0}'.format(login_session['_csrf_token']))
    return login_session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not login_session.get('user_id'):
            return make_response(json.dumps('You aint logged in'), 300)
        return func(*args, **kwargs)
    return wrapper


# gconnect functionality
# auth code and state token are sent here
@app.route('/gconnect', methods=['POST'])
def gconnect():

    # get state param from url
    state = request.args.get('state')

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


# define route handlers
@app.route('/')
@inject_state_token
def homePage():
    # user = get_user_by_id(login_session.get('user_id'))
    all_categories = session.query(Category).order_by(Category.name).all()
    all_events = session.query(Event).order_by(asc(Event.title)).all()
    return render_template('home.html', all_events=all_events, all_categories=all_categories)


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
        app.logger.debug(request.method)
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


def logged_in_as_author_required(func):
    @wraps(func)
    def wrapper(author_id):
        if login_session.get('user_id') != author_id:
            return make_response(json.dumps('You are not authorized to do this.'), 300)
        return func(author_id)
    return wrapper


# Event Edit
@app.route('/event/<int:event_id>/edit/', methods=['GET', 'POST'])
@inject_state_token
def editEvent(event_id):

    event = session.query(Event).filter_by(id=event_id).one()
    categories = session.query(Category).all()

    # check if there is a logged in user; return his id if logged in
    logged_in_user_id = login_session.get('user_id')

    # handle unauthenticated user
    if not logged_in_user_id:
        response = make_response(json.dumps('You are not logged in'), 301)

    if logged_in_user_id == event.creator_id:
        if request.method == 'POST':
            event.title = request.form['title']
            event.description = request.form['description']
            event.category_id = request.form['category_id']
            session.commit()
            flash('Event saved: %s' % event.title)
            return redirect(url_for('showEvent', event_id=event_id))
        elif request.method == 'GET':
            return render_template('event-edit.html', event=event, categories=categories)
    else:
        response = make_response(json.dumps('You are not authorized to edit this event.'), 300)
        return response


# Event Delete
@app.route('/event/<int:event_id>/delete/', methods=['GET', 'POST'])
@inject_state_token
def deleteEvent(event_id):
    event_to_delete = session.query(Event).filter_by(id=event_id).one()

    # check if user is logged in
    if 'username' not in login_session:
        response = make_response(json.dumps('User is not logged in'), 301)
        return response

    # check if user has authorization to delete
    if event_to_delete.creator_id != login_session['user_id']:
        return '<script>function myFunction(){alert("You do not have permission to delete this event.");}</script><body onload="myFunction()">'

    if request.method == 'POST':
        session.delete(event_to_delete)

        # delete images associated with this event
        images = session.query(Image).filter_by(event_id=event_to_delete.id).all()
        if images:
            try:
                for img in images:
                    # delete Image object from database
                    session.delete(img)
                    # delete image from file system
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


# JSON Endpoint per event
@app.route('/event/<int:event_id>/JSON/')
def eventJSON(event_id):
    event = session.query(Event).filter_by(id=event_id).all()
    return jsonify(EventItem=[e.serialize for e in event])


@app.route('/categories/JSON/')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[cat.serialize for cat in categories])


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


@app.route('/categories/')
@inject_state_token
def allCategories():
    categories = session.query(Category).all()
    response = render_template('all-categories.html', categories=categories)
    return response


@app.route('/upload/<int:event_id>/', methods=['POST'])
def upload(event_id):
    event = session.query(Event).filter_by(id=event_id).one()
    if event:
        uploaded_file = request.files['file']
        uploaded_file.filename = rename_file(uploaded_file.filename, str(event_id))
        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            file_url = os.path.join(app.config['FILE_UPLOAD_FOLDER'], filename)
            uploaded_file.save(file_url)

            # check if existing image exists
            image = session.query(Image).filter_by(event_id=event.id).all()

            # if there is no existing image,
            #   create a new image
            if len(image) is 0:
                image = Image(event_id=event.id, serving_url=file_url)
            else:
                image = image[0]
                # delete existing image from system
                # change the serving url to the current one
                os.remove(image.serving_url)
                image.serving_url = file_url

            session.add(image)
            session.commit()

            return redirect(url_for('showEvent', event_id=event_id))
        return make_response(json.dumps('Error uploading file'), 500)
    else:
        return make_response(json.dumps('The event for which this image is uploaded does not exist.'), 400)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['FILE_UPLOAD_FOLDER'], filename)


@app.route('/all-images/')
@inject_state_token
def allImages():
    images = session.query(Image).all()
    return render_template('all-images.html', images=images)


# Create new user
#   returns: user.id
def create_user(login_session):
    new_user = User(username=login_session['username'], email=login_session['email'])
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


# Returns user, given his id
def get_user_by_id(user_id):
    try:
        user = session.query(User).filter_by(id=user_id).one()
        return user
    except:
        return None


# def is_logged_in():
#     if login_session.get('user_id'):
#         return True
#     return False


# def get_event_by_id(event_id):
#     event = session.query(Event).filter_by(id=event_id).one()
#     return event or None


# if we are executing app.py
#   run this app on the selected port
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'  # flask uses this to create sessions
    app.debug = True
    # app.logger.debug(app.config)
    app.run(host='0.0.0.0', port=5000)
