# FSND P3: Catalog (Guyana Events Website)

This website displays events, which are categorized in their respective categories.

## How to Run

 1. `cd into p3_category/vagrant`, run `vagrant up`, then `vagrant ssh`.
 2. Enter project folder using `cd /vagrant/catalog`.
 3. Setup the database using `python db_setup.py`
 4. Run the app using `python app.py`


## Database Setup

There are 4 data models:
 - `Event`: The event or activity entities happening in Guyana. This is the primary content of the app.
 - `User`: The author of the Event entities.
 - `Category`: The taxonomy of the Event entities.
 - `Image`: The image file of the Event entities.

## Rubric:
 - [x] Implement json endpoint with all required content. Implement additional api endpoints (Atom)
 - [x] Add image that reads from db
 - [x] New item form includes image input
 - [x] Include item images.
 - [x] Readme doc
 - [x] Uses nonces to avoid cross-site request forgeries (CSRF)
 - [x] Page reads category and item info from db.
 - [x] Add new items.
 - [x] Page includes edit/update functionality.
 - [x] Delete functionality.
 - [x] Implement a third party authorization and authentication process.
 - [x] CRUD operations should consider authorization status prior to execution.
 - [x] Code quality is neatly formatted
 - [x] Code comments


#### Templates
 All templates inherit from the `base.html` parent template.

#### Google Login

 Google+ Login State Token: Users may gconnect from any page where the gconnect button is visible. The gconnect button is placed inside the `base.html` parent template. The login state token is injected into templates via the flask.g object, and the @inject_state_token decorated function.

#### How Google Connect works:

 1. The user clicks on Google Sign In button which contains the client ID of the registered app with Google API. If the client ID is valid, Google returns a result object (`authResult`).

 2. A callback function is specified, `signInCallback()`, and handles the returned authResult object by sending the `authResult['code']` data, along with the state token, to the `/gconnect` handler via an AJAX request. Note: A unique state token is generated during each page's refresh. The same token is saved as `login_session['state']`. The `login_session` object is `flask.session`.

 3. The `/gconnect` handler receives the `authResult['code']` and state token. It compares to see `request.arg.get('state') == login_session['state'] to validate the request to be forgery-free.

 4. The auth code (from request.data in ajax request) is then used for upgrading into a 'credential' object. This is the `oauth2client.client.OAuth2Credentials` object.

 5. Using `httplib2.Http()`, the `credentials.access_token` is sent to Google API server for validation via an acces token validation url.

 6. Check for the access token to be intended for the rightful user by comparing `access_token_validation_result['user_id'] == credentials.id_token['sub']`

 7. Check if user is already logged in by checking if `login_session['access_token']` exists and `login_session['access_token'] == login_session['gplus_id']`

 8. Use an http request to get user data using the userinfo_url. Store the returned user_data in login_session object. The create_user() function uses the login_session object to create new users.

 *Note that the auth_code is used for upgrading into a credentials object, while the access_token is used for validating using the http request.*


#### Image Uploads

 - The event's image upload form is found on the event page, the event is created.
 - The filename of the uploaded file is renamed using the `rename_file()` function. This ensures that each filename is unique.
 - Images are uploaded into the `catalog/uploads` folder.

#### Protection against CSRF

 - Protection against cross-site request forgeries is built using this guide: http://flask.pocoo.org/snippets/3/
 - A csrf token is generated and stored within the login_session object, and sent to each html form via a hidden input. On form submission, this token must match the one stored within the login_session object; the request is aborted otherwise.


#### Authorization

 - To ensure that the user is able to perform his own scope of authorized actions, two decorated functions are used — `@login_required`, `@logged_in_as_author_required`

#### Feeds

 - Atom feeds are done using AtomFeed from `werzeug.contrib.atom` module (http://flask.pocoo.org/snippets/10/)
