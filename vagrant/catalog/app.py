# import models from db_setup
from db_setup import Base, Author, Category, Event

# sqlalchemy
from sqlalchemy import create_engine, asc

# flask for templating
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash

# sessions
from sqlalchemy.orm import sessionmaker
from flask import session as login_session


# define app
# __name__ = "__main__"
app = Flask(__name__)

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


# define route handlers
@app.route('/')
def homePage():
    all_events = session.query(Event).order_by(asc(Event.title))
    return render_template('home.html', all_events=all_events)

# Create Event
@app.route('/event/create/', methods=['GET', 'POST'])
def createEvent():
    if request.method == 'POST':
        title = request.form['title']
        new_event = Event(title=title)

        # create and save new Event instance
        session.add(new_event)
        session.commit()
        flash('New event created: %s' % new_event.title)
        return redirect(url_for('showEvent', event_id=new_event.id))
    elif request.method == 'GET':
        return render_template('event-create.html')


# Event Edit
@app.route('/event/<int:event_id>/edit/', methods=['GET', 'POST'])
def editEvent(event_id):
    event = session.query(Event).filter_by(id=event_id).one()
    if request.method == 'POST':
        event.title = request.form['title']
        session.commit()
        flash('Event saved: %s' % event.title)
        return redirect(url_for('homePage'))
    elif request.method == 'GET':
        return render_template('event-edit.html', event=event)


# Event Delete
@app.route('/event/<int:event_id>/delete/', methods=['GET', 'POST'])
def deleteEvent(event_id):
    event = session.query(Event).filter_by(id=event_id).one()
    if request.method == 'POST':
        session.delete(event)
        session.commit()
        flash('Event deleted: %s' % event.title)
        return redirect(url_for('homePage'))
    elif request.method == 'GET':
        return render_template('event-delete.html', event=event)


# Event Page
@app.route('/event/<int:event_id>/')
def showEvent(event_id):
    event = session.query(Event).filter_by(id=event_id).one()
    return render_template('event-page.html', event=event)


# if we are executing app.py
#   run this app on the selected port
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
