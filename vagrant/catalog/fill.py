from db_setup import Base, Category, Event, Image
from sqlalchemy import create_engine
from flask import Flask
from sqlalchemy.orm import sessionmaker
import datetime


engine = create_engine('sqlite:///events.db')
Base.metadata.bind = engine

# Generate new Session object
#   using sessionmaker factory
#   and binding session to the engine connection
db_session = sessionmaker(bind=engine)

# used for querying the db
session = db_session()

app = Flask(__name__)


def init():
    # Create categories
    cat1 = Category(name='Sports & Entertainment')
    cat2 = Category(name='Arts & Theatre')
    cat3 = Category(name='Adventures & Outdoors')
    cat4 = Category(name='Gaming & Puzzles')
    cat5 = Category(name='Food & Drinks')
    cat6 = Category(name='Competitions & Marathons')
    cat7 = Category(name='Comedy')
    cat8 = Category(name='Recreational')
    cats = [cat1, cat2, cat3, cat4, cat5, cat6, cat7, cat8]
    for cat in cats:
        if not session.query(Category).filter_by(name=cat.name).all():
            session.add(cat)
    session.commit()
init()
