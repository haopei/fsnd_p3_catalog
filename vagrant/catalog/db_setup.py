# use sqlalchemy to map python class to tables in db
from sqlalchemy import Column, ForeignKey, String, Integer, DateTime
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

# make an instance of declarative_base
Base = declarative_base()

# Normalized Design
#   Row has a unique key, all columns describe the key
#   Facts irrelevant to the key belong in different tables
#   Tables should not imply false relationships
#   Every row has same number of column


# Category class
class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
        }


# User class
class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    email = Column(String(500), nullable=False)


# Event class
class Event(Base):
    __tablename__ = 'event'
    id = Column(Integer, primary_key=True)

    # all fields should adhere to normalized design
    title = Column(String(250), nullable=False)
    description = Column(String(1000), nullable=True)
    image = Column(String, nullable=True)
    created = Column(DateTime, default=datetime.datetime.utcnow)

    # set relationship with Category
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)

    # relationship with author (User)
    creator_id = Column(Integer, ForeignKey('user.id'))
    creator = relationship(User)

    @property
    def serialize(self):
        """Returns object data in serializable format"""
        return {
            'id': self.id,
            'title': self.title,
            'category_id': self.category_id,
            'creator_id': self.creator_id
        }

    def __init__(self, title, description, creator_id, category_id):
        self.title = title
        self.description = description
        self.creator_id = creator_id
        self.category_id = category_id


class Image(Base):
    __tablename__ = 'image'
    id = Column(Integer, primary_key=True)
    serving_url = Column(String, nullable=False)
    event_id = Column(Integer, ForeignKey('event.id'))
    event = relationship(Event)


engine = create_engine('sqlite:///events.db')

Base.metadata.create_all(engine)
