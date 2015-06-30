# use sqlalchemy to map python class to tables in db
from sqlalchemy import Column, ForeignKey, String, Integer
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship


# make an instance of declarative_base
Base = declarative_base()


# Category class
class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)


# Author class
class Author(Base):
    __tablename__ = 'author'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)


# Event class
class Event(Base):
    __tablename__ = 'event'
    id = Column(Integer, primary_key=True)
    title = Column(String(250), nullable=False)
    # description = Column(String(1000))

    # set relationship with category and author
    # category_id = Column(Integer, ForeignKey('category.id'))
    # category = relationship(Category)
    # author_id = Column(Integer, ForeignKey('author.id'))
    # author = relationship(Author)


engine = create_engine('sqlite:///events.db')

Base.metadata.create_all(engine)
