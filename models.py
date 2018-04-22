from sqlalchemy import Column,Integer,String, ForeignKey, Boolean, Time
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
  __tablename__ = 'user'

  id = Column(Integer, primary_key=True)
  username = Column(String(32), index=True)
  password_hash = Column(String(64))

  def hash_password(self, password):
    self.password_hash = pwd_context.encrypt(password)

  def verify_password(self, password):
    return pwd_context.verify(password, self.password_hash)

  def generate_auth_token(self, expiration=600):
    s = Serializer(secret_key, expires_in=expiration)
    return s.dumps({'id': self.id})

  @staticmethod
  def verify_auth_token(token):
    s = Serializer(secret_key)
    try:
      data = s.loads(token)
    except SignatureExpired:
      #Valid Token, but expired
      return None
    except BadSignature:
      #Invalid Token
      return None
    user_id = data['id']
    return user_id

  @property
  def serialize(self):
    return {
      'id'       : self.id,
      'username' : self.username
    }

class Request(Base):
  __tablename__ = 'request'

  id = Column(Integer, primary_key=True)
  meal_type = Column(String) #Pizza
  location_string = Column(String(64))
  latitude = Column(String)
  longitude = Column(String)
  meal_time = Column(String(12)) #Breakfast, Lunch or Dinner
  filled = Column(Boolean)
  user_id = Column(Integer, ForeignKey('user.id'))
  user = relationship(User)

  @property
  def serialize(self):
    return {
      'id': self.id,
      'meal_type': self.meal_type,
      'location_string': self.location_string,
      'latitude': self.latitude,
      'longitude': self.longitude,
      'meal_time': self.meal_time,
      'filled': self.filled,
      'user_id': self.user_id
    }

class Proposal(Base):
  __tablename__ = 'proposal'

  id = Column(Integer, primary_key=True)
  user_proposed_to = Column(Integer)
  user_proposed_from = Column(Integer)
  filled = Column(Boolean)
  request_id = Column(Integer, ForeignKey('request.id'))
  request = relationship(Request)

  @property
  def serialize(self):
    return {
      'id': self.id,
      'user_proposed_to': self.user_proposed_to,
      'user_proposed_from': self.user_proposed_from,
      'filled': self.filled,
      'request_id': self.request_id
    }


class MealDate(Base):
  __tablename__ = 'mealdate'

  id = Column(Integer, primary_key=True)
  user_1 = Column(Integer) #Pizza
  user_2 = Column(Integer)
  restaurant_name = Column(String)
  restaurant_address = Column(String)
  meal_time = Column(String(12)) #Breakfast, Lunch or Dinner

  @property
  def serialize(self):
    return {
      'id': self.id,
      'user_1': self.user_1,
      'user_2': self.user_2,
      'restaurant_name': self.restaurant_name,
      'restaurant_address': self.restaurant_address,
      'meal_time': self.meal_time
    }


engine = create_engine('sqlite:///app.db')

Base.metadata.create_all(engine)

