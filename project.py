from models import Base, User, Request, Proposal, MealDate
from flask import Flask, jsonify, request, url_for, abort, g
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from geocode import getGeocodeLocation
from findARestaurant import findARestaurant


import time
from functools import update_wrapper
from redis import Redis
redis = Redis()

from flask import Flask
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

engine = create_engine('sqlite:///app.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()
app = Flask(__name__)

#0
#RATE LIMITING
#-------------------------------------------------------------------------------------------
class RateLimit(object):
	expiration_window = 10

	def __init__(self, key_prefix, limit, per, send_x_headers):
		self.reset = (int(time.time()) // per) * per + per
		self.key = key_prefix + str(self.reset)
		self.limit = limit
		self.per = per
		self.send_x_headers = send_x_headers
		p = redis.pipeline()
		p.incr(self.key)
		p.expireat(self.key, self.reset + self.expiration_window)
		self.current = min(p.execute()[0], limit)

	remaining = property(lambda x: x.limit - x.current)
	over_limit = property(lambda x: x.current >= x.limit)

def get_view_rate_limit():
	return getattr(g, '_view_rate_limit', None)

def on_over_limit(limit):
	return (jsonify({'data':'You hit the rate limit',
		'error':'429'}), 429)

def ratelimit(limit, per=300, send_x_headers=True,
	over_limit=on_over_limit,
	scope_func=lambda:request.remote_addr,
	key_func=lambda: request.endpoint):
	def decorator(f):	
		def rate_limited(*args, **kwargs):
			key = 'rate-limit/%s/%s' % (key_func(), scope_func())
			rlimit = RateLimit(key, limit, per, send_x_headers)
			if over_limit is not None and rlimit.over_limit:
				return over_limit(rlimit)
			return f(*args, **kwargs)
		return update_wrapper(rate_limited, f)
	return decorator

@app.after_request
def inject_x_rate_header(response):
	limit = get_view_rate_limit()
	if limit and limit.send_x_headers:
		h = response.headers
		h.add('X-RateLimit-Remaning', str(limit.remaining))
		h.add('X-RateLimit-Limit', str(limit.limit))
		h.add('X-RateLimit-Reset', str(limit.reset))
	return response


@app.route('/rate-limited')
@ratelimit(limit=300, per=30 * 1)
def index():
	return jsonify({'response':'This is a rate rate-limited response'})
#-------------------------------------------------------------------------------------------


#0
#AUTHENTICATION AND AUTHORIZATION
#-------------------------------------------------------------------------------------------
@auth.verify_password
def verify_password(username_or_token, password):
  user_id = User.verify_auth_token(username_or_token)
  if user_id:
    user = session.query(User).filter_by(id = user_id).one()
  else:
  	user = session.query(User).filter_by(username = username_or_token).first()
  	if not user or not user.verify_password(password):
  		return False
  g.user = user;
  return True
#-------------------------------------------------------------------------------------------


#1
#USER PART
#-------------------------------------------------------------------------------------------
@app.route('/api/v1/login')
@ratelimit(limit=300, per=30 * 1)
@auth.login_required
def get_auth_token():
	token = g.user.generate_auth_token()
	return jsonify({'token': token.decode('ascii')})


@app.route('/api/v1/users', methods = ['POST'])
@ratelimit(limit=300, per=30 * 1)
def new_user():
	username = request.json.get('username')
	password = request.json.get('password')
	if username is None or password is None:
	    abort(400) # missing arguments
	if session.query(User).filter_by(username = username).first() is not None:
	    abort(400) # existing user
	user = User(username = username)
	user.hash_password(password)
	session.add(user)
	session.commit()
	return jsonify({ 'username': user.username }), 201


@app.route('/api/v1/users', methods = ['GET', 'PUT', 'DELETE'])
@ratelimit(limit=300, per=30 * 1)
@auth.login_required
def users_function():
	if request.method == 'GET':
		users = session.query(User).all()
		return jsonify(AllUsers=[user.serialize for user in users]), 200

	if request.method == 'PUT':
		username = request.json.get('username')
		password = request.json.get('password')
		if username is None and password is None:
			abort(400) # No argument
		if username:
			g.user.username = username
		if password:
			g.user.password = password
			g.user.hash_password(password)
		session.add(g.user)
		session.commit()
		return jsonify({ 'updated_username': g.user.username }), 202

	if request.method == 'DELETE':
		session.delete(g.user)
		session.commit()
		return jsonify({ 'deleted_username': g.user.username }), 202


@app.route('/api/v1/users/<int:id>')
@ratelimit(limit=300, per=30 * 1)
@auth.login_required
def get_user(id):
    user = session.query(User).filter_by(id = id).one()
    if not user:
        abort(400)
    return jsonify(user.serialize), 200
#-------------------------------------------------------------------------------------------


#2
#REQUEST PART
#-------------------------------------------------------------------------------------------
@app.route('/api/v1/requests', methods = ['GET', 'POST'])
@ratelimit(limit=300, per=30 * 1)
@auth.login_required
def requests_function():
	if request.method == 'GET':
		requests = session.query(Request).filter(Request.user_id != g.user.id).all()
		return jsonify(OpenRequests=[item.serialize for item in requests]), 200

	if request.method == 'POST':
		meal_type = request.json.get('meal_type')
		location_string = request.json.get('location_string')
		meal_time = request.json.get('meal_time')
		latitude, longitude = getGeocodeLocation(location_string)
		if meal_type is None or location_string is None or meal_time is None:
		    abort(400) # missing arguments
		request_item = Request(meal_type = meal_type, location_string = location_string, meal_time = meal_time,
			latitude = latitude, longitude = longitude, filled = False, user_id = g.user.id)
		session.add(request_item)
		session.commit()
		return jsonify(request_item.serialize), 201


@app.route('/api/v1/requests/<int:id>', methods = ['GET', 'PUT', 'DELETE'])
@ratelimit(limit=300, per=30 * 1)
@auth.login_required
def request_function(id):
	if request.method == 'GET':
		req = session.query(Request).filter_by(id = id).one()
		return jsonify(req.serialize), 200

	if request.method == 'PUT':
		current_request = session.query(Request).filter_by(id = id, user_id = g.user.id).one()

		if current_request is None:
			print "You cannot edit someone else's request"
			abort(400) # Not owner
		meal_type = request.json.get('meal_type')
		location_string = request.json.get('location_string')
		meal_time = request.json.get('meal_time')

		if meal_type is None and location_string is None and meal_time is None:
		    abort(400) # No argument
		if meal_type:
			current_request.meal_type = meal_type
		if location_string:
			current_request.location_string = location_string
			latitude, longitude = getGeocodeLocation(location_string)
			current_request.latitude = latitude
			current_request.longitude = longitude
		if meal_time:
			current_request.meal_time = meal_time

		session.add(current_request)
		session.commit()
		return jsonify(current_request.serialize), 202

	if request.method == 'DELETE':
		current_request = session.query(Request).filter_by(id = id, user_id = g.user.id).one()

		if current_request is None:
			print "You cannot edit someone else's request"
			abort(400) # Not owner

		session.delete(current_request)
		session.commit()
		return jsonify({"Deleted": "True"}), 202
#-------------------------------------------------------------------------------------------


#3
#PROPOSAL PART
#-------------------------------------------------------------------------------------------
@app.route('/api/v1/proposals', methods = ['GET', 'POST'])
@ratelimit(limit=300, per=30 * 1)
@auth.login_required
def propals_function():
	if request.method == 'GET':
		# current_user_proposals_from = session.query(Proposal).filter_by(user_proposed_from = g.user.id).all()
		# current_user_proposals_to = session.query(Proposal).filter_by(user_proposed_to = g.user.id).all()
		current_user_proposals = session.query(Proposal).filter((Proposal.user_proposed_from == g.user.id) |
			(Proposal.user_proposed_to == g.user.id)).all()
		return jsonify(YourProposals=[current_user_proposal.serialize for current_user_proposal in current_user_proposals]), 200
	
	if request.method == 'POST':
		user_proposed_from = g.user.id
		request_id = request.json.get('request_id')

		current_request = session.query(Request).filter_by(id = request_id).one()

		if request_id is None or current_request is None:
			abort(400) # Missing arguments or No request with that id

		user_proposed_to = current_request.user_id

		if user_proposed_to == user_proposed_from:
			print "You cannot proposal to your own requests!"
			abort(400) # Both cannot be same user
		
		proposal = Proposal(user_proposed_from = user_proposed_from, user_proposed_to = user_proposed_to, 
			filled = False, request_id = current_request.id)
		session.add(proposal)
		session.commit()
		return jsonify(proposal.serialize), 201


@app.route('/api/v1/proposals/<int:id>', methods = ['GET', 'PUT', 'DELETE'])
@ratelimit(limit=300, per=30 * 1)
@auth.login_required
def propal_function(id):
	if request.method == 'GET':
		proposal = session.query(Proposal).filter(Proposal.id == id,
			(Proposal.user_proposed_from == g.user.id) | (Proposal.user_proposed_to == g.user.id)).first()
		
		if proposal is None:
			print "You don't have permission to access this proposal"
			abort(400)
		return jsonify(proposal.serialize), 200
		

	if request.method == 'PUT':
		current_proposal = session.query(Proposal).filter_by(id = id, user_proposed_from = g.user.id).first()

		if current_proposal is None:
			print "You cannot edit someone else's proposal"
			abort(400) # Not owner
		
		request_id = request.json.get('request_id')
		current_request = session.query(Request).filter_by(id = request_id).first()

		if request_id is None or current_request is None:
			abort(400) # Missing argument or No request with that id

		current_proposal.request_id = request_id
		current_proposal.user_proposed_to = current_request.user_id

		if current_proposal.user_proposed_to == current_proposal.user_proposed_from:
			print "You cannot proposal to your own requests!"
			abort(400) # Both cannot be same user
		
		session.add(current_proposal)
		session.commit()
		return jsonify(current_proposal.serialize), 202

	if request.method == 'DELETE':
		current_proposal = session.query(Proposal).filter_by(id = id).first()

		if current_proposal is None:
			abort(400) # Not owner

		session.delete(current_proposal)
		session.commit()
		return jsonify({"Deleted": "True"}), 202
#-------------------------------------------------------------------------------------------


#4 (LAST)
#MealDate PART
#-------------------------------------------------------------------------------------------
@app.route('/api/v1/dates', methods = ['GET', 'POST'])
@ratelimit(limit=300, per=30 * 1)
@auth.login_required
def dates_function():
	if request.method == 'GET':
		all_dates = session.query(MealDate).filter((MealDate.user_1 == g.user.id) | (MealDate.user_2 == g.user.id))
		return jsonify(AllDates=[date.serialize for date in all_dates])

	if request.method == 'POST':
		
		current_proposal = session.query(Proposal).filter_by(user_proposed_to = g.user.id).first()
		current_request = session.query(Request).filter_by(id = current_proposal.request_id).first()
		
		user_1 = g.user.id
		user_2 = current_proposal.user_proposed_from

		accepted = request.json.get('accepted')

		if accepted == "False":
			session.delete(current_proposal)
			session.commit()
			return jsonify({"Status": "Rejected"}), 202
		
		restaurantJSON = findARestaurant(current_request.meal_type, current_request.location_string)
		restaurant_name = restaurantJSON.get('name')
		restaurant_address = restaurantJSON.get('address')
		date = MealDate(user_1 = user_1, user_2 = user_2, restaurant_name = restaurant_name, 
			restaurant_address = restaurant_address, meal_time = current_request.meal_time)

		session.add(date)
		session.commit()
		return jsonify(date.serialize), 201


@app.route('/api/v1/dates/<int:id>', methods = ['GET', 'PUT', 'DELETE'])
@ratelimit(limit=300, per=30 * 1)
@auth.login_required
def date_function(id):
	if request.method == 'GET':
		meal_date = session.query(MealDate).filter(MealDate.id == id, (MealDate.user_1 == g.user.id) | 
			(MealDate.user_2 == g.user.id)).first()
		
		if meal_date is None:
			print "You don't have permission to access this proposal"
			abort(400)
		return jsonify(meal_date.serialize), 200
		

	if request.method == 'PUT':
		meal_date = session.query(MealDate).filter(MealDate.id == id, (MealDate.user_1 == g.user.id) | 
			(MealDate.user_2 == g.user.id)).first()

		if meal_date is None:
			print "You cannot edit someone else's proposal"
			abort(400) # Not owner
		
		meal_time = request.json.get('meal_time')

		if meal_time is None:
			abort(400) # Missing argument

		meal_date.meal_time = meal_time
		
		session.add(meal_date)
		session.commit()
		return jsonify(meal_date.serialize), 202

	if request.method == 'DELETE':
		meal_date = session.query(MealDate).filter(MealDate.id == id, (MealDate.user_1 == g.user.id) | 
			(MealDate.user_2 == g.user.id)).first()

		if meal_date is None:
			abort(400) # No date with that id

		session.delete(meal_date)
		session.commit()
		return jsonify({"Deleted": "True"}), 202
#-------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------
if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port = 5000)
#-------------------------------------------------------------------------------------------