#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
'''
This blog must have: 
1. Front page that lists entries 
2. Form to submit new entries 
3. Permalink page for entries 
'''
import os 
import re  #This is the regular expression library!
import webapp2
import jinja2
import string
import random
import hmac #for security, safer than using hashlib
import hashlib
from google.appengine.ext import db 


# This is all helper stuff....
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)


#REGEX:
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{5,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

#FUNCTINOS FOR CHECKING VALID INPUTS:

def valid_username(username):
		return username and USER_RE.match(username)
#The line above means the same as:
#	If there is a username, & it matches this regex, then return True 

def valid_password(password):
		return password and PASS_RE.match(password)

def valid_email(email):
		return not email or EMAIL_RE.match(email)


#SECURITY (hasing, passwords, salts, etc)
#safer, hmac hashing function:
def hash_str(s):
	return hmac.new(secret, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

#This uses the above 2 fns to determine is the value entered is correct
#(eg, did the password entered match that originally created)
def check_secure_val(h):
	s = h.split("|")[0]
	if h == make_secure_val(s):
		return s

#SECRET:
secret = "super_secrety_secret" 

#Adding the salt for security:
#How to implement password protection
def make_salt():
	salt = ''.join([random.choice(string.letters) for i in range(5)])
	return salt

#Now, making hash with the salt:
def make_hash_pw(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name+pw+salt).hexdigest()
	return "%s,%s" % (salt, h)
	#return "%s,%s" % (hf, s)

#Now it needs to be verified (and actually used). That is, 
#when user enters name & pw:
def valid_pw(name, pw, h):
	#salt = h.split(",")[1]
	salt = h.split(",")[0]
	return h == make_hash_pw(name, pw, salt)

#DB ENTRIES OF USERS:
def users_key(group= 'default'):
	return db.Key.from_path('users', group)

#Now, the user object which will be stored in the google datastre
class User(db.Model):
	name = db.StringProperty(required = True)
	#We dont store pws in our db, we store hash of passwords...
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()
#These are just methods for getting a user out of the db,
# by their name or their id. 
	
	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = cls.all().filter('name =', name).get()
		return u
		#This would be similar to:
		#Select * FROM user WHERE name = name
#Or: posts = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY timestamp DESC")?not exactly
		

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_hash_pw(name, pw)
		return cls(parent = users_key(),
					name = name, 
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def user_object_login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

#DB BLOG entries:  
def blog_key(name='dafault'):
	return db.Key.from_path('blogs', name)

class BlogEntry(db.Model):
	#user_id = db.StringProperty(required=True)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	timestamp = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def get_author(self):
		author  = User.by_id(self.user_id)
		return author.name

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)
###Careful with this.....
def render_str(*template, **params):
	t = jinja_env.get_template(*template)
	return t.render(**params)

#Defining the handler function:
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, *template, **params):
		t = jinja_env.get_template(*template)
		return t.render(**params)

	def render(self, *template, **params):
		return self.write(self.render_str(*template, **params))


	#Now, add code to set a cookie (go check notes on expiration)
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s = %s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)
#Change this to the second login_name? Nope- change the other login
# user_object_login
	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))


#########      ---- MAIN PAGE ----

class BlogFront(Handler):
	def get(self):
		#Previously used gql (now, gone back to this):
		#posts = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY timestamp DESC LIMIT 10")
		#Now, will use google's procedural language:
		posts = BlogEntry.all().order('-timestamp')
		if self.user:
			self.render("homepage.html", username=self.user.name, posts = posts)
		else:
			self.render("homepage.html", username="Guest", posts = posts)

'''
		username = self.request.get("name")
		if valid_username(username):
			self.render("homepage.html", username=username, posts = posts)

		else:
			self.render("homepage.html", posts = posts, username="Guest")
'''
########    ---REGISTRATION PAGE----
class SignUp(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False #If make it through the whole page with no errors,
		# then render the success page
		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")

		params = dict(username = self.username, email = self.email) 
		#This is for string substitution back into the signup form

		#Now, checking the signup form inputs: 
		if not valid_username(self.username):
			params["name_error"] = "That is not a valid username"
			have_error = True

		if not valid_password(self.password):
			params["password_error"] = "That is not a valid password"
			have_error = True

		elif self.password != self.verify:
			params["verify_error"] = "Your passwords do not match"
			have_error = True

		if not valid_email(self.email):
			params["email_error"] = "That is not a valid email address"
			have_error = True

		if have_error:
			self.render("signup.html", **params)
		else:
			#Well, we shouldn't be doing it this way, the username should 
			#be in a cookie....This is what we did, but change it cause of 
			#'register' class:self.redirect('/?username=' + username)
			self.done()


#  Register is descended from signup:
class Register(SignUp):
	def done(self):
		#First, we ensure that the user is not already registered in the db:
		u = User.by_name(self.username)
		if u:
			msg = 'Unfortunately this username already exists'
			self.render('signup.html', name_error = msg)
		else:
			#So, now if not a taken username, can add user to database:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			#All that login does is set the cookie
			self.redirect('/')

class Login(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.user_object_login(username, password)
		if u:
			self.login(u)
			self.redirect('/')
		else:
			msg = 'Invalid login'
			self.render("login.html", error = msg)

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/')




#Blog post page
class FormPage(Handler):
	def render_form(self, subject="", content="", error=""):
		self.render("blog_form.html", subject = subject, content = content, 
			error = error)

	def get(self):
		if self.user:
			self.render_form()
		else:self.redirect('/signup', name_error="Need to be registered and logged in to make a post")

	def post(self):
		if not self.user:
			self.redirect('/')

		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			b = BlogEntry(parent = blog_key(), user_id = self.user.key().id(), 
						  subject = subject, content = content)
			b.put()
			post_id = str(b.key().id())
			self.redirect("/blog/%s" % post_id, post_id=post_id)
		else:
			error = "To publish a blog post, both a subject, and content is required"
			self.render_form(subject, content, error)
#    ---- PARTICULAR POST -----

class PostPage(Handler):
	def get(self, post_id):
		key = db.Key.from_path('BlogEntry', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post, post_no = post_id)


app = webapp2.WSGIApplication([('/', BlogFront),
								('/form', FormPage),#Where you make a blog submission
								('/signup', Register),
								('/login', Login),
								('/logout', Logout),
								('/blog/([0-9]+)', PostPage)], debug = True)