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
from google.appengine.ext import db 


# This is all helper stuff....
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, *template, **params):
		t = jinja_env.get_template(*template)
		return t.render(**params)

	def render(self, *template, **params):
		return self.write(self.render_str(*template, **params))

#VALID INPUTS..

def valid_username(username):
		return username and USER_RE.match(username)
#The line above means the same as:
#	If there is a username, & it matches thes regex, then return True 

def valid_password(password):
		return password and PASS_RE.match(password)

def valid_email(email):
		return not email or EMAIL_RE.match(email)

#REGEX:
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{5,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


#########      ---- MAIN PAGE ----

class MainPage(Handler):
	def get(self):
		posts = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY timestamp DESC")

		username = self.request.get("username")
		if valid_username(username):
			self.render("homepage.html", username=username, posts = posts)

		else:
			self.render("homepage.html", posts = posts, username="Guest")


#db entries:  
def blog_key(name='dafault'):
	return db.Key.from_path('blogs', name)

class BlogEntry(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	timestamp = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

#Registration Page
class SignUp(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False #If make it through the whole page with no errors, then render the success page
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")

		params = dict(username = username, email = email) #This is for string substitution back into the signup form

		#Now, checking the signup form inputs: 
		if not valid_username(username):
			params["name_error"] = "That is not a valid username"
			have_error = True

		if not valid_password(password):
			params["password_error"] = "That is not a valid password"
			have_error = True

		elif password != verify:
			params["verify_error"] = "Your passwords do not match"
			have_error = True

		if not valid_email(email):
			params["email_error"] = "That is not a valid email address"
			have_error = True

		if have_error:
			self.render("signup.html", **params)
		else:
			self.redirect('/?username=' + username)




#Blog post page
class FormPage(Handler):
	def render_form(self, subject="", content="", error=""):
		self.render("form.html", subject = subject, content = content, error = error)

	def get(self):
		self.render_form()

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			b = BlogEntry(subject = subject, content = content)
			b.put()

			self.redirect("/")
		else:
			error = "To publish a blog post, both a subject, and content is required"
			self.render_form(subject, content, error)



app = webapp2.WSGIApplication([('/', MainPage),
								('/form', FormPage), #This is where you make a blog submission
								('/signup', SignUp)], debug = True)