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
import webapp2
import jinja2
import string
import random
from google.appengine.ext import db 

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



#main page
class MainPage(Handler):
	def get(self):
		posts = db.GqlQuery("SELECT * FROM BlogEntry ORDER BY timestamp DESC")

		self.render("homepage.html", posts = posts)

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
								('/form', FormPage),
								('/signup', SignUp)], debug = True)