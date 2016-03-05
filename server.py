#!/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import tornado.ioloop
import tornado.web
import tornado.escape
import tornado.options
from tornado.options import define, options
import logging


define("port", default=5000, type=int)
define("username", default="user")
define("password", default="pass")

class BaseHandler(tornado.web.RequestHandler):
  cookie_username = "username"

  def get_current_user(self):
    username = self.get_secure_cookie(self.cookie_username)
    logging.debug('BaseHandler - username: %s' % username)
    if not username: return None
    return tornado.escape.utf8(username)

  def set_current_user(self, username):
    self.set_secure_cookie(self.cookie_username, tornado.escape.utf8(username))

  def clear_current_user(self):
    self.clear_cookie(self.cookie_username)

class MainHandler(BaseHandler):
  @tornado.web.authenticated
  def get(self):
    self.write("Hello, <b>" + self.get_current_user() + "</b> <br> <a href=/auth/logout>Logout</a>")


class AuthLoginHandler(BaseHandler):
	def get(self):
		self.render("login.html")

	def post(self):
		logging.debug("xsrf_cookie:" + self.get_argument("_xsrf", None))

		self.check_xsrf_cookie()

		username = self.get_argument("username")
		password = self.get_argument("password")

		logging.debug('AuthLoginHandler:post %s %s' % (username, password))

		if username == options.username and password == options.password:
			self.set_current_user(username)
			self.redirect("/")
		else:
			self.write_error(403)

class AuthLogoutHandler(BaseHandler):
	def get(self):	
		self.clear_current_user()
		self.redirect('/')

class HomeHandler(tornado.web.RequestHandler):
  def get(self):
  	self.render("home.html")
class ActHandler(tornado.web.RequestHandler):
  def get(self):
  	self.render("activity.html")
class BlogHandler(tornado.web.RequestHandler):
  def get(self):
  	self.render("blog.html")
class LinkHandler(tornado.web.RequestHandler):
  def get(self):
    self.render("link.html")
class WikiHandler(tornado.web.RequestHandler):
  def get(self):
    self.render("wiki.html")

class Application(tornado.web.Application):
  def __init__(self):
    handlers = [
      (r"/home", HomeHandler),
      (r"/activity", ActHandler),
      (r"/blog", BlogHandler),
      (r"/link", LinkHandler),
      (r"/wiki", WikiHandler),
		  (r'/', MainHandler),
      (r'/auth/login', AuthLoginHandler),
      (r'/auth/logout', AuthLogoutHandler)
    ]
    settings = dict(
    	cookie_secret='gaofjawpoer940r34823842398429afadfi4iias',
    	static_path=os.path.join(os.path.dirname(__file__), "static"),
    	template_path=os.path.join(os.path.dirname(__file__), "templates"),
  		login_url="/auth/login",
   		xsrf_cookies=True,
    	autoescape="xhtml_escape",
    	debug=True,
    )
    tornado.web.Application.__init__(self, handlers, **settings)


def main():
  tornado.options.parse_config_file(os.path.join(os.path.dirname(__file__), 'server.conf'))
  tornado.options.parse_command_line()
  app = Application()
  app.listen(options.port)
  logging.debug('run on port %d in %s mode' % (options.port, options.logging))
  tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
  main()

