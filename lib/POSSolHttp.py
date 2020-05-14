#!/usr/bin/python
# POSSolHttp
#   Common HTTP functions used by Solace Tempale python scripts
#
# Ramesh Natarjan (Solace PSG) 
#
# May 30, 2016
#   Initial Version
#

import sys, os
import httplib, base64
import string, re
import xml.etree.ElementTree as ET
import logging, inspect

# import POSSol libs & Classes
#mypath = os.path.dirname(__file__)
#sys.path.append(mypath+"/lib")
sys.path.append(os.getcwd()+"/lib")
import POSSolXml as posxml

class POSSolHttp:
   'Solace HTTP connection implementation'

	#--------------------------------------------------------------
	# Constructor
	#--------------------------------------------------------------
   def __init__(self, me, host, user, passwd, url = '/SEMP'):
      self.m_logger = logging.getLogger(me)
      self.m_logger.enter ("%s::%s : %s %s %s", __name__, inspect.stack()[0][3], host, user, url)

      self.m_me = me
      self.m_host = host 
      self.m_user = user
      self.m_passwd = passwd
      self.m_url = url
      self.OpenHttpConnection()

   #-------------------------------------------------------
   # Connection related functions
   #
   def OpenHttpConnection(self):
      self.m_logger.enter ("%s::%s :", __name__, inspect.stack()[0][3])

      auth = string.strip(base64.encodestring(self.m_user+":"+self.m_passwd))
      self.m_hdrs = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
      self.m_hdrs["Authorization"] = "Basic %s" % auth
      self.m_logger.info("HTTP connection to :%s", self.m_host)
      self.m_logger.debug("Headers: %s", self.m_hdrs.items())
      try:
         self.m_conn = httplib.HTTPConnection(self.m_host)
      except httplib.InvalidURL as e:
         self.m_logger.exception(e)
	 raise
      except:
         self.m_logger.exception("Unexpected exception: %s", sys.exc_info()[0])
         raise
      return self.m_conn

   #-------------------------------------------------------
   # Post a req 
   #
   def Post(self, req):
      self.m_logger.enter ("%s::%s :", __name__,inspect.stack()[0][3])
      self.m_logger.trace ("request: %s", req)

      self.m_logger.debug ("URL: %s", self.m_url)
      self.m_conn.request("POST", self.m_url, req, self.m_hdrs)
      self.m_res = self.m_conn.getresponse()
      if not self.m_res:
         raise Exception ("No SEMP response")
      self.m_resp = self.m_res.read()
      if self.m_resp is None:
         raise Exception ("Null SEMP response")
         return None
      return self.m_resp
