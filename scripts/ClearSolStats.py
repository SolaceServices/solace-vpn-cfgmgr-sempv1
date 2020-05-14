#!/usr/bin/python
#ClearSolStats.py
#
# ABOUT
# Issue SEMP Requesst to clear Solace stats form the Router/VMR
#
# HISTORY
# - Nov 29, 2016: nram (Solace PSG)
#   Initial version

import argparse
import xml.etree.ElementTree as ET
import httplib, base64
import string, re
import time
import os.path

Verbose = 0

#----------------------------------------------------------------------------
# some log helpers
# TODO: use logger instead
#
def vprint (s):
    global Verbose
    if Verbose > 0:
        print s

def dprint (s):
    global Verbose
    if Verbose > 2:
        print '---\n', s

#----------------------------------------------------------------------------
# HTTP utils
# TODO: move to a lib
#
def open_http( url, user, passwd):
      global Hdrs
      auth = string.strip(base64.encodestring(user+":"+passwd))
      Hdrs = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
      Hdrs["Authorization"] = "Basic %s" % auth
      print ("Opening HTTP connection to [%s]" % url)
      dprint ("Headers: %s" % Hdrs.items())
      try:
         conn = httplib.HTTPConnection(url)
      except httplib.InvalidURL as e:
         print (e)
	 raise
      except:
         print ("Unexpected exception: %s" % sys.exc_info()[0])
         raise
      return conn

def post_http (req, url = '/SEMP'):
      global Hdrs
      dprint ("request: %s" % req)

      vprint ("Posting to URL %s" % url)
      Conn.request("POST", url, req, Hdrs)
      res = Conn.getresponse()
      if not res:
         raise Exception ("No SEMP response")
      resp = res.read()
      if resp is None:
         raise Exception ("Null SEMP response")
         return None
      return resp
      
#------------------------------------------------------------------------
# SEMP helpers
#
def read_semp_req(fname):
      global SEMP_VERSION
      global SEMP_DIR
      sempfile = "%s/%s/%s" % (SEMP_DIR, SEMP_VERSION, fname)
      vprint ("Reading SEMP request template file: %s" % sempfile )
      try:
         f = open(sempfile , 'r')
         if not f:
           raise Exception('Unable to open file', sempfile )
         req = f.read()
         dprint ("SEMP req template = %s" % req)
         f.close()
         return req
      except IOError as e:
        print (e)
	raise e
      except:
        print ('Unexpected exception %s' % sys.exc_info()[0])
	raise

#--------------------------------------------------------------------------------------
# Main
#--------------------------------------------------------------------------------------
p = argparse.ArgumentParser ()
pr = p.add_argument_group("Required Arguments")
pr.add_argument('--url', action='store', required=True, help='Router/VPN URL in IP:PORT')
pr.add_argument('--vpn', action='store', required=True, help='VPN Name')
p.add_argument('--user', action='store', default='admin', help='Admin CLI username (default: admin)')
p.add_argument('--passwd', action='store', default='admin', help='CLI password (default: admin)')
p.add_argument('--sempdir', action='store', default='SEMP/Templates', help='SEMP template dir (default: SEMP/Templates)')
p.add_argument('--sempver', action='store', default='7_2', help='SEMP Version (default: 7_2)')
p.add_argument('-v','--verbose', action='count', help='Verbose mode (-vvv for debug)')

r = p.parse_args()
Verbose = r.verbose
SEMP_DIR = r.sempdir
SEMP_VERSION = r.sempver

# Open HTTP connection to router and get the SEMP directly
Conn = open_http (r.url, r.user, r.passwd)

for xmlfile in ['clear/ClearMsgVpnStats.xml',\
                'clear/ClearMsgVpnSpoolStats.xml',\
                'clear/ClearClientStats.xml']:
   print "Processing Request file: %s" % (xmlfile)
   semp_req = read_semp_req (xmlfile) % (SEMP_VERSION, r.vpn)
   dprint ("SEMP Req: %s" % semp_req)
   semp_resp = post_http (semp_req)
   dprint ("SEMP RESPONSE (2): %s" % semp_resp)
   #  save the SEMP response
   respfile = "%s/%s_%s.xml" % ('out/semp', re.sub ('[/\.]', '_', xmlfile), time.strftime("%Y%m%d_%H%M%S"))
   vprint ('Writing SEMP Response to file %s' % respfile)
   with open(respfile, 'w') as fd_semp:
       print >>fd_semp, semp_resp
   fd_semp.close()
