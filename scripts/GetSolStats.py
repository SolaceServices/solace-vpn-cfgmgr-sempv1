#!/usr/bin/python
# GetSolStats.py
#
# ABOUT
# Issue SEMP Requesst to get stats form Solace Router/VMR
# Generate CSV file with the following info:
#    TIMESTAMP
#    INGRESS_MSG_RATE
#    EGRESS_MSG_RATE
#    INGRESS_BYTES_RATE
#    EGRESS_BYTES_RATE
#    INGRESS_DISCARDS
#    EGRESS_DISCARDS
#
# LIMITATIONS
#  Not much error checking done
#  Tested for SolTR 7.1.1 & 7.2 only
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

      dprint ("Posting to URL %s" % url)
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
      vprint ("   Reading file: %s" % sempfile )
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
pr.add_argument('--id', action='store', required=True, help='Test ID')
pr.add_argument('--url', action='store', required=True, help='Router/VPN URL in IP:PORT')
pr.add_argument('--vpn', action='store', required=True, help='VPN Name')
p.add_argument('--user', action='store', default='admin', help='Admin CLI username (default: admin)')
p.add_argument('--passwd', action='store', default='admin', help='CLI password (default: admin)')
p.add_argument('--outdir', action='store', default='out', help='Dir for output (default: out)')
p.add_argument('--sempdir', action='store', default='SEMP/Templates', help='SEMP template dir (default: SEMP/Templates)')
p.add_argument('--sempver', action='store', default='7_2', help='SEMP Version (default: 7_2)')
p.add_argument('--interval', action='store', default='5', help='Sampling interval (default: 5 seconds)')
p.add_argument('--samples', action='store', default='10', help='Max samples (default: 10)')
p.add_argument('-v','--verbose', action='count', help='Verbose mode (-vvv for debug)')

r = p.parse_args()
Verbose = r.verbose
SEMP_DIR = r.sempdir
SEMP_VERSION = r.sempver
nap = float(r.interval)

#--------------------------------------------------------------------
# Parse SEMP response file
#
#print ('Processing SEMP output file %s' % r.file)
#with open(r.file, 'r') as fd_semp:
#    xmlstr = fd_semp.read()
#fd_semp.close()

# Open HTTP connection to router and get the SEMP directly
Conn = open_http (r.url, r.user, r.passwd)
#print ("Sending 'show all client message-spool detail' for vpn: %s" % r.vpn)
#semp_req = '<rpc semp-version="soltr/%s"> <show> <client> <name>*</name> <vpn-name>%s</vpn-name> <message-spool></message-spool> <detail></detail> </client> </show> </rpc>' % (SEMP_VERSION, r.vpn)
#dprint ("SEMP Req: %s" % semp_req)
#semp_resp = post_http (semp_req)
#dprint ("SEMP RESPONSE (1) : %s" % semp_resp)

#semp_req = read_semp_req ('show/version.xml')  % (SEMP_VERSION)
#dprint ("SEMP Req: %s" % semp_req)
#semp_resp = post_http (semp_req)
#dprint ("SEMP RESPONSE (2): %s" % semp_resp)

#semp_req = read_semp_req ('show/client_stats.xml')  % (SEMP_VERSION)
#dprint ("SEMP REQUEST (client stats): %s" % semp_req)
#semp_resp = post_http (semp_req)
#dprint ("SEMP RESPONSE (client stats): %s" % semp_resp)


# open CSV output file
#csvfile = "%s/client_info_%s.csv" % (r.outdir, re.sub('[\.:]','_',r.url))
csvfile = "%s/sol_stats_%s.csv" % (r.outdir, r.id)
print ('Writing to CSV file %s' % csvfile)
stats = {}
# Write header to CSV file
if not os.path.exists(csvfile):
   with open(csvfile, 'w') as fd_csv:
    print >>fd_csv, "#ID:%s" % (r.id)
    print >>fd_csv, "%s,%s,%s,%s,%s,%s,%s,%s" % ('TIMESTAMP',\
                                              'INGRESS_MSG_RATE',\
                                              'EGRESS_MSG_RATE',\
                                              'INGRESS_BYTES_RATE',\
                                              'EGRESS_BYTES_RATE',\
                                              'INGRESS_DISCARDS',\
                                              'EGRESS_DISCARDS',\
                                              'MSGS_SPOOLED')
   fd_csv.close()

# Gather and save stats
vprint ("Collecting %s stats every %s seconds" % (r.samples, nap))
n = 0
while (n < int(r.samples)):
   stats['timestamp'] = time.strftime("%Y%m%d %H:%M:%S")
   print ("%-3d/%-3s) %s" % (n+1, r.samples, stats['timestamp']))

   # Post SEMP Request -- vpn_stats
   print ('   Processing SEMP Request %s' % 'show/vpn_stats.xml')
   semp_req = read_semp_req ('show/vpn_stats.xml')  % (SEMP_VERSION, r.vpn)
   dprint ("SEMP REQUEST (VPN stats): %s" % semp_req)
   semp_resp = post_http (semp_req)

   # Save SEMP response
   dprint ("SEMP RESPONSE (VPN stats): %s" % semp_resp)
   respfile = "%s/vpn_stats_%s.xml" % ('out/semp', time.strftime("%Y%m%d_%H%M%S"))
   vprint ('   Writing SEMP Response to file %s' % respfile)
   with open(respfile, 'w') as fd_semp:
      print >>fd_semp, semp_resp
   fd_semp.close()

   # Process SEMP Reponse XML
   xmlroot = ET.fromstring(semp_resp)
   en_stats = './rpc/show/message-vpn/vpn/stats'
   e_stats = xmlroot.find(en_stats)
   for tag in ['current-ingress-rate-per-second', \
                'current-egress-rate-per-second', \
                'current-ingress-byte-rate-per-second', \
                'current-egress-byte-rate-per-second', \
                'ingress-discards/total-ingress-discards', \
                'egress-discards/total-egress-discards' ]:
       stats[tag] = e_stats.find(tag).text
       vprint ("   %-40s: %s" % (tag, stats[tag]))

   # Post SEMP Request -- vpn spool stats
   print ('   Processing SEMP Request %s' % 'show/vpn_spool_stats.xml')
   semp_req = read_semp_req ('show/vpn_spool_stats.xml')  % (SEMP_VERSION, r.vpn)
   dprint ("SEMP REQUEST (VPN spool stats): %s" % semp_req)
   semp_resp = post_http (semp_req)

   # Save SEMP response
   dprint ("SEMP RESPONSE (VPN spool stats): %s" % semp_resp)
   respfile = "%s/vpn_spool_stats_%s.xml" % ('out/semp', time.strftime("%Y%m%d_%H%M%S"))
   vprint ('   Writing SEMP Response to file %s' % respfile)
   with open(respfile, 'w') as fd_semp:
      print >>fd_semp, semp_resp
   fd_semp.close()
   # Process SEMP Reponse XML
   xmlroot = ET.fromstring(semp_resp)
   en_stats = './rpc/show/message-spool/message-spool-stats'
   e_stats = xmlroot.find(en_stats)
   for tag in ['spooled-to-adb' ]:
       stats[tag] = e_stats.find(tag).text
       vprint ("   %-40s: %s" % (tag, stats[tag]))

   # Post SEMP Request -- vpn spool detail
   print ('   Processing SEMP Request %s' % 'show/vpn_spool_detail.xml')
   semp_req = read_semp_req ('show/vpn_spool_detail.xml')  % (SEMP_VERSION, r.vpn)
   dprint ("SEMP REQUEST (VPN spool stats): %s" % semp_req)
   semp_resp = post_http (semp_req)

   # Save SEMP response
   dprint ("SEMP RESPONSE (VPN spool stats): %s" % semp_resp)
   respfile = "%s/vpn_spool_detail_%s.xml" % ('out/semp', time.strftime("%Y%m%d_%H%M%S"))
   vprint ('   Writing SEMP Response to file %s' % respfile)
   with open(respfile, 'w') as fd_semp:
      print >>fd_semp, semp_resp
   fd_semp.close()
   # Process SEMP Reponse XML
   xmlroot = ET.fromstring(semp_resp)
   en_stats = './rpc/show/message-spool/message-vpn/vpn'
   e_stats = xmlroot.find(en_stats)
   for tag in ['current-messages-spooled']:
       stats[tag] = e_stats.find(tag).text
       vprint ("   %-40s: %s" % (tag, stats[tag]))

   # Append stats to CSV file
   with open(csvfile, 'a') as fd_csv:
       print >>fd_csv, "%s,%s,%s,%s,%s,%s,%s,%s" % (stats['timestamp'],
                                          stats['current-ingress-rate-per-second'], \
                                          stats['current-egress-rate-per-second'], \
                                          stats['current-ingress-byte-rate-per-second'], \
                                          stats['current-ingress-byte-rate-per-second'], \
                                          stats['ingress-discards/total-ingress-discards'], \
                                          stats['egress-discards/total-egress-discards'], \
                                          stats['current-messages-spooled'], \
                                          )
   
       dprint (stats )
       time.sleep(nap)
   n = n+1
fd_csv.close()       
