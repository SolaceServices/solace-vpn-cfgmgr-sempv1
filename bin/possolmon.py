#!/usr/bin/python
#possolmon : Solace Monitor
# This file gathers solace snapshot stats for displays
#   supports gathering real-time stats with --host option
#   or re-displaying already stored stats with --dir option
#   (either --host or --dir option should be provided)
#
# Ramesh Natarajan, Solace PSG

import argparse
import sys, os
import logging, inspect
import getpass
import yaml
import time
import re
# Import libraries
sys.path.append(os.getcwd()+"/lib")
import POSSolLogger as poslog
import POSSolSemp   as possemp
import POSSolHttp   as poshttp
import POSSolStats  as posstat
import POSSolXml    as posxml

# Globals
me = "possolmon"
myver = "v0.8.1"

   #-----------------------------------------------------------------------------------
   # main
   #
def main(argv):

   global semp, log

   # setup & parse arguments
   p = argparse.ArgumentParser( prog=me)
   pr = p.add_argument_group("Connection Info")
   pr.add_argument('--host', action="store", required=False, help='Solace router name to get stats (real-time)')
   pr.add_argument('--vpn', action="store", required=True, help='VPN to gather stats. Use all for everything')
   pr.add_argument('--dir', action="store", dest="dirs", required=False, help='Dir with stats XML (not real-time)')

   po = p.add_argument_group("Optional")
   po.add_argument('--user', dest="username", default="admin", help='CLI username (default: admin)')
   po.add_argument('--password', help='CLI user Password (default: <read from stdin>)') 
   po.add_argument('--compact', '-c', action="store_true", required=False, default=False, help='Compact display')
   po.add_argument('-v','--verbose', action="count", help='Verbose mode (-vvv for debug)')
   r = p.parse_args()

   log = poslog.POSSolLogger(me, r.verbose).GetLogger()
   if log is None:
      raise Exception("Logger not defined")
   log.note("=== %s (%s) Starting", me, myver)
   log.debug ("args %s", r)

   if (not r.host and not r.dirs):
      log.error ("Either host or dirs argument should me suppled")
      exit

   if (r.host):
      if (not r.password):
         r.password = getpass.getpass("Enter password for "+ r.username+ " : ")

   try:
      vpn = r.vpn 
      vpns = [vpn]
      if (r.host):
         # create http connection object
         http = poshttp.POSSolHttp(me, r.host, r.username, r.password)
   
         # create semp object
         semp = possemp.POSSolSemp(me, http)
   
         semp.GetSystemStats(vpn)
         #files =  semp.ReqRespXmlFiles()
         #paths = [os.path.dirname(files[1])]
   
         # this gets VPN stats response XML
         if vpn == 'all':
            semp.GetAllVpnStats()
         else:
            semp.GetVpnStats(vpn)
         files =  semp.ReqRespXmlFiles()
         path = os.path.dirname(files[1])
         #paths.append(os.path.dirname(files[1]))
         log.debug ("Paths (calc): %s", path)
      else:
         path = r.dirs
         log.debug ("Paths (args): %s", path)

      log.note('Response Dir: %s', path)
      stat = posstat.POSSolStats(me, path, r.compact)
      stat.SystemStats()

      if vpn == 'all':
         rxml = posxml.POSSolXml(me, None, path + '/ShowSpoolDetails.xml')
         rxml.BasePath('./rpc/show/message-spool/message-vpn/vpn')
         vpns = rxml.FindAll('/name')
         log.info ("VPN names: %s", vpns)
      for vpn in vpns:
          # skip non application vpns
         if re.search('default|MGMT_VPN|config-sync',vpn):
             continue
         stat.VpnStats(vpn)
         stat.VpnQueueStats(vpn)
         stat.VpnClientUserStats(vpn)
         stat.VpnBridgeStats(vpn)
      stat.cleanup()

   except Exception as e:
      log.exception(repr(e))
   except :
      log.exception("Unexpected exception: %s", sys.exc_info()[0])


#-----------------------------------------------------------------------------------
# Start main
#
if __name__ == "__main__":
   main(sys.argv[1:])
