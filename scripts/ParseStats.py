#!/usr/bin/python
# parsestats.py -- parse stats collected by possolmon.py
# Ramesh Natarajan, Solace PSG 
# Jul 07, 2016


import argparse
import sys, os
import logging, inspect
import getpass
import yaml
import time
# Import libraries
sys.path.append(os.getcwd()+"/lib")
import POSSolLogger as poslog
import POSSolSemp   as possemp
import POSSolHttp   as poshttp
import POSSolXml    as posxml

# Globals
me = "parsestats"

   #-----------------------------------------------------------------------------------
   # main
   #
def main(argv):

   global semp, vpn, log

   # setup & parse arguments
   p = argparse.ArgumentParser( prog=me)
   p.add_argument('--path', '-d', action="store", required=True, help='Dir with stats xml')
   p.add_argument('--vpn', action="store", required=False, help='VPNs to display stats')
   p.add_argument('-v','--verbose', action="count", help='Verbose mode (-vvv for debug)')
   r = p.parse_args()

   log = poslog.POSSolLogger(me, r.verbose).GetLogger()
   if log is None:
      raise Exception("Logger not defined")
   log.note("=== %s Starting", me)

   if not r.vpn:
      r.vpn = "all"

   try:

      #-----------------------------------------------------
      # message spool details
      #
      fname = r.path + "/ShowMsgSpoolDetails.xml"
      with open(fname, 'r') as f:
         xmlstr = f.read()
      f.close() 
      xml = posxml.POSSolXml(me, xmlstr)
      mss = xml.ParseMsgSpoolDetails()

      fname = r.path + "/ShowClientDetails.xml"
      with open(fname, 'r') as f:
         xmlstr = f.read()
      f.close() 
      xml = posxml.POSSolXml(me, xmlstr)
      msd = xml.ParseClientDetails()

      prh ('System Status')
      if mss['config-status'].find('Enabled') >= 0: 
         prs ("Status", mss['config-status'], 'OK')
      else:
         prs ("Status", mss['config-status'], '### Unknown ###')
      prt ("Active Disk Partition",
            float(mss['active-disk-partition-usage']), 100)
      prt ("Connections",
           int(msd['total-clients']), 9000)
      prt ("Egress flows",
           int(mss['active-flow-count']) + int(mss['inactive-flow-count']),
           int(mss['flows-allowed']))
      prt ("Ingress flows",
           int(mss['ingress-flow-count']),
           int(mss['ingress-flows-allowed']))
      prt ("Transacted Sessions",
           int(mss['transacted-sessions-used']),
           int(mss['max-transacted-sessions']))

      #-----------------------------------------------------
      # message spool stats
      #
      #fname = r.path + "/ShowMsgSpoolStats.xml"
      #with open(fname, 'r') as f:
      #   xmlstr = f.read()
      #f.close() 
      #xml = posxml.POSSolXml(me, xmlstr)
      #mss = xml.ParseMsgSpoolStats()

      #-----------------------------------------------------
      # vpn details
      #
      fname = r.path + "/ShowAllVpnDetails.xml"
      with open(fname, 'r') as f:
         xmlstr = f.read()
      f.close() 
      xml = posxml.POSSolXml(me, xmlstr)
      vpnds = xml.ParseAllVpnDetails()

      fname = r.path + "/ShowAllVpnSpoolDetails.xml"
      with open(fname, 'r') as f:
         xmlstr = f.read()
      f.close() 
      xml = posxml.POSSolXml(me, xmlstr)
      vpnsp = xml.ParseAllVpnSpoolDetails()
      for vpn in vpnds.keys():
	 if r.vpn != "all" and vpn != r.vpn:
	    continue
         if vpn == "default" or vpn == "#config-sync":
	    continue
         prh ('VPN Status : ' + vpn)
	 vpnd = vpnds[vpn] # vpn detail
	 vpns = vpnsp[vpn] # spool detail
         if vpnd['enabled'].find('true') >= 0 and \
	    vpnd['local-status'].find('Up') >= 0 and \
	    vpnd['operational'].find('true') >= 0: 
            prs ("Status", vpnd['enabled'], 'OK')
         else:
            prs ("Status", vpnd['enabled'], 'DOWN (Not enabled or local status/oper down')
         prt ("Connections",
           int(vpnd['connections']),
           int(vpnd['max-connections']))
         prt ("Subscriptions",
           int(vpnd['unique-subscriptions']),
           int(vpnd['max-subscriptions']))
         prt ("Endpoints",
           int(vpns['current-queues-and-topic-endpoints']),
           int(vpns['maximum-queues-and-topic-endpoints']))
         prt ("Spool",
           int(float(vpns['current-spool-usage-mb'])),
           int(float(vpns['maximum-spool-usage-mb'])))
         prt ("Transacted Sessions",
           int(vpns['current-transacted-sessions']),
           int(vpns['maximum-transacted-sessions']))
         prt ("Ingress flows",
           int(vpns['current-ingress-flows']),
           int(vpns['maximum-ingress-flows']))
         prt ("Egress flows",
           int(vpns['current-egress-flows']),
           int(vpns['maximum-egress-flows']))

   except Exception as e:
      log.exception(repr(e))
   except :
      log.exception("Unexpected exception: %s", sys.exc_info()[0])

def prh (h):
   print '\n'+h
   print '-------------------------------------------------------------------'
   print '{:30s} {:>10s} {:>10s} {:>6s}% {:10s}' .\
          format('Resource', 'Usage', 'Limit', '', 'Status')
   print '-------------------------------------------------------------------'

def prs (t, v, s):
   print '{:30s} {:>29s} {:10s}' . format(t, v, s)

def prt (t, v, vm):
   vp = 100.0*v/vm
   if vp > 80:
         s = 'CRITICAL'
   elif vp > 60:
         s = 'WARNING'
   else:
         s = 'OK'
   print '{:30s} {:10d} {:10d} {:6.2f}% {:10s}' . format(t, int(v), vm, vp, s)

#-----------------------------------------------------------------------------------
# Start main
#
if __name__ == "__main__":
   main(sys.argv[1:])
