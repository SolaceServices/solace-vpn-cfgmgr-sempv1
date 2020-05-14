#!/usr/bin/python
# possoladm : Solace Admin 
# This file implements following admin functions:
#    enable / disable objects (like VPN, Queues)
#    purge queues
#    clear VPN and appliance stats
#    export vpn config from the appliance
#
# Ramesh Natarajan, Solace PSG

import sys, os
import getpass
import argparse
import logging, inspect
import textwrap
import time
import yaml
# Import libraries
sys.path.append(os.getcwd()+"/lib")
import POSSolLogger as poslog
import POSSolYaml   as posyaml
import POSSolHttp   as poshttp
import POSSolSemp   as possemp

# Globals
me = "possoladm"
myver = "v0.8.1"

#--------------------------------------------------------------
# main
#--------------------------------------------------------------
def main(argv):
   global logger

   # setup arguments
   p = argparse.ArgumentParser( prog=me,
   	description='possoladm : Solace Admin tool',
        formatter_class=argparse.RawDescriptionHelpFormatter)

   #pr = p.add_argument_group('Required')
   
   # Required args
   pr = p.add_argument_group("Connection Info")
   pr.add_argument('--host', action="store", required=True, help='Solace router name')

   # Optional args
   po = p.add_argument_group("Actions")
   po.add_argument('--enable', action="store_true", help='Enable objects (no shutdown)')
   po.add_argument('--disable', action="store_true", help='Disable objects (shutdown)')
   po.add_argument('--purge', action="store_true", help='Purge messages (Q/DTE only)')
   po.add_argument('--clearstats', action="store_true", help='Purge messages (Q/DTE only)')
   po.add_argument('--export', action="store_true", help='export vpn config from the appliance')
   po.add_argument('--force', action="store_true", help='Ignore errors *** USE WITH CAUTION ***')

   po = p.add_argument_group("Objects")
   po.add_argument('--vpn', action='store', nargs="+", required=True, help='VPN names')
   po.add_argument('--system', action='store_true', help='Apply to system (eg: clear)')
   po.add_argument('--clientusers', action='store', nargs='+', help='List of Clients')
   po.add_argument('--queues', action='store', nargs='+', help='List of Queues')
   po.add_argument('--bridges', action='store', nargs='+', help='List of Bridges')
   po.add_argument('--jndi', action='store', nargs='+', help='List of JNDI objects')
   po.add_argument('--all', action='store_true', help='All VPN objects')

   po = p.add_argument_group("Optional")
   po.add_argument('--user', dest="username", default="admin", help='CLI username (default: admin)')
   po.add_argument('--password', help='CLI user Password (default: <read from stdin>)') 
   po.add_argument('--env', action='store', help='DC or env for file prefix (default: hostname)')
   po.add_argument('-v','--verbose', action="count", help='Verbose mode: -v verbose, -vv debug, -vvv trace')

   # parse and validate args
   r = p.parse_args()

   if not (r.enable or r.disable or r.purge or r.clearstats or r.export):
       print (me +' Missing Argument: No Action argument')
       sys.exit(0)

   if not (r.vpn or r.clientusers or r.queues or r.bridges or r.jndi):
       print (me +' Missing Argument: No Object argument')
       sys.exit(0)

   if r.purge and not r.queues:
      print ("Purge can be used only with Queues")
      sys.exit(0)

   if r.system and not r.clearstats:
      print ("Router scope (--system) applies only to clear operation")
      sys.exit(0)

   if r.env:
       env = r.env
   else:
       env = r.host
   #if r.export and not r.env:
   #   print "Export requires env argument"
   #   sys.exit(0)

   if r.force:
      yn = raw_input('Ignore errors and continue with force flag (y/N) ?')
      if yn != "y":
        sys.exit(0)

   # initialize logging
   log = poslog.POSSolLogger(me, r.verbose).GetLogger()
   if log is None:
      raise Exception("Logger not defined")
   log.note("=== %s (%s) Starting", me, myver)
   log.debug ("args %s", r)
   log.debug("env : %s", env)

   # set traceback limit based on verbosity
   sys.tracebacklimit = 0
   if r.verbose:
      sys.tracebacklimit = int(r.verbose)

   if r.vpn and r.vpn[0] == 'all':
       log.error ("--vpn all not supported. Pl list VPNs individually")
       sys.exit(0)

   # If password not passed, read from stdin
   if (not r.password):
      r.password = getpass.getpass("Enter password for "+ r.username+ " : ")
   
   try:

      # create http connection object
      http = poshttp.POSSolHttp(me, r.host, r.username, r.password)

      # create semp object
      semp = possemp.POSSolSemp(me, http)

      # ---------------------------------------------------------
      # disable
      #
      if r.disable:
         if r.all:
            vpn = r.vpn[0]
            if not confirm("All objects in vpn %s will be disabled" % (vpn)):
               sys.exit(0)
            semp.DisableMsgVpn(vpn)
            sys.exit(0)

         if r.clientusers:
            vpn = r.vpn[0]
            if not confirm("Following client users in vpn %s will be disabled:\n%s" % (vpn, r.clientusers)):
               sys.exit(0)
	    if r.clientusers[0] == 'all':
               semp.DisableClientUsers(vpn, semp.GetClientUsernames())
	    else:
               semp.DisableClientUsers(vpn, r.clientusers)

         if r.queues:
            vpn = r.vpn[0]
            if not confirm("Following queues in vpn %s will be disabled:\n%s" % (vpn, r.queues)):
               sys.exit(0)
	    if r.queues[0] == 'all':
               semp.DisableQueues(vpn, semp.GetQueueNames(vpn))
	    else:
               semp.DisableQueues(vpn, r.queues)

         if r.bridges:
            vpn = r.vpn[0]
            if not confirm("Following bridges in vpn %s will be disabled:\n%s" % (vpn, r.bridges)):
               sys.exit(0)
	    if r.bridges[0] == 'all':
               semp.DisableBridges(vpn, semp.GetBridgeNames(vpn))
	    else:
               semp.DisableBridges(vpn, r.bridges)

         if r.jndi:
            vpn = r.vpn[0]
            if not confirm("JNDI in vpn %s will be disabled", vpn ):
               sys.exit(0)
            semp.DisableJNDI(vpn)


      # ---------------------------------------------------------
      # enable
      #
      if r.enable:
         vpn = r.vpn[0]
         if r.all:
            if not confirm("All objects in vpn %s will be enabled" % (vpn)):
               sys.exit(0)
            semp.EnableMsgVpn(vpn)
            sys.exit(0)

         if r.clientusers:
            vpn = r.vpn[0]
            if not confirm("Following client users in vpn %s will be enabled:\n%s" % (vpn, r.clientusers)):
               sys.exit(0)
	    if r.clientusers[0] == 'all':
               semp.EnableClientUsers(vpn, semp.GetClientUsernames())
	    else:
               semp.EnableClientUsers(vpn, r.clientusers)

         if r.queues:
            vpn = r.vpn[0]
            if not confirm("Following queues in vpn %s will be enabled:\n%s" % (vpn, r.queues)):
               sys.exit(0)
	    if r.queues[0] == 'all':
               semp.EnableQueues(vpn, semp.GetQueueNames(vpn))
	    else:
               semp.EnableQueues(vpn, r.queues)

         if r.bridges:
            vpn = r.vpn[0]
            if not confirm("Following bridges in vpn %s will be enabled:\n%s" % (vpn, r.bridges)):
               sys.exit(0)
	    if r.bridges[0] == 'all':
               semp.EnableBridges(vpn, semp.GetBridgeNames(vpn))
	    else:
               semp.EnableBridges(vpn, r.bridges)

         if r.jndi:
            vpn = r.vpn[0]
            if not confirm("JNDI in vpn %s will be enabled", vpn ):
               sys.exit(0)
            semp.EnableJNDI(vpn)

      # ---------------------------------------------------------
      # purge queus
      #
      if r.purge:
         vpn = r.vpn[0]
         if not confirm("Following queues in vpn %s will be purged:\n%s" % (vpn, r.queues)):
            sys.exit(0)
         if r.queues:
	    if r.queues[0] == 'all':
               semp.PurgeQueues(vpn, semp.GetQueueNames(vpn))
	    else:
               semp.PurgeQueues(vpn, r.queues)

      # ---------------------------------------------------------
      # clear stats
      #
      if r.clearstats:
         if not confirm("All stats in vpn %s will be cleared" % (r.vpn)):
            sys.exit(0)
         # force so missing objects (like DTE) don't stop clear
         semp.Force(True)
         if r.system:
            semp.ClearSystemStats()
         semp.ClearVpnStats(r.vpn)

      # ---------------------------------------------------------
      # export vpn
      #
      if r.export:
         for vpn in r.vpn:
            cfg = semp.GetMsgVpnConfig(vpn)
            ts = time.strftime("%Y%m%d-%H%M%S")
            fname = 'exported/%s_%s_%s.yaml' %(env, vpn, ts)

            yml = posyaml.POSSolYaml(me)
            yml.WriteCfgToYaml(r.host, vpn, cfg, fname)


   except SystemExit as e:
      sys.exit(e)
   except Exception as e:
      log.exception(repr(e))
   except :
      log.exception("Unexpected exception: %s", sys.exc_info()[0])


def confirm(s):
    print ('----------------------------------------------------------------------------------')
    print (s)
    print ('----------------------------------------------------------------------------------')
    yn = raw_input('Do you want to proceed (y/N) ?')
    if yn.lower() != "y":
       return False
    return True

if __name__ == "__main__":
   main(sys.argv[1:])
