#!/usr/bin/python
#possolmgr : Solace Config Manager
#
# This file implements following VPN management features:
#     create, delete VPN and VPN objects
#     update VPN and other object properties (eg: queue spool size)
#     validate input files and dump them (dump option)
#     diff the config file with appliance config (verify option)
# Besides the VPN, the following objeccts can be created/deleted/modifed:
#     clientusers, clientprofiles & acl-profiles
#     queues and topic subscriptions
#     bridges
#     jndi
# This script takes 3 input files arguments
#    1. vpn config : YAML file with VPN and VPN object info
#    2. site defaults: YAML File with site specific info (such as IP, port)
#            and any site specific overrides (such as thresholds, global settings)
#    2. password file: YAML file with passwords for client usernames
#
# Ramesh Natarajan, Solace PSG 

import sys, os
import getpass
import argparse
import logging, inspect
import textwrap
import yaml
# Import libraries
sys.path.append(os.getcwd()+"/lib")
import POSSolLogger as poslog
import POSSolYaml   as posyam
import POSSolHttp   as poshttp
import POSSolSemp   as possemp

# Globals
me = "possolmgr"
myver = "v0.8.1"

#--------------------------------------------------------------
# main
#--------------------------------------------------------------
def main(argv):
   global logger

   # setup arguments
   p = argparse.ArgumentParser( prog=me,
   	description='possolmgr : Solace Config Management tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
	epilog=textwrap.dedent('''\
 Refer README.txt for additional info and sample usage.
 '''))

   #pr = p.add_argument_group('Required')
   
   # Required args
   pr = p.add_argument_group("Config files")
   pr.add_argument('--cfgfile', '-f',  action="store", dest='configfile', required=True, help='Config file with Solace router and VPN info')
   pr.add_argument('--sitecfg', '-s', required=True, help='site defaults file') 
   pr.add_argument('--pwdfile', '-p', required=True, help='password file') 
   # Optional args
   po = p.add_argument_group("Actions")
   po.add_argument('--create', action='store_true', help='Create objects')
   po.add_argument('--delete', action='store_true', help='Delete objects')
   po.add_argument('--update', action='store_true', help='Update object properties')
   po.add_argument('--enable', action="store_true", help='Enable objects (no shutdown)')
   po.add_argument('--disable', action="store_true", help='Disable objects (shutdown)')
   po.add_argument('--verify', action='store_true', help='Verify VPN in Solace router')
   po.add_argument('--dump', action='store_true', help='Dump config file')
   po.add_argument('--force', action="store_true", help='Ignore errors *** USE WITH CAUTION ***')

   po = p.add_argument_group("Objects")
   po.add_argument('--vpn', action='store', help='Add/Delete VPN and VPN objects')
   po.add_argument('--clientusers', action='store', nargs='+', help='List of Clients')
   po.add_argument('--clientprofiles',  action='store',  nargs='+', help='List of Client profiles')
   po.add_argument('--aclprofiles', action='store',  nargs='+', help='List of ACL profiles')
   po.add_argument('--queues', action='store', nargs='+', help='List of Queues')
   po.add_argument('--queuesubs', action='store', nargs='+', help='List of Queues for topic subscription')
   po.add_argument('--bridges', action='store', nargs='+', help='List of Bridges')
   po.add_argument('--jndi', action='store', nargs='+', help='List of JNDI objects')
   po.add_argument('--rdps', action='store', nargs='+', help='List of RDP objects')

   po = p.add_argument_group("Optional")
   po.add_argument('--user', dest="username", default="admin", help='CLI username (default: admin)')
   po.add_argument('--password', help='CLI user Password (default: <read from stdin>)') 
   po.add_argument('--vmr', action="store_true", help='Running on VMR (default: No)')
   po.add_argument('-v','--verbose', action="count", help='Verbose mode: -v verbose, -vv debug, -vvv trace')

   # parse and validate args
   r = p.parse_args()

   if not (r.create or r.delete or r.update or r.enable or r.disable or r.dump or r.verify):
      raise Exception("Missing Argument: No Action argument")

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

   # set traceback limit based on verbosity
   sys.tracebacklimit = 0
   if r.verbose:
      sys.tracebacklimit = int(r.verbose)

   cfg = posyam.POSSolYaml(me, r.configfile, r.sitecfg, r.pwdfile, r.vmr)
   vpn = cfg.GetVpnName()

      # ---------------------------------------------------------
      # dump config and exit
      #
   if r.dump:
     cfg.Dump(r.verbose);
     sys.exit(0)

   if not r.verify:
      if not (r.vpn or r.clientusers or r.clientprofiles or r.aclprofiles or r.queues or r.queuesubs or r.bridges or r.jndi or r.rdps):
         raise Exception("Missing Argument: Atleast one object argument must be provided")

   # If password not passed, read from stdin
   if (not r.password):
      r.password = getpass.getpass("Enter password for "+ r.username+ " : ")
   
   try:

      # create http connection object
      http = poshttp.POSSolHttp(me, cfg.GetHostInfo(), r.username, r.password)

      # create semp object
      semp = possemp.POSSolSemp(me, http, cfg, r.vmr, r.force)

      # ---------------------------------------------------------
      # verify config with router and exit
      #
      if r.verify:
	  vpn = cfg.GetVpnName()
          log.note("Comparing VPN %s on router with config %s", vpn, r.configfile)
	  acfg = semp.GetMsgVpnConfig(vpn)
          acfgmap =  semp.makeNameMap(acfg)
          #log.trace ("ROUTER CONFIG BEFORE MAP:\n%s", acfg)
          #log.trace ("ROUTER CONFIG AFTER MAP:\n%s", acfgmap)
          if cfg.Compare(acfgmap) == True:
             log.note("VPN %s config on router is same as %s", vpn, r.configfile)
	  else:
             log.error("VPN %s config on router different from %s", vpn, r.configfile)
          sys.exit(0)
      # ---------------------------------------------------------
      # disable
      #
      if r.disable:
         if r.vpn:
            semp.DisableMsgVpn(vpn)

         if r.clientusers:
	    if r.clientusers[0] == 'all':
               semp.DisableClientUsers(vpn, cfg.GetClientUsernames())
	    else:
               semp.DisableClientUsers(vpn, r.clientusers)

         if r.queues:
	    if r.queues[0] == 'all':
               semp.DisableQueues(vpn, cfg.GetQueueNames())
	    else:
               semp.DisableQueues(vpn, r.queues)

         if r.bridges:
	    if r.bridges[0] == 'all':
               semp.DisableBridges(vpn, cfg.GetBridgeNames())
	    else:
               semp.DisableBridges(vpn, r.bridges)

         if r.rdps:
	    if r.rdps[0] == 'all':
               semp.DisableRDPs(vpn, cfg.GetRDPNames())
	    else:
               semp.DisableRDPs(vpn, r.rdps)

         if r.jndi:
            semp.DisableJNDI(vpn)

      # ---------------------------------------------------------
      # delete objects
      #
      if r.delete:

         if r.clientusers:
	    if r.clientusers[0] == 'all':
               semp.DeleteClientUsersAndObjects(vpn)
	    else:
               semp.DeleteClientUsers(vpn, r.clientusers)

         if r.clientprofiles:
	    if r.clientprofiles[0] == 'all':
               semp.DeleteClientProfiles(vpn, cfg.GetClientProfileNames())
	    else:
               semp.DeleteClientProfiles(vpn, r.clientprofiles)

         if r.aclprofiles:
	    if r.aclprofiles[0] == 'all':
               semp.DeleteACLProfiles(vpn, cfg.GetACLProfileNames())
	    else:
               semp.DeleteACLProfiles(vpn, r.aclprofiles)

         if r.queues:
	    if r.queues[0] == 'all':
               semp.DeleteQueuesAndObjects(vpn)
	    else:
               semp.DeleteQueues(vpn, r.queues)

         if r.bridges:
	    if r.bridges[0] == 'all':
               semp.DeleteBridgesAndObjects(vpn)
	    else:
               semp.DeleteBridges(vpn, r.bridges)

         if r.jndi:
	    if r.jndi[0] == 'all':
               semp.DeleteConnectionFactories(vpn, cfg.GetConnectionFactoryNames())
	    else:
               semp.DeleteConnectionFactories(vpn, r.jndi)

         if r.rdps:
	    if r.rdps[0] == 'all':
               semp.DeleteRDPsAndObjects(vpn)
	    else:
               semp.DeleteRDPs(vpn, r.rdps)

         if r.vpn:
            print ("************************************************************")
            print ("VPN <%s> will be deleted" % vpn)
            print ("************************************************************")
            yn = raw_input('Are you sure (y/N) ?')
            if yn != "y":
               sys.exit(0)
            semp.DeleteMsgVpnAndObjects(vpn)


      # ---------------------------------------------------------
      # create objects
      #
      if r.create or r.update:
         if r.update:
	     vpn = cfg.GetVpnName()
             log.note("Comparing VPN %s on router with config %s", vpn, r.configfile)
	     acfg = semp.GetMsgVpnConfig(vpn)
             acfgmap =  semp.makeNameMap(acfg)
             if cfg.Compare(acfgmap) == True:
                log.note("VPN %s config on router is same as %s", vpn, r.configfile)
                yn = raw_input('Do you still want to update (y/N) ?')
                if yn != "y":
                   sys.exit(0)
	     else:
                log.note("VPN %s config on router is different from %s", vpn, r.configfile)
                yn = raw_input('Do you want to update (y/N) ?')
                if yn != "y":
                   sys.exit(0)
         if r.vpn:
            if vpn != r.vpn:
                log.note("VPN %s from config is different from arg %s", vpn, r.vpn)
                yn = raw_input('Do you want to proceed (y/N) ?')
                if yn != "y":
                   sys.exit(0)
            semp.CreateMsgVpnAndObjects(r.vpn, r.update)

         if r.clientusers:
	    if r.clientusers[0] == 'all':
               semp.CreateClientUsersAndObjects(vpn, r.update)
	    else:
               semp.CreateClientUsers(vpn, r.clientusers, r.update)

         if r.clientprofiles:
	    if r.clientprofiles[0] == 'all':
               semp.CreateClientProfiles(vpn, cfg.GetClientProfileNames(), r.update)
	    else:
               semp.CreateClientProfiles(vpn, r.clientprofiles, r.update)

         if r.aclprofiles:
	    if r.aclprofiles[0] == 'all':
               semp.CreateACLProfiles(vpn, cfg.GetACLProfileNames(), r.update)
	    else:
               semp.CreateACLProfiles(vpn,  r.aclprofiles, r.update)

         if r.queues:
	    if r.queues[0] == 'all':
               semp.CreateQueuesAndObjects(vpn, r.update)
	    else:
               semp.CreateQueues(vpn, r.queues, r.update)
               #semp.CreateQueuesSubs(vpn, r.queues, r.update)

         if r.queuesubs:
	    if r.queuesubs[0] == 'all':
               semp.CreateAllQueuesSubs(vpn, r.update)
	    else:
               semp.CreateQueuesSubs(vpn, r.queuesubs, r.update)

         if r.bridges:
	    if r.bridges[0] == 'all':
               semp.CreateAllBridgesAndObjects(vpn, r.update)
	    else:
               semp.CreateBridges(vpn, r.bridges, r.update)
               for bridgename in r.bridges:
	         if semp.m_cfg.BridgeHasRemoteVpns(bridgename):
                    semp.CreateBridgeRemoteVpns(vpn, bridgename, semp.m_cfg.GetBridgeRemoteVpnNames(bridgename))
                 else:
	            semp.m_logger.info ("No remote vpns for bridge %s", bridgename)

         if r.rdps:
	    if r.rdps[0] == 'all':
               semp.CreateAllRDPsAndObjects(vpn, r.update)
	    else:
               semp.CreateRDPs(vpn, r.rdps, r.update)
               for rdp in r.rdps:
	         if semp.m_cfg.RDPHasConsumers(rdp):
                    semp.CreateRDPConsumers(vpn, rdp, semp.m_cfg.GetRDPConsumerNames(rdp))
                 else:
	            semp.m_logger.info ("No Consumers for RDP %s", rdp)
	         if semp.m_cfg.RDPHasQueueBindings(rdp):
                    semp.CreateRDPQueueBindings(vpn, rdp, semp.m_cfg.GetRDPQueueBindingNames(rdp))
                 else:
	            semp.m_logger.info ("No Queue bindings for RDP %s", rdp)

         if r.jndi:
	    if r.jndi[0] == 'all':
               semp.CreateConnectionFactories(vpn, cfg.GetConnectionFactoryNames(), r.update)
	    else:
               semp.CreateConnectionFactories(vpn, r.jndi, r.update)


      # ---------------------------------------------------------
      # enable
      #
      if r.enable:
         if r.vpn:
            semp.EnableMsgVpn(vpn)

         if r.clientusers:
	    if r.clientusers[0] == 'all':
               semp.EnableClientUsers(vpn, cfg.GetClientUsernames())
	    else:
               semp.EnableClientUsers(vpn, r.clientusers)

         if r.queues:
	    if r.queues[0] == 'all':
               semp.EnableQueues(vpn, cfg.GetQueueNames())
	    else:
               semp.EnableQueues(vpn, r.queues)

         if r.bridges:
	    if r.bridges[0] == 'all':
               semp.EnableBridges(vpn, cfg.GetBridgeNames())
	    else:
               semp.EnableBridges(vpn, r.bridges)

         if r.rdps:
	    if r.rdps[0] == 'all':
               semp.EnableRDPs(vpn, cfg.GetRDPNames())
	    else:
               semp.EnableRDPs(vpn, r.rdps)

         if r.jndi:
            semp.EnableJNDI(vpn)


   except SystemExit as e:
      sys.exit(e)
   except Exception as e:
      log.exception(repr(e))
   except :
      log.exception("Unexpected exception: %s", sys.exc_info()[0])

if __name__ == "__main__":
   main(sys.argv[1:])
