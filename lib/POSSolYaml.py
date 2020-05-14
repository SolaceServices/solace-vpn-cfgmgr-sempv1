#!/usr/bin/python
# POSSolYaml
#   YAML tools for Solace Tempale python scripts
#
# Ramesh Natarjan (Solace PSG)

import sys, os
import re
import yaml
import logging, inspect
import pprint
import json
import time
# import common function
mypath = os.path.dirname(__file__)
sys.path.append(mypath+"/lib")

class POSSolYaml:
   'Solace Yaml implementation'


	#--------------------------------------------------------------
	# Constructor
	#--------------------------------------------------------------
   def __init__(self, me, appcfgfile = None, sitecfgfile = None, pwdfile = None, vmr=False):
      self.m_me = me
      self.m_logger = logging.getLogger(me)
      global log
      log = self.m_logger
      log.enter (" %s::%s  appcfg %s sitecfg %s", __name__, inspect.stack()[0][3], appcfgfile, sitecfgfile)
      if (appcfgfile == None and sitecfgfile == None):
          log.debug ("Nothing to do here.")
          return

      # read config files
      try :

	 # load valid-tags reference dict
         self.m_vref = self.Load("cfg/valid-tags.yaml")

	 # load password file if passed
	 self.m_pwd = {}
	 if pwdfile is not None:
	     log.debug ("Loading password file %s", pwdfile)
             pwdh = self.Load(pwdfile)
	     log.debug ("password hash %s", pwdh)
	     self.m_pwd =  self.makeNameMap (pwdh)
	     log.trace ("password name map %s", self.m_pwd)
             #print "PASSWORDS:\n", self.m_pwd
             #print "PASSWORDS:\n", yaml.dump (self.m_pwd, default_flow_style=False)

	 # load app config
         self.m_appcfg = self.Load(appcfgfile)

	 # no site cfg. take app config as is
	 self.m_sitecfg = {}
         if sitecfgfile is None:
            self.m_dict = self.m_appcfg.copy()
            log.debug ("App config:\n%s", self.m_dict)
         else:
            log.info ("Merging App config %s with Site config %s", appcfgfile, sitecfgfile)
            self.m_sitecfg = self.Load(sitecfgfile)
            self.m_dict = self.m_sitecfg.copy()
            self.m_dict.update(self.m_appcfg)
            # for vmr, overlay site config on top of appconfig
            if vmr:
                log.note ("Overriding values from site-config with VMR options")
                #print 'client-profiles:', self.m_dict['client-profiles']
                for t in ['max-connections', 'max-endpoints', 'max-transactions', 'max-transacted-sessions', 'max-egress-flows', 'max-ingress-flows', 'max-subscriptions']:
                   sval = self.m_sitecfg['vpn'][0][t]
                   log.note ("   %s (%s) => %s", t, self.m_dict['vpn'][0][t], sval)
                   self.m_dict['vpn'][0][t] = sval
                   for c in self.m_dict['client-profiles']:
                       c[t] = sval
            log.trace ("Merged config:\n%s", self.m_dict)
         # make a hashmap of dict for easier navigation
         self.m_map = {}
         self.MakeMap()
         #log.trace ("bridge data(1): %s", self.m_map['bridges'])
         self.Validate()
         #log.trace ("bridge data(2): %s", self.m_map['bridges'])
	 self.Preprocess()
         #log.trace ("bridge data(3): %s", self.m_map['bridges'])
      except yaml.YAMLError as ex:
         log.exception ('YAMLException', ex)
      except:
         log.exception ("unexpected exception", sys.exc_info()[0])
	 raise


	#--------------------------------------------------------------
	# Load
	#--------------------------------------------------------------
   def Load(self, fname):
      log = self.m_logger
      log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], fname)

      log.info ("Reading YAML file %s", fname)
      try:
        with open(fname, 'r') as f:
            l_dict = yaml.load(f)
	    log.trace ("%s file content:\n%s", fname, l_dict)
	    f.close()
	    return l_dict
      except IOError as ex:
        log.exception (ex)
	raise ex
      except yaml.YAMLError as ex:
        log.exception (ex)
	raise ex
      except:
        log.exception ('Unexpected exception', sys.exc_info()[0])
	raise

   def GetMap(self):
       return self.m_map

   def GetDict(self):
       return self.m_dict

	#--------------------------------------------------------------
	# MakeMap : read dict and make them into hash map key'ed by object names
	#--------------------------------------------------------------
   def MakeMap(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      for key in  self.m_dict.keys():
          self.m_map[key] = {}
          log.debug ("Processing root key: %s", key)
          log.trace ("record len %d %s", len(self.m_dict[key]), self.m_dict[key])
	  for k in self.m_dict[key]:
	     log.trace ("processing key %s", k)
	     kname = 'default'
             if not k.has_key('name'):
	        continue
	     kname = k['name']
	     if key == "queues" and kname == "DEAD_MSG_QUEUE":
	        kname = "#DEAD_MSG_QUEUE"
	     log.trace ("key name %s", kname)
	     if self.m_sitecfg.has_key(key):
	        # merage site-config and app-config
	        ka = k.copy()
	        if key == "queues" and kname == "#DEAD_MSG_QUEUE":
		   ka['name'] = '#DEAD_MSG_QUEUE'
                log.trace ("app record: %s", ka)
	        ks = self.m_sitecfg[key][0].copy()
		if ks.has_key('key'):
		   del ks['key']
                log.trace ("site record: %s", ks)
	        km = merged(ka, ks)
                log.trace ("merged record: %s", km)
		#if kname == 'default':
                #  log.info ("skipping m_map[%s][%s] => %s", key, kname, km)
		#else:
                log.debug ("Adding %s[%s] => %s", key, kname, km)
                self.m_map[key][kname] = km
	     else:
                log.info ("No site-default for %s. use app record", key)
                self.m_map[key][kname] = k
	     # process remote-vpn list of bridges
	     if key == 'bridges':
	        if kname == 'default':
		   continue
		# use nameMap instead
		log.trace("BRIDGE m_map[%s][%s] = %s", key, kname, self.m_map[key][kname])
	        for r in self.m_map[key][kname]:
		   log.debug("processing %s[%s].%s", key, kname, r)
                   if r != 'remote-vpns':
		      continue
	           rv =  self.m_map[key][kname][r]
		   log.trace("remote-vpns: %s", rv)
		   remotemap = {}
		   for r1 in rv:
		      log.debug ("processing remote-vpn entry:  %s", r1)
		      rname = 'default'
		      if 'vpnname' in r1:
			 rname = r1['vpnname']
		         log.debug("processing remote vpn (site): %s", rname)
			 if self.m_sitecfg[key][0].has_key('remote-vpns'):
			    log.debug ('merging remote-vpns')
			    log.trace ('remote-vpn: %s',  self.m_sitecfg[key][0]['remote-vpns'])
			    ra = r1.copy()
			    rs = self.m_sitecfg[key][0]['remote-vpns'].copy()
			    log.trace ("remote-vpn app  = %s", ra)
			    log.trace ("remote-vpn site = %s", rs)
			    rm = merged(ra, rs)
			    log.trace ("remote-vpn merged = %s", rm)
                            remotemap[rname] = rm
			 else:
			    log.info ('remote-vpns not found in site-config. taking app-config as is')
                            remotemap[rname] = ra
                   self.m_map[key][kname][r] = remotemap.copy()
             # Process RDP objects
	     if key == 'rest-delivery-points':
	        if kname == 'default':
		   continue
		log.trace("RDP map[%s][%s] = %s", key, kname, self.m_map[key][kname])
                # Fix 2nd level entries
                # TODO: for simplicity site-defaults are not merged here
                # will result in unintelligent code like bridge one otherwise
                for tag in ['consumers', 'queue-bindings']:
                  tagname = re.sub('s$','',tag) # get rid of last 's'
                  log.debug ("Processing RDP object %s (name: %s)", tag, tagname);
	          objects =  self.m_map[key][kname][tag]
                  objectmap = {}
                  for obj in objects:
                    objname = obj[tagname]
                    del obj[tagname]
                    objectmap[objname] = obj
		    log.trace ('RDP[%s][%s]= %s',  tag, objname, obj)
                  self.m_map[key][kname][tag] = objectmap
		log.trace("NEW RDP MAP[%s][%s] = %s", key, kname, self.m_map[key][kname])

     #-----------------------------------------------------------------------------------
     # makeNameMap  -- this is simplified version of MakeMap above
     # convert { 'name' : 'myname', 'tag' : 'value' }, ... tp
     #         { 'myname' : { 'name' : 'myname', 'tag' : 'value' }, ... }
     # create a destination map (mapd) internally and return
     #
   def makeNameMap (self, srcmap):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      log.trace ("srcmap = %s", srcmap)
      namemap = {}
      for k1, v1 in  srcmap.items():
          log.trace ("v1 = %s", v1)
          if type(v1) is list:
             log.debug ("Processing list of keys: %s", k1)
	     rootmaplist = [nmap(v2) for v2 in v1]
             log.trace ("namemaplist[%s] = %s", k1, rootmaplist)
             namemap[k1] = rootmaplist
          else:
             log.debug ("Processing key: %s", k1)
	     rootmap = nmap(v1)
             log.debug ("namemap[%s] = %s", k1, rootmap)
             namemap[k1] = rootmap
      return namemap

	#--------------------------------------------------------------
	# Validate : validate tags in map
	#
   def Validate(self):
     failed = False
     log = self.m_logger
     log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
     vpn = None

     # validate tags
     for k1 in self.m_vref.keys():
	v1 = self.m_vref[k1]
        if self.m_map.has_key(k1):
           m1 = self.m_map[k1].keys()
           log.debug ("Tag %s found in with %s (%d entries)", k1, m1, len(m1))
	   if k1 == 'vpn':
	      vpn = m1[0]
	   if 'default' in m1:
	      m1.remove('default')
	   if 'key' in m1:
	      m1.remove('key')
	   if len(m1) >= 1:
              log.debug ("Tag %s has %d entries", k1, len(m1))
	   else:
	      if self.m_vref[k1]['required'] == False:
                 log.warning ("Optional tag %s has no entries", k1)
	      else:
                 log.error ("Tag %s has no entries", k1)
                 failed = True

           for m2 in m1:
              log.debug ("checking map entry %s[%s]", k1, m2)
	      if m2 == "default":
	         continue
              for k2 in self.m_vref[k1].keys():
		 # site-defaults may use this dummy key for empty record. ignore this
	         if k2 == "key":
                    log.debug ("ignoring key %s/%s", k1, k2)
	            continue
	         v2= self.m_vref[k1][k2]
                 #log.debug ("Checking for tag %s[%s]/%s %s", k1, m2, k2, type(self.m_map[k1][m2]))
                 #log.debug ("%s", self.m_map[k1][m2])
		 if k2 == "required":
		    continue
                 if self.m_map[k1][m2].has_key(k2):
                    log.debug ("Object-1 %s[%s] has tag %s", k1, m2, k2)

                 else:
		    if v2 == False:
                       log.warning ("Object %s[%s] is missing optional tag %s", k1, m2, k2)
		    else:
		       if k2 == "topic-subscriptions" and m2 == "DEAD_MSG_QUEUE":
		          continue
                       log.error ("Object %s[%s] is missing tag %s", k1, m2, k2)
	               failed = True
                 if k2 == "event-thresholds" or k2 == "remote-user":
                    for k3 in self.m_vref[k1][k2].keys():
	               if k3 == "key" or k3 == "required":
                          log.debug ("Skipping Object %s[%s] tag %s/%s", k1, m2, k2, k3)
	                  continue
                       if self.m_map[k1][m2][k2].has_key(k3):
                          log.debug ("Object %s[%s] has tag %s/%s", k1, m2, k2, k3)
                       else:
                          log.error ("Object %s[%s] is missing tag %s/%s", k1, m2, k2, k3)
	                  failed = True
                 if k2 == "remote-vpns":
                    for k3 in self.m_vref[k1][k2].keys():
	               if k3 == "key" or k3 == "required":
                          log.debug ("Skipping Object %s[%s] tag %s/%s", k1, m2, k2, k3)
	                  continue
		       log.trace("remote-vpns: %s", self.m_map[k1][m2][k2])
                       for k4,v4 in self.m_map[k1][m2][k2].items():
			  log.trace("looking for %s in %s", k3, v4)
                          if v4.has_key(k3):
                             log.debug ("Object %s[%s][%s] has tag %s/%s", k1, m2, k4, k2, k3)
                          else:
                             log.error ("Object %s[%s][%s] is missing tag %s/%s", k1, m2, k4, k2, k3)
	                     failed = True
        else:
           log.error ("Tag %s not found in config", k1)
	   failed = True

     if failed:
        log.critical ("Config file validation failed. Exiting")
        raise Exception('VPN validation failed')
     else:
        log.info ("Config files are valid")

	#--------------------------------------------------------------
	# Preprocess : Fix some fields
	# TODO: replace this with loop comprehension
   def Preprocess(self):
     failed = False
     log = self.m_logger
     log.enter (" %s::%s ", __name__, inspect.stack()[0][3])

     m = self.m_map
     vpn = self.GetVpnName()
     for k in m.keys():
        log.debug ("processing root tag %s for VPN %s", k, vpn)
	for k1 in m[k]:
            log.debug ("processing %s[%s]", k, k1)
	    for k2 in m[k][k1]:
                log.debug ("processing tag %s[%s].%s", k, k1, k2)
		# If password is to be read from file, do it
		if k2 == 'password' and m[k][k1][k2] == 'ONFILE':
                   self.m_map[k][k1][k2] =  self.GetPassword(vpn, k1)
		   if self.m_map[k][k1][k2] is None:
                      log.error ("Password for %s[%s] is missing in file", k, k1)
	              failed = True
		   else:
                      log.info ("Password for %s[%s] read from file", k, k1)
		if k2 == 'remote-user':
	          for k3 in m[k][k1][k2]:
		    kn = m[k][k1][k2]['username']
                    log.debug ("processing remote-user %s[%s].%s.%s (%s)", k, k1,k2,k3, kn)
		    if k3 == 'password' and m[k][k1][k2][k3] == 'ONFILE':
                        self.m_map[k][k1][k2][k3] =  self.GetPassword(vpn, kn)
		        if self.m_map[k][k1][k2][k3] is None:
                           log.error ("Password for %s[%s].%s is missing in file", k, k1,kn)
	                   failed = True
		        else:
                           log.info ("Password for %s[%s].%s read from file", k, k1,kn)

		# convert Spool size to MB
		if k2 == 'spool-size' and k == 'vpn':
                   self.m_map[k][k1][k2] = sizeInMB(self.m_map[k][k1][k2])
                   log.info ("%s[%s] %s: %s MB", k, k1, k2, self.m_map[k][k1][k2])
		# convert VPN large msg threshold to KB
		if k2 == 'large-msg-threshold' and k == 'vpn':
                   self.m_map[k][k1][k2] = sizeInKB(self.m_map[k][k1][k2])
                   log.info ("%s[%s] %s: %s KB", k, k1, k2, self.m_map[k][k1][k2])
		# convert Queue max-msg-size to Bytes
		if k2 == 'max-msg-size' and k == 'queues':
                   self.m_map[k][k1][k2] = sizeInBytes(self.m_map[k][k1][k2])
                   log.info ("%s[%s] %s: %s Bytes", k, k1, k2, self.m_map[k][k1][k2])
		# convert Queue spool to MB
		if k2 == 'max-spool' and k == 'queues':
                   self.m_map[k][k1][k2] = sizeInMB(self.m_map[k][k1][k2])
                   log.info ("%s[%s] %s: %s KB", k, k1, k2, self.m_map[k][k1][k2])
		# convert tcp-win spool to KB
		if k2 == 'tcp-win' and k == 'client-profiles':
                   self.m_map[k][k1][k2] = sizeInKB(self.m_map[k][k1][k2])
                   log.info ("%s[%s] %s: %s KB", k, k1, k2, self.m_map[k][k1][k2])

                # fix client-profile missing values from vpn
                if k == 'client-profiles':
                   log.trace ('client-profile value: %s', self.m_map[k][k1])
                   for k2 in ['max-transactions', 'max-egress-flows', 'max-ingress-flows', 'max-endpoints', 'max-transacted-sessions', 'max-connections', 'max-subscriptions']:
                      log.trace ('vpn value: %s', self.m_map['vpn'])
                      if self.m_map[k][k1][k2] == 'vpn-limit':
                        self.m_map[k][k1][k2] = self.m_map['vpn'][vpn][k2]
                        log.info ("%s[%s] %s: %s VPN", k, k1, k2, self.m_map[k][k1][k2])

     if failed:
        raise Exception('Failed to normalize VPN')

	#--------------------------------------------------------------
	# Find : find a tag in map (dict) using xpath like query
	#
   def Find(self, q):
     self.m_logger.debug ("ENTERING %s::%s  %s", __name__, inspect.stack()[0][3], q)

     keys = q.split('/')
     nd = self.m_map
     for k in keys:
       if k == '':
         continue
       if k in nd:
         nd = nd[k]
       else:
         return None
     return nd

	#--------------------------------------------------------------
	# Return host ip and port in ip:port format
	#
   def FindHostInfo(self):
       self.m_logger.debug ("ENTERING %s::%s  ", __name__, inspect.stack()[0][3])

       (ip, port) =  (self.Find('router/admin-ip'), \
       	    self.Find('router/semp-port'))
       self.m_logger.debug ("hostinfo %s:%s", ip, port)
       return (ip+':'+str(port))

	#--------------------------------------------------------------
	# get vpn info
	#
   def GetVpnData(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      if 'vpn' not in self.m_map:
          return None
      return self.m_map['vpn'][self.GetVpnName()]

   def GetVpnName(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      if 'vpn' not in self.m_map:
          return None
      return self.m_map['vpn'].keys()[0]

	#--------------------------------------------------------------
	# get client user info
	#
   def GetClientUserData(self, cuname):
      log = self.m_logger
      log.enter (" %s::%s  clientuser %s", __name__, inspect.stack()[0][3], cuname)
      if cuname not in self.m_map['client-users']:
          return None
      return self.m_map['client-users'][cuname]

   def GetClientUsernames(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      if 'client-users' not in self.m_map:
          return None
      return self.m_map['client-users'].keys()


	#--------------------------------------------------------------
	# get client profile info
	#
   def GetClientProfileData(self, name):
      log = self.m_logger
      log.enter (" %s::%s  ClientProfile %s", __name__, inspect.stack()[0][3], name)
      if name not in self.m_map['client-profiles']:
          return None
      return self.m_map['client-profiles'][name]

   def GetClientProfileNames(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      if 'client-profiles' not in self.m_map:
          return None
      return self.m_map['client-profiles'].keys()

	#--------------------------------------------------------------
	# get client profile info
	#
   def GetACLProfileData(self, name):
      log = self.m_logger
      log.enter (" %s::%s  ACLProfile %s", __name__, inspect.stack()[0][3], name)
      if name not in self.m_map['acl-profiles']:
          return None
      return self.m_map['acl-profiles'][name]

   def GetACLProfileNames(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      if 'acl-profiles' not in self.m_map:
          return None
      return self.m_map['acl-profiles'].keys()

	#--------------------------------------------------------------
	# get queue
	#
   def GetQueueNames(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      if 'queues' not in self.m_map:
          return None
      return self.m_map['queues'].keys()

   def GetQueueData(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Queue %s", __name__, inspect.stack()[0][3], name)
      if name not in self.m_map['queues']:
          return None
      return self.m_map['queues'][name]

   def QueueHasThresholds(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Queue %s", __name__, inspect.stack()[0][3], name)
      return self.GetQueueData(name).has_key('event-thresholds')

   def GetQueueThresholds(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Queue %s", __name__, inspect.stack()[0][3], name)
      return self.GetQueueData(name)['event-thresholds']

   def QueueHasSubs(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Queue %s", __name__, inspect.stack()[0][3], name)
      return self.GetQueueData(name).has_key('topic-subscriptions')

   def GetQueueSubs(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Queue %s", __name__, inspect.stack()[0][3], name)
      return self.GetQueueData(name)['topic-subscriptions']

	#--------------------------------------------------------------
	# get bridge info
	#
   def GetBridgeNames(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      if 'bridges' not in self.m_map:
          return None
      return self.m_map['bridges'].keys()

   def GetBridgeData(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Bridge %s", __name__, inspect.stack()[0][3], name)
      if name not in self.m_map['bridges']:
          return None
      return self.m_map['bridges'][name]

   def GetBridgeThresholds(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Bridge %s", __name__, inspect.stack()[0][3], name)
      return self.GetBridgeData(name)['event-thresholds']

   def BridgeHasRemoteVpns(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Bridge %s", __name__, inspect.stack()[0][3], name)
      return self.GetBridgeData(name).has_key('remote-vpns')

   def GetBridgeRemoteVpnNames(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Bridge %s", __name__, inspect.stack()[0][3], name)
      return self.GetBridgeData(name)['remote-vpns'].keys()

   def GetBridgeRemoteVpnData(self, name, rvpn):
      log = self.m_logger
      log.enter (" %s::%s  Bridge %s remote-vpn %s", __name__, inspect.stack()[0][3], name, rvpn)
      log.trace ("bridge data = %s", self.GetBridgeData(name))
      log.trace ("remote vpns map[%s] = %s", rvpn, self.GetBridgeData(name)['remote-vpns'][rvpn])
      return self.GetBridgeData(name)['remote-vpns'][rvpn]


	#--------------------------------------------------------------
	# get RDP info
	#
   def GetRDPNames(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      if 'rest-delivery-points' not in self.m_map:
          return None
      return self.m_map['rest-delivery-points'].keys()

   def GetRDPData(self, name):
      log = self.m_logger
      log.enter (" %s::%s  RDP %s", __name__, inspect.stack()[0][3], name)
      if name not in self.m_map['rest-delivery-points']:
          return None
      return self.m_map['rest-delivery-points'][name]

   def GetRDPThresholds(self, name):
      log = self.m_logger
      log.enter (" %s::%s  RDP %s", __name__, inspect.stack()[0][3], name)
      return self.GetRDPData(name)['event-thresholds']

   def RDPHasConsumers(self, name):
      log = self.m_logger
      log.enter (" %s::%s  RDP %s", __name__, inspect.stack()[0][3], name)
      return self.GetRDPData(name).has_key('consumers')

   def GetRDPConsumerNames(self, name):
      log = self.m_logger
      log.enter (" %s::%s  RDP %s", __name__, inspect.stack()[0][3], name)
      return self.GetRDPData(name)['consumers'].keys()

   def GetRDPConsumerData (self, name, rvpn):
      log = self.m_logger
      log.enter (" %s::%s  RDP %s consumers %s", __name__, inspect.stack()[0][3], name, rvpn)
      log.trace ("RDP data = %s", self.GetRDPData(name))
      log.trace ("Consumers map[%s] = %s", rvpn, self.GetRDPData(name)['consumers'][rvpn])
      return self.GetRDPData(name)['consumers'][rvpn]

   def RDPHasQueueBindings(self, name):
      log = self.m_logger
      log.enter (" %s::%s  RDP %s", __name__, inspect.stack()[0][3], name)
      return self.GetRDPData(name).has_key('queue-bindings')

   def GetRDPQueueBindingNames(self, name):
      log = self.m_logger
      log.enter (" %s::%s  RDP %s", __name__, inspect.stack()[0][3], name)
      return self.GetRDPData(name)['queue-bindings'].keys()

   def GetRDPQueueBindingData (self, name, rvpn):
      log = self.m_logger
      log.enter (" %s::%s  RDP %s consumers %s", __name__, inspect.stack()[0][3], name, rvpn)
      log.trace ("RDP data = %s", self.GetRDPData(name))
      log.trace ("Queue Binding map[%s] = %s", rvpn, self.GetRDPData(name)['queue-bindings'][rvpn])
      return self.GetRDPData(name)['queue-bindings'][rvpn]

	#--------------------------------------------------------------
	# get jndi info
	#
   def GetConnectionFactoryNames(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      if 'jndi' not in self.m_map:
          return None
      return self.m_map['jndi'].keys()

   def GetConnectionFactoryData(self, name):
      log = self.m_logger
      log.enter (" %s::%s  Connection Factory %s", __name__, inspect.stack()[0][3], name)
      if name not in self.m_map['jndi']:
          return None
      return self.m_map['jndi'][name]

	#--------------------------------------------------------------
	# Return host ip and port in ip:port format
	#
   def GetHostInfo(self):
       log = self.m_logger
       log.enter (" %s::%s  ", __name__, inspect.stack()[0][3])

       if 'router' not in self.m_map:
           return None
       log.debug ("router %s", self.m_map['router'])
       r = self.m_map['router'].keys()[0]
       log.debug ("router info %s", r)
       (ip, port) =  (self.m_map['router'][r]['admin-ip'], self.m_map['router'][r]['semp-port'])
       return (ip+':'+str(port))

	#--------------------------------------------------------------
	# compare two configs
        #
   def Compare(self, ncfg, tag1="Config", tag2="Router"):
     log = self.m_logger
     log.enter (" %s::%s  ", __name__, inspect.stack()[0][3])

     rc = True

     # ignore these from the list returned by appliance as they are
     # not present in the config file
     # FIXME: harcoded tags
     ignoretags = { 'client-profiles' : ['#client-profile', 'default'],
                    'acl-profiles' :    ['#acl-profile', 'default'],
                    'client-users' :    ['#client-username', 'default'],
                    'router' :    ['name']
		    }

     log.trace ("ignore tags : %s", ignoretags)
     mcfg = self.m_map
     vref = self.m_vref

     log.trace ("%s read:\n%s", tag1, mcfg)
     log.trace ("%s config:\n%s", tag2, ncfg)

     # compare 1st level tags .. look for union of both keys
     allkeys = set(mcfg.keys()) | (set(ncfg.keys()))
     # remove these from keys as they are not present in router / config
     if 'router' in allkeys:
         allkeys.remove('router')
     smaps = []
     for k in allkeys:
	   log.debug ('Processing key %s', k)
	   smap = {'key1': k}
           if mcfg.has_key(k):
	      log.trace ('config-read[%s] =  %s', k, mcfg[k])
              smap['config'] = sorted(mcfg[k].keys())
	   else:
              smap['config'] = []
           if ncfg.has_key(k):
	      log.trace ('router-config[%s] =  %s', k, ncfg[k])
              smap['router'] = sorted(ncfg[k].keys())
	      for ik in ignoretags.keys():
	        if k == ik:
		   for it in ignoretags[ik]:
		      if it in smap['router']:
			 log.debug ("Ignoring %s from list %s", it, k)
		         smap['router'].remove(it)
	   else:
              smap['router'] = []
	   log.debug ("comparing key: %s", k)
	   log.trace ("%s val: %s", tag1, smap['config'])
	   log.trace ("%s val: %s", tag2, smap['router'])
           smaps.append(smap)
     for smap in smaps:
         if smap['config'] == smap['router']:
	    log.info ("List of %s is same [%s, %s]", smap['key1'], smap['config'], smap['router'])
	 else:
	    rc = False
	    log.info ("List of <%s> is different", smap['key1'])
            log.info ("%s: %s" , tag1, smap['config'])
            log.info ("%s: %s" , tag2, smap['router'])
            #print "   %s: %s" % (tag1, sorted(smap['config']))
            #print "   %s: %s" % (tag2, sorted(smap['router']))
            # print only the diff not the whole list
	    print ("\n--- List of <%s> is different" % smap['key1'])
            print ("   %s: %s" % (tag1, list(set(smap['config']) - set(smap['router']))))
            print ("   %s: %s" % (tag2, list(set(smap['router']) - set(smap['config']))))
            #print "   Config:\n", yaml.dump (smap['config'], default_flow_style=False)
            #print "   Router:\n", yaml.dump (smap['router'], default_flow_style=False)

     # now look for properties and elements for common keys
     comkeys1 = set(mcfg.keys()) & (set(ncfg.keys()))
     log.debug ("common keys1 = %s (%d)", comkeys1, len(comkeys1))
     smaps3 = []
     for k1 in comkeys1:
	   ckeys2 = set(mcfg[k1]) & set(ncfg[k1])
	   log.trace ("mcfg[%s] = %s", k1, mcfg[k1])
	   log.trace ("ncfg[%s] = %s", k1, ncfg[k1])
	   log.debug ("%s common keys2 = %s (%d)", k1, ckeys2, len(ckeys2))
	   for k2 in ckeys2:
	     log.debug ("checking %s[%s]", k1, k2)
             ckeys3 = set(mcfg[k1][k2].keys()) | (set(ncfg[k1][k2].keys()))
	     log.debug ("%s[%s] common keys3 = %s (%d)", k1, k2, ckeys3, len(ckeys3))
	     for k3 in ckeys3:
	           #if k1 == 'bridges' and k3 in ignoretags['bridges']:
	           if k1 == 'bridges':
		      log.debug ("ignoring tag %s from %s", k3, k1)
		      continue;
		   ki = "%s/%s/%s" % (k1,k2,k3)
		   if k3 == 'password':
		      log.debug ("ignoring tag %s from %s", k3, k1)
		      continue
		   smap3 = {'key3': ki}
		   if mcfg[k1][k2].has_key(k3):
		      smap3['config'] = mcfg[k1][k2][k3]
		   else:
		      smap3['config'] = []
		   if ncfg[k1][k2].has_key(k3):
		      smap3['router'] = ncfg[k1][k2][k3]
		   else:
		      smap3['router'] = []
		   smaps3.append(smap3)
     # Look for 2nd level of dict elements (event-thresholds, bridge-info, etc)
     for sm in smaps3:
	 log.debug ("%s is type %s", sm['key3'], type(sm['config']))
	 identical = True
	 if isinstance(sm['config'], list):
            if sorted(sm['config']) != sorted(sm['router']):
	       identical = False
	 #FIXME: doesn't work for event-thresholds and remote-bridge-
         elif isinstance(sm['config'], dict):
            if sorted(sm['config']) != sorted(sm['router']):
	       identical = False
         else :
            # remove Byte units ..
            # FIXME: this removes all trailing chars matching unit
            rm = str(sm['router'])
            rm = re.sub(r'[KMG]$','',rm)
            if str(sm['config']) != rm:
	       identical = False
         if identical:
	    log.info ("Config for [%s] is same", sm['key3'])
	 else:
	    rc = False
            log.info ("Config for [%s] is different:\n   %s: <%s>\n   %s: <%s>" , sm['key3'], tag1, sm['config'], tag2, sm['router'])
            if type(sm['config']) is list:
               print ("\n--- List of <%s> is different:" % sm['key3'])
               print ("   %s: %s" % (tag1, list(set(sm['config']) - set(sm['router']))))
               print ("   %s: %s" % (tag2, list(set(sm['router']) - set(sm['config']))))
            else:
               print ("\n--- Config for <%s> is different:" % sm['key3'])
               print ("   %s: %s" % (tag1, sm['config']))
               print ("   %s: %s" % (tag2, sm['router']))

     return rc

	#--------------------------------------------------------------
	# dump cfg
	#
   def Dump(self, verbose=False):
       log = self.m_logger
       log.enter (" %s::%s  ", __name__, inspect.stack()[0][3])
       print ("\nConfig Summary\n----------------------------------------------------\n")
       for k in self.m_map.keys():
           print  (k)
	   ko = self.m_map[k].keys()
	   if 'default' in ko:
	      ko.remove('default')
	   print ("   ", ko)
       if verbose:
          print ("\nConfig Details\n----------------------------------------------------\n")
          print (yaml.dump (self.m_map, default_flow_style=False))
       #pp = pprint.PrettyPrinter(indent=1)
       #pp = pprint.PrettyPrinter(indent=1)
       #pp.pprint (self.m_map)

	#--------------------------------------------------------------
	# Return password stored in password file
	#
   def GetPassword(self, vpn, uname):
       log = self.m_logger
       log.enter (" %s::%s VPN %s USERNAME %s", __name__, inspect.stack()[0][3], vpn, uname)
       pwds = self.m_pwd['vpns']
       if vpn in pwds:
          log.warn ("VPN %s not found in password map", vpn)
          return None
       # get vpn record
       vpndata =  {vpn: p[vpn] for p in pwds if p.keys()[0] == vpn}
       if vpn not in vpndata:
          log.warn ("No VPN %s found in password map", vpn)
          return None
       #print "vpndata = ", vpndata
       if 'client-users' not in vpndata[vpn]:
          log.warn ("No client-users for VPN %s in password map", vpn)
          return None
       cusers = vpndata[vpn]['client-users']
       cudata =  {uname: p[uname] for p in cusers if p.keys()[0] == uname}
       #print "cudata for ", uname, "= ", cudata
       if uname not in cudata:
          log.warn ("No data for user %s found in password map", vpn)
          return None
       cudata = cudata[uname]
       if not cudata.has_key('password'):
          log.warn ("No password for user %s in password file", uname)
          return None
       #print "passwd = ",  cudata['password']
       return cudata['password']


	#--------------------------------------------------------------
        # Write VPN config returned by POSSolSemp::GetMsgVpnConfig
        # to Yaml file.
        # fixYaml rearrages the tags to make it readable
	#
   def WriteCfgToYaml(self, host, vpn, cfg, fname):
      log = self.m_logger
      log.enter (" %s::%s  host: %s vpn: %s fname: %s", __name__, inspect.stack()[0][3], host, vpn, fname)
      # write to file in yaml
      d = 'exported/tmp'
      try:
        os.stat(d)
      except:
        log.info("creating dir: %s", d)
        os.makedirs(d) # exist_ok=True)
      ts = time.strftime("%Y%m%d-%H%M%S")
      tmpfname = 'exported/tmp/%s-%s_%s.tmp.yaml' %(host, vpn, ts)
      log.info("Writing tmp output to %s", tmpfname)
      with open (tmpfname, 'w') as ft:
         #print yaml.dump (cfg, default_flow_style=False)
	 print >>ft, "---\n# %s VPN config" % (vpn)
	 print >>ft, "# Imported from %s" % (host)
	 print >>ft, "# Generated by %s at %s\n#" % (self.m_me, time.strftime("%c"))
         print >>ft, yaml.dump (cfg, default_flow_style=False)
      ft.close()

      return self.fixYaml(tmpfname, fname)


   def fixYaml(self, tmpyfname, yfname):
      log = self.m_logger
      log.enter (" %s::%s  tmpfname: %s fname: %s", __name__, inspect.stack()[0][3], tmpyfname, yfname)
      log.note("Writing output to %s", yfname)
      fo =  open(yfname, 'w')
      sl = []
      b = False
      nl = ''
      with open(tmpyfname) as fi:
          for l in fi:
              l = l.rstrip()
              #print '>', l
              if re.search('^- ',l):
                  #print 'got - start bloc', l
                  l = re.sub('^-',' ',l)
                  #print 'new - start bloc', l
                  sl.append(l)
                  b = True
                  continue
              if re.search(' name:',l):

                  #print 'got name end bloc', l
                  l = "- %s" % (l.strip())
                  #print 'new - end bloc', l
                  #sl.append(l)
                  #print >>fo, '# %s' % (l)
                  print >>fo, l
                  for s in sl:
                     print >>fo, s
                  b = False
                  sl = []
                  continue
              if b is True:
                  #print 'in bloc. add'
                  sl.append(l)
              else:
                  #print 'out bloc. print'
                  print >>fo, l
      fi.close()
      fo.close()


#--------------------------------------------------------------------
# non class util functions
# TODO: move to a common file
#--------------------------------------------------------------------

    #--------------------------------------------------------------
    # deep merge dictionaries
    #
def merged(source, destination):
    for key, value in source.items():
        if isinstance(value, dict):
            # get node or create one
            node = destination.setdefault(key, {})
            merged(value, node)
        else:
            destination[key] = value
    return destination

    #--------------------------------------------------------------
    # make a name map recursively from a dictionary
    # convert { 'name' : 'myname', 'tag' : 'value' }, ... to
    #         { 'myname' :
    #              { 'tag' : 'value' }, ... }
    # name tag from orignal map removed.
    # calls nmap recursively for list and other complex structures
    #
def nmap(m):
    #print ("nmap: m = %s" % m)
    # if list, call itself for each element
    if type(m) is list:
       return [nmap(k1) for k1 in m]
    # return as is if not dict
    if type(m) is not dict:
       return m
    # do actual tag mapping
    r =  {v: m  for k, v in m.items() if k == 'name'}
    # delete redundant name key
    rk = r.keys()[0]
    del r[rk]['name']
    #print ("nmap: r = %s" % r)
    # call itself for dictionary elements
    for k in r[rk].keys():
       r[rk][k] = nmap(r[rk][k])
    return r

    #----------------------------------------------------------
    # sizeInBytes - convert human readable size to bytes
    #
def sizeInBytes (su):
     global log
     log.enter (" %s::%s SIZE %s", __name__, inspect.stack()[0][3], su)
     um = { 'B' : 1, 'K' : 1024, 'M' : 1048576, 'G' : 1073741824 }
     if len(su) == 1:
         return int(su)
     p = re.compile('(\d+)\s*(\w+)')
     (s,u) = p.match(str(su)).groups()
     u = u.upper()
     if u and u in um.keys():
        b = int(s)*um[u]
        log.debug ("%s (%s %s) -> %d bytes", su, s, u, b)
        return b
     return int(su)

def sizeInKB (s):
    return sizeInBytes(s) / 1024

def sizeInMB (s):
    return sizeInBytes(s) / 1048576

def sizeInGB (s):
    return sizeInBytes(s) / 1073741824
