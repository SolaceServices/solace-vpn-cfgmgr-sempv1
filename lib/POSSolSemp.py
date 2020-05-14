#!/usr/bin/python
# POSSolSemp
#   Common SEMP related functions used by Solace Tempale python scripts
#
# Ramesh Natarjan (Solace PSG)

import sys, os
import time
import httplib, base64
import string, re
import xml.etree.ElementTree as ET
import logging, inspect

# import POSSol libs & Classes
#mypath = os.path.dirname(__file__)
#sys.path.append(mypath+"/lib")
sys.path.append(os.getcwd()+"/lib")
import POSSolXml as posxml
import POSSolHttp as poshttp

class POSSolSemp:
   'Solace SEMP XML implementation'

	#--------------------------------------------------------------
	# Constructor
        #  This stores the passed values to class variables
        #
        # Arguments:
        #   prog: program name (used for looking up log handler)
        #   http: http handler to appliance
        #   cfg: vpn config file object. If calling from possoladm (no config)
        #        pass None
        #   vmr: pass True if running on VMR
        #   force: pass True to ignore errors
        #   semp_version: override default semp version
        #
   def __init__(self, prog, http, cfg = None, vmr = False, force = False, semp_version = '7_1_1'):
      self.m_prog = prog
      self.m_logger = logging.getLogger(prog)
      self.m_logger.enter ("%s::%s  force %s semp_version %s", __name__, inspect.stack()[0][3], force, semp_version)

      self.m_http = http
      self.m_cfg = cfg
      self.m_vmr =  vmr
      self.m_force =  force
      self.m_version =  semp_version
      self.m_tstamp = time.strftime("%Y%m%d-%H%M%S")
      self.m_reqxmlfile = None
      self.m_respxmlfile = None
      self.m_vpnnames = None

	#--------------------------------------------------------------
        # Force:
        #   set force flag outside of constructor
        #
   def Force(self, f):
      self.m_logger.info ("set force %s", f)
      self.m_force = f if True else False

	#--------------------------------------------------------------
        # PassOrRaise
        #   Raise an exception unless force is used
        #
   def PassOrRaise(self, s):
      log = self.m_logger
      if (self.m_force):
         log.note("*** " + s + "(ignored with force)")
         pass
      else:
         log.error(s)
         #log.debug("raising exception %s", s)
         raise Exception(s)

   #-------------------------------------------------------
   # Post a Semp req
   #
   def PostSemp(self, req):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])

      rc = self.m_http.Post(req)
      #log.trace ("HTTP Response = %s", rc)
      if rc is None:
         raise Exception ("Null response")
      # response is stored in http object
      return rc

   #-------------------------------------------------------
   # Process a Semp req
   #
   def ProcessSemp(self, tag, req, vpn='novpn'):
      #self.m_logger.enter (" %s::%s  tag: %s req: %s ", __name__, inspect.stack()[0][3], tag, req)
      log = self.m_logger
      log.enter ("%s::%s  tag: %s", __name__, inspect.stack()[0][3], tag)

      # save request and response files
      if self.m_tstamp is None:
         self.m_tstamp = time.strftime("%Y%m%d-%H%M%S")
      if self.m_cfg:
         vpn = self.m_cfg.GetVpnName()
      fname = re.sub('[^0-9a-zA-Z]+', '_', tag)
      self.m_reqxmlfile = "semp/request/%s-%s/%s.xml" % (vpn, self.m_tstamp, fname)
      reqxml = posxml.POSSolXml(self.m_prog, req)
      reqxml.Save(self.m_reqxmlfile, "request semp")
      log.trace ('Request File: %s Contents:\n%s', fname, req)

      #  post request
      resp =  self.PostSemp(req)
      rxml = posxml.POSSolXml(self.m_prog, resp)

      # save response
      self.m_respxmlfile = "semp/response/%s-%s/%s.xml" % (vpn, self.m_tstamp, fname)
      rxml.Save(self.m_respxmlfile, "response semp")
      log.trace ('Response File: %s Contents:\n%s', fname, resp)

      # look for known errors in response
      s = rxml.Find('./parse-error')
      if s:
         es = "SEMP Request \"%s\" failed (Reason : %s)" % (tag, s)
	 self.PassOrRaise(es)
	 #raise Exception(es)
      rc = rxml.FindAt('./execute-result', 'code')
      if rc != "ok" :
         rs = rxml.FindAt('./execute-result', 'reason')
         es = "SEMP Request \"%s\" failed (Reason : %s)" % (tag, rs)
	 self.PassOrRaise(es)
	 return None
	 #raise Exception(es)
	 #raise posexp.SempFailed(tag, rs, xmlfname)
      self.m_logger.status ("%s (status: %s)", tag, rc)
      return resp


   #-------------------------------------------------------
   # ReadSempRequest
   #
   def ReadSempReq(self, fname):
      log = self.m_logger
      log.enter (" %s::%s  fname = %s", __name__, inspect.stack()[0][3], fname)
      sempfile = "semp/templates/%s/%s" % (self.m_version, fname)
      self.m_logger.info ("Reading semp request template file: %s",sempfile )
      try:
         f = open(sempfile , 'r')
         if not f:
           raise Exception('Unable to open file', sempfile )
         req = f.read()
         self.m_logger.trace ("semp req template = %s", req)
         f.close()
         return req
      except IOError as e:
        log.exception (e)
	raise e
      except:
        log.exception ('Unexpected exception', sys.exc_info()[0])
	raise

   #--------------------------------------------------------------------
   # CREATE FUNCTIONS
   #--------------------------------------------------------------------

   #-------------------------------------------------------
   # Create Client Profile
   #
   def CreateClientProfile(self, vpn, cpname, cpdata, update=False):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s clientprofile: %s", __name__, inspect.stack()[0][3], vpn, cpname)

      if not update:
         log.note ("Creating ClientProfile %s", cpname)
         # Create ClietProfile
         req = self.ReadSempReq('ClientProfile/CreateClientProfile.xml') % (self.m_version, cpname, vpn)
         self.ProcessSemp("CreateClientProfile_%s" % (cpname),  req)
      else:
         log.note ("Updating ClientProfile %s", cpname)
      # Set ClientProfile properties
      pmap = {}
      if cpdata['allow-bridge-connections'] == 'yes':
         pmap ['EnableBridgeConnections'] = None
      else:
         pmap ['DisableBridgeConnections'] = None

      if cpdata['allow-guaranteed-endpoint-create'] == 'yes':
         pmap ['EnableGuaranteedEndpointCreate'] = None
      else:
         pmap ['DisableGuaranteedEndpointCreate'] = None

      if cpdata['allow-guaranteed-message-send'] == 'yes':
         pmap ['EnableGuaranteedSend'] = None
      else:
         pmap ['DisableGuaranteedSend'] = None

      if cpdata['allow-guaranteed-message-receive'] == 'yes':
         pmap ['EnableGuaranteedReceive'] = None
      else:
         pmap ['DisableGuaranteedReceive'] = None

      if cpdata['allow-transacted-sessions'] == 'yes':
         pmap ['EnableTransactedSessions'] = None
      else:
         pmap ['DisableTransactedSessions'] = None

      pmap ['SetTcpWindowSize'] = [cpdata['tcp-win']]
      pmap ['SetG1QMinBurst'] = [cpdata['g1-queue-min-burst']]
      pmap ['SetMaxConnections'] = [cpdata['max-connections']]
      pmap ['SetMaxEgressFlows'] = [cpdata['max-egress-flows']]
      pmap ['SetMaxIngressFlows'] = [cpdata['max-ingress-flows']]
      pmap ['SetMaxSubscriptions'] = [cpdata['max-subscriptions']]
      pmap ['SetMaxEndpoints'] = [cpdata['max-endpoints']]
      pmap ['SetMaxTransactions'] = [cpdata['max-transactions']]
      pmap ['SetMaxTransactedSessions'] = [cpdata['max-transacted-sessions']]
      for prop in sorted(pmap.keys()):
        reqfile = "ClientProfile/%s.xml" % prop
        pargs =  [cpname,prop,vpn]
	pargs.append (pmap[prop])
	if pmap[prop] is None:
	   log.note ("    %s", prop)
           req = self.ReadSempReq(reqfile) % (self.m_version, cpname,vpn)
	else:
	   log.note ("    %s => %s", prop, pmap[prop])
           log.debug ("Calling ReadSempReq with %s additional args %s (%d)", reqfile, pargs, len(pargs))
	   if len(pmap[prop]) == 1:
              req = self.ReadSempReq(reqfile) % (self.m_version, cpname, vpn, pmap[prop][0])
	   if len(pmap[prop]) == 2:
              req = self.ReadSempReq(reqfile) % (self.m_version, cpname, vpn, pmap[prop][0], pmap[prop][1])
	   if len(pmap[prop]) == 3:
              req = self.ReadSempReq(reqfile) % (self.m_version, cpname, vpn, pmap[prop][0], pmap[prop][1], pmap[prop][2])
        self.ProcessSemp("ClientProfile_%s-%s" % (cpname,prop),  req)

   def CreateClientProfiles(self, vpn, cpnames, update=False):
      log = self.m_logger
      log.enter (" %s::%s  ClientProfile names: %s", __name__, inspect.stack()[0][3], cpnames)
      for cpname in cpnames:
         if cpname not in self.m_cfg.GetClientProfileNames():
	    raise Exception ("ClientProfile name %s not in config" % (cpname))
         self.CreateClientProfile(vpn, cpname, self.m_cfg.GetClientProfileData(cpname), update)


   #-------------------------------------------------------
   # Create ACL Profile
   #
   def CreateACLProfile(self, vpn, aclname, acldata, update=False):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s aclprofile: %s", __name__, inspect.stack()[0][3], vpn, aclname)

      if not update:
         log.note ("Creating ACLProfile %s", aclname)
         # Create ClietProfile
         req = self.ReadSempReq('ACLProfile/CreateACLProfile.xml') % (self.m_version, aclname, vpn)
         self.ProcessSemp("CreateACLProfile_%s" % (aclname),  req)
      else:
         log.note ("Updating ACLProfile %s", aclname)
      # Set ACLProfile properties
      pmap = {}
      # process default actions .. treat True as allow and False as disallow
      pmap ['SetClientConnectDefaultAction'] = acldata['client-connect-default-action']
      pmap ['SetPublishTopicDefaultAction'] = acldata['publish-topic-default-action']
      pmap ['SetSubscribeTopicDefaultAction'] = acldata['subscribe-topic-default-action']
      #if pmap ['SetClientConnectDefaultAction'] is True:
      #   pmap ['SetClientConnectDefaultAction'] = 'allow'
      #if pmap ['SetClientConnectDefaultAction'] is False:
      #   pmap ['SetClientConnectDefaultAction'] = 'disallow'
      #if pmap ['SetPublishTopicDefaultAction'] is True:
      #   pmap ['SetPublishTopicDefaultAction'] = 'allow'
      #if pmap ['SetPublishTopicDefaultAction'] is False:
      #   pmap ['SetPublishTopicDefaultAction'] = 'disallow'
      #if pmap ['SetSubscribeTopicDefaultAction'] is True:
      #   pmap ['SetSubscribeTopicDefaultAction'] = 'allow'
      #if pmap ['SetSubscribeTopicDefaultAction'] is False:
      #   pmap ['SetSubscribeTopicDefaultAction'] = 'disallow'
      for prop in sorted(pmap.keys()):
        reqfile = "ACLProfile/%s.xml" % prop
        pargs =  [aclname,prop,vpn]
	pargs.append (pmap[prop])
	if pmap[prop] is None:
	   log.note ("    %s", prop)
           req = self.ReadSempReq(reqfile) % (self.m_version, aclname,vpn)
	else:
	   log.note ("    %s => %s", prop, pmap[prop])
           log.debug ("Calling ReadSempReq with %s additional args %s (%d)", reqfile, pargs, len(pargs))
           req = self.ReadSempReq(reqfile) % (self.m_version, aclname,vpn, pmap[prop])
        self.ProcessSemp("ACLProfile_%s-%s" % (aclname,prop),  req)
      # process exceptions
      for a in acldata['client-connect-exceptions']:
        prop = 'SetClientConnectException'
        reqfile = "ACLProfile/%s.xml" % prop
	log.note ("    %s => %s", prop, a)
        pargs =  [aclname,prop,vpn, a]
        log.debug ("Calling ReadSempReq with %s additional args %s (%d)", reqfile, pargs, len(pargs))
        req = self.ReadSempReq(reqfile) % (self.m_version, aclname,vpn, a)
        self.ProcessSemp("ACLProfile_%s-%s" % (aclname,prop),  req)
      for a in acldata['publish-topic-exceptions']:
        prop = 'SetPublishTopicException'
        reqfile = "ACLProfile/%s.xml" % prop
	log.note ("    %s => %s", prop, a)
        pargs =  [aclname,prop,vpn, a]
        log.debug ("Calling ReadSempReq with %s additional args %s (%d)", reqfile, pargs, len(pargs))
        req = self.ReadSempReq(reqfile) % (self.m_version, aclname,vpn, a)
        self.ProcessSemp("ACLProfile_%s-%s" % (aclname,prop),  req)
      for a in acldata['subscribe-topic-exceptions']:
        prop = 'SetSubscribeTopicException'
        reqfile = "ACLProfile/%s.xml" % prop
	log.note ("    %s => %s", prop, a)
        pargs =  [aclname,prop,vpn, a]
        log.debug ("Calling ReadSempReq with %s additional args %s (%d)", reqfile, pargs, len(pargs))
        req = self.ReadSempReq(reqfile) % (self.m_version, aclname,vpn, a)
        self.ProcessSemp("ACLProfile_%s-%s" % (aclname,prop),  req)

   def CreateACLProfiles(self, vpn, aclnames, update=False):
      log = self.m_logger
      log.enter (" %s::%s  ACLProfile names: %s", __name__, inspect.stack()[0][3], aclnames)
      for aclname in aclnames:
         if aclname not in self.m_cfg.GetACLProfileNames():
	    raise Exception ("ACLProfile name %s not in config" % (aclname))
         self.CreateACLProfile(vpn, aclname, self.m_cfg.GetACLProfileData(aclname), update)

   #-------------------------------------------------------
   # Create Client user
   #
   def CreateClientUser(self, vpn, cuname, cudata, update=False):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s clientuser: %s", __name__, inspect.stack()[0][3], vpn, cuname)

      if not update:
         log.note ("Creating Client user %s", cuname)
         req = self.ReadSempReq('ClientUser/CreateClientUser.xml') % (self.m_version, cuname, vpn)
         self.ProcessSemp("CreateClientUser_%s" % (cuname),  req)
      else:
         log.note ("Updating Client user %s", cuname)

      # Set ClientUser properties
      pmap = {}
      if cudata['password'] == 'SKIP':
         log.note ('    Skip SetPassword')
      else:
         pmap ['SetPassword'] = [cudata['password']]
      pmap ['SetClientProfile'] = [cudata['client-profile']]
      pmap ['SetACLProfile'] =  [cudata['acl-profile']]
      # set the following from vpndata
      vpndata = self.m_cfg.GetVpnData()
      # this is on client profile
      #pmap ['SetMaxConnections'] =  [vpndata['max-connections']]
      for prop in sorted(pmap.keys()):
        reqfile = "ClientUser/%s.xml" % prop
	if pmap[prop] is None:
	   log.note ("    %s", prop)
           req = self.ReadSempReq(reqfile) % (self.m_version, cuname,vpn)
	else:
           #print "look for password in", prop.lower(),  re.search ('password', prop.lower())
           if re.search ('password', prop.lower()):
	      log.note ("    %s => [*****]", prop)
           else:
	      log.note ("    %s => %s", prop, pmap[prop])
	   log.debug ("property %s for clientUser %s pmap %s len %d", prop, cuname, pmap[prop], len(pmap[prop]))
	   if len(pmap[prop]) == 1:
              req = self.ReadSempReq(reqfile) % (self.m_version, cuname, vpn, pmap[prop][0])
	   if len(pmap[prop]) == 2:
              req = self.ReadSempReq(reqfile) % (self.m_version, cuname, vpn, pmap[prop][0], pmap[prop][1])
	   if len(pmap[prop]) == 3:
              req = self.ReadSempReq(reqfile) % (self.m_version, cuname, vpn, pmap[prop][0], pmap[prop][1], pmap[prop][2])
        self.ProcessSemp("ClientUser_%s-%s" % (cuname,prop), req)

   def CreateClientUsers(self, vpn, cunames, update=False):
      log = self.m_logger
      log.enter (" %s::%s  client-usernames: %s", __name__, inspect.stack()[0][3], cunames)
      # create users
      for cuname in cunames:
         if cuname not in self.m_cfg.GetClientUsernames():
	    raise Exception ("Client username %s not in config" % (cuname))
         self.CreateClientUser(vpn, cuname, self.m_cfg.GetClientUserData(cuname), update)

   def CreateClientUsersAndObjects(self, vpn, update=False):
       log = self.m_logger
       log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
       # don't update profiles if updating
       if not update:
         self.CreateClientProfiles(vpn, self.m_cfg.GetClientProfileNames(), update)
         self.CreateACLProfiles(vpn, self.m_cfg.GetACLProfileNames(), update)
       self.CreateClientUsers(vpn, self.m_cfg.GetClientUsernames(), update)


   #-------------------------------------------------------
   # Create Queues
   #
   def CreateQueue(self, vpn, qname, qdata, update=False):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s Queue: %s", __name__, inspect.stack()[0][3], vpn, qname)
      # get DMQ name
      if qname == "DEAD_MSG_QUEUE" or qname == "DMQ":
         qname = "#DEAD_MSG_QUEUE"

      if not update:
         log.note ("Creating Queue %s", qname)
         log.debug ("qname: %s qdata: %s", qname, qdata)
         req = self.ReadSempReq('Queue/CreateQueue.xml') % (self.m_version, vpn, qname)
         self.ProcessSemp("CreateQueue_%s" % (qname),  req)
      else:
         log.note ("Updating Queue %s", qname)
      # Set Queue properties
      pmap = {}
      ets = qdata['event-thresholds']
      pmap ['SetSpoolUsageThresholds'] = [ets['spool-usage-set'], ets['spool-usage-clear']]
      pmap ['SetBindCountThresholds'] = [ets['bind-count-set'], ets['bind-count-clear']]
      if qdata['respect-ttl'] == 'yes':
         pmap ['EnableRespectTTL'] = None
      else:
         pmap ['DisableRespectTTL'] = None

      if qdata['reject-msg-to-sender-on-discard'] == 'yes':
         pmap ['EnableRejectMsgToSenderOnDiscard'] = None
      else:
         pmap ['DisableRejectMsgToSenderOnDiscard'] = None

      if qdata['others-permission'] == 'no-access':
         log.note ("    Skip SetOtherPermission")
      else:
         pmap ['SetOtherPermission'] =  [qdata['others-permission']]
      pmap ['SetMaxSpoolSize'] =  [qdata['max-spool']]
      pmap ['SetMaxMsgSize'] =  [qdata['max-msg-size']]
      pmap ['SetMaxBindCount'] = [qdata['max-bind-count']]
      pmap ['SetMaxRedelivery'] = [qdata['max-redelivery']]
      pmap ['SetMaxUnackedMsgs'] = [qdata['max-unacked-msgs']]
      pmap ['SetAccessType'] = [qdata['access-type']]
      if qdata['owner'] == 'SKIP':
         log.note ("    Skip SetOwner")
      else:
         pmap ['SetOwner'] =  [qdata['owner']]
      for prop in sorted(pmap.keys()):
        reqfile = "Queue/%s.xml" % prop
	if pmap[prop] is None:
	   log.note ("    %s", prop)
           req = self.ReadSempReq(reqfile) % (self.m_version, vpn, qname)
	else:
	   log.note ("    %s => %s", prop, pmap[prop])
	   log.debug ("property %s for queue %s pmap %s len %d", prop, qname, pmap[prop], len(pmap[prop]))
	   if len(pmap[prop]) == 1:
              req = self.ReadSempReq(reqfile) % (self.m_version, vpn, qname, pmap[prop][0])
	   if len(pmap[prop]) == 2:
              req = self.ReadSempReq(reqfile) % (self.m_version, vpn, qname, pmap[prop][0], pmap[prop][1])
	   if len(pmap[prop]) == 3:
              req = self.ReadSempReq(reqfile) % (self.m_version, qname, vpn, pmap[prop][0], pmap[prop][1], pmap[prop][2])
        self.ProcessSemp("Queue_%s-%s" % (qname,prop), req)

   def CreateQueues(self, vpn, qnames, update=False):
      log = self.m_logger
      log.enter (" %s::%s  queuenames: %s", __name__, inspect.stack()[0][3], qnames)
      # create users
      for qname in qnames:
         if qname not in self.m_cfg.GetQueueNames():
	    raise Exception ("Queuename %s not in config" % (qname))
         self.CreateQueue(vpn, qname, self.m_cfg.GetQueueData(qname), update)

   def CreateQueuesAndObjects(self, vpn, update=False):
       log = self.m_logger
       log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
       self.CreateQueues(vpn, self.m_cfg.GetQueueNames(), update)
       # if updating don't update topic subscriptions
       if update:
          return
       for qname in self.m_cfg.GetQueueNames():
	 if self.m_cfg.QueueHasSubs(qname):
            self.CreateQueueSubs(vpn, qname, self.m_cfg.GetQueueSubs(qname), update)
         else:
	    log.info ("No topic subscriptions for queue %s", qname)

   #-------------------------------------------------------
   # Create Queue Subscriptions
   #
   def CreateQueueSub(self, vpn, qname,  tsname, update=False):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s QueueSub: queue: %s topic-sub: %s", __name__, inspect.stack()[0][3], vpn, qname, tsname)
      #if update:
      #  return
      # fix DMQ name
      if qname == "DEAD_MSG_QUEUE" or qname == "DMQ":
         qname = "#DEAD_MSG_QUEUE"
      log.note ("    Adding topic subscription %s to queue %s", tsname, qname)
      req = self.ReadSempReq('Queue/CreateQueueSub.xml') % (self.m_version, vpn, qname, tsname)
      self.ProcessSemp("CreateQueueSub_%s_%s" % (qname,tsname),  req)

   def CreateQueueSubs(self, vpn, qname, tsnames, update=False):
      log = self.m_logger
      log.enter (" %s::%s  queuename: %s", __name__, inspect.stack()[0][3], qname)
      #if update:
      #   return
      log.note ("Creating topic subsciptions for queue %s", qname)
      # create topic subscriptions
      for tsname in tsnames:
         if tsname not in self.m_cfg.GetQueueSubs(qname):
	    raise Exception ("Topic subscrition %s for queue %s not in config" % (tsname, qname))
         self.CreateQueueSub(vpn, qname, tsname, update)

   def CreateQueuesSubs(self, vpn, qlist, update=False):
       log = self.m_logger
       log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
       for qname in qlist:
	 if self.m_cfg.QueueHasSubs(qname):
            self.CreateQueueSubs(vpn, qname, self.m_cfg.GetQueueSubs(qname), update)
         else:
	    log.info ("No topic subscriptions for queue %s", qname)

   def CreateAllQueuesSubs(self, vpn, update=False):
       log = self.m_logger
       log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
       return self.CreateQueuesSubs (vpn, self.m_cfg.GetQueueNames(), update)

   #-------------------------------------------------------
   # Create Bridges
   #
   def CreateBridge(self, vpn, bridgename, bdata, update=False):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s Bridge: %s update: %s", __name__, inspect.stack()[0][3], vpn, bridgename, update)

      if not update:
         log.note ("Creating Bridge %s", bridgename)
         req = self.ReadSempReq('Bridge/CreateBridge.xml') % (self.m_version, bridgename, vpn)
         self.ProcessSemp("CreateBridge_%s" % (bridgename),  req)
      else:
         log.note ("Updating Bridge %s", bridgename)


      # Set Bridge properties
      pmap = {}
      if bdata.has_key('remote-user'):
         if bdata['remote-user']['password'] == 'SKIP':
            log.note ("    Skip RemoteUserPassword")
         else:
            pmap ['RemoteUser'] =  [bdata['remote-user']['username'], bdata['remote-user']['password']]
      #if bdata.has_key('trusted-common-name'):
      #   pmap ['SSLOptions'] =  [bdata['trusted-common-name']]
      pmap ['SSLOptions'] =  [bdata['trusted-common-name']]
      pmap ['SetTTLValue'] =  [bdata['max-ttl']]
      for prop in pmap.keys():
        if re.search ('user', prop.lower()):
	   log.note ("    %s => [%s, *****]", prop, pmap[prop][0])
        else:
	   log.note ("    %s => %s", prop, pmap[prop])
        reqfile = "Bridge/%s.xml" % prop
	if pmap[prop] is None:
           req = self.ReadSempReq(reqfile) % (self.m_version, bridgename, vpn)
	else:
	   log.debug ("property %s for bridge %s pmap %s len %d", prop, bridgename, pmap[prop], len(pmap[prop]))
	   if len(pmap[prop]) == 1:
              req = self.ReadSempReq(reqfile) % (self.m_version, bridgename, vpn, pmap[prop][0])
	   if len(pmap[prop]) == 2:
              req = self.ReadSempReq(reqfile) % (self.m_version, bridgename, vpn, pmap[prop][0], pmap[prop][1])
	   if len(pmap[prop]) == 3:
              req = self.ReadSempReq(reqfile) % (self.m_version, bridgename, vpn, pmap[prop][0], pmap[prop][1], pmap[prop][2])
        self.ProcessSemp("Bridge_%s-%s" % (bridgename,prop), req)

   def CreateBridges(self, vpn, bridgenames, update=False):
      log = self.m_logger
      log.enter (" %s::%s  bridgenames: %s (update: %s)", __name__, inspect.stack()[0][3], bridgenames,update)
      # create users
      for bridgename in bridgenames:
         if bridgename not in self.m_cfg.GetBridgeNames():
	    raise Exception ("Bridgename %s not in config" % (bridgename))
         self.CreateBridge(vpn, bridgename, self.m_cfg.GetBridgeData(bridgename), update)

   #-------------------------------------------------------
   # Create Bridge Remote Vpns
   #
   def CreateBridgeRemoteVpn(self, vpn, bridgename,  rvpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s bridge: %s remote-vpn: %s", __name__, inspect.stack()[0][3], vpn, bridgename, rvpn)
      rprops =  self.m_cfg.GetBridgeRemoteVpnData(bridgename, rvpn)
      log.trace ("remote vpn data = %s", rprops)
      raddr =  rprops['ip-port']
      log.note ("    Adding Remote VPN %s (remote addr: %s) to bridge %s", rvpn, raddr, bridgename)
      req = self.ReadSempReq('Bridge/CreateRemoteVpn.xml') % (self.m_version, bridgename, vpn, rvpn, raddr)
      self.ProcessSemp("CreateBridgeRemoteVpn_%s_%s" % (bridgename,rvpn),  req)

      pmap = {}
      pmap ['RemoteVpnQueue'] =  [rprops['queue-name']]
      pmap ['RemoteVpnWindowSize'] =  [rprops['window-size']]
      pmap ['SetRemoteConnectOrder'] =  [rprops['connect-order']]
      otag = None
      if re.search('^compress', rprops['options']):
         if (self.m_vmr):
            log.note ("*** RemoteVPN %s option %s ignored for VMR", rvpn, rprops['options'])
            otag = None
	 else:
            otag = 'compressed-data'
      if re.search('^ssl', rprops['options']):
         otag = 'ssl'
      if otag is not None:
         pmap ['RemoteVpnOptions'] =  [otag]
         log.debug ("RemoteVPN %s options tag %s matched %s", rvpn, rprops['options'], otag)
      else:
         log.debug ("No match for RemoteVPN %s options tag %s. No options selected", rvpn, rprops['options'])
      for prop in pmap.keys():
	log.note ("    %s => %s", prop, pmap[prop])
        reqfile = "Bridge/%s.xml" % prop
	if pmap[prop] is None:
           req = self.ReadSempReq(reqfile) % (self.m_version, bridgename, vpn, rvpn, raddr)
	else:
	   log.debug ("property %s for bridge %s pmap %s len %d", prop, bridgename, pmap[prop], len(pmap[prop]))
           req = self.ReadSempReq(reqfile) % (self.m_version, bridgename, vpn, rvpn, raddr, pmap[prop][0])
        self.ProcessSemp("Bridge_%s-%s" % (bridgename,prop), req)

   def CreateBridgeRemoteVpns(self, vpn, bridgename, rvpns):
      log = self.m_logger
      log.enter (" %s::%s  bridge: %s", __name__, inspect.stack()[0][3], bridgename)
      log.note ("Creating remote-vpn for bridge %s", bridgename)
      # create users
      for rvpn in rvpns:
         if rvpn not in self.m_cfg.GetBridgeRemoteVpnNames(bridgename):
	    raise Exception ("Remote VPN %s for bridge %s not in config" % (rvpn, bridgename))
         self.CreateBridgeRemoteVpn(vpn, bridgename, rvpn)


   def CreateBridgesAndObjects(self, vpn, update=False):
       log = self.m_logger
       log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
       self.CreateBridges(vpn, self.m_cfg.GetBridgeNames(),update)
       for bridgename in self.m_cfg.GetBridgeNames():
	 if self.m_cfg.BridgeHasRemoteVpns(bridgename):
            self.CreateBridgeRemoteVpns(vpn, bridgename, self.m_cfg.GetBridgeRemoteVpnNames(bridgename))
         else:
	    self.m_logger.info ("No remote vpns for bridge %s", bridgename)

   #-------------------------------------------------------
   # Create RDP
   #
   def CreateRDP(self, vpn, rdpname, bdata, update=False):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s RDP: %s update: %s", __name__, inspect.stack()[0][3], vpn, rdpname, update)

      if not update:
         log.note ("Creating RDP %s", rdpname)
         req = self.ReadSempReq('REST/CreateRDP.xml') % (self.m_version, vpn, rdpname)
         self.ProcessSemp("CreateRDP_%s" % (rdpname),  req)
      else:
         log.note ("Updating RDP %s", rdpname)


      # Set RDP properties
      pmap = {}
      if bdata.has_key('consumers'):
          pmap ['SetClientProfile'] =  [bdata['client-profile']]
      for prop in pmap.keys():
	log.note ("    %s => %s", prop, pmap[prop])
        reqfile = "REST/%s.xml" % prop
	if pmap[prop] is None:
           req = self.ReadSempReq(reqfile) % (self.m_version, vpn, rdpname)
	else:
	   log.debug ("property %s for RDP %s pmap %s len %d", prop, rdpname, pmap[prop], len(pmap[prop]))
	   if len(pmap[prop]) == 1:
              req = self.ReadSempReq(reqfile) % (self.m_version, vpn, rdpname, pmap[prop][0])
        self.ProcessSemp("RDP_%s-%s" % (rdpname,prop), req)

   def CreateRDPs(self, vpn, rdpnames, update=False):
      log = self.m_logger
      log.enter (" %s::%s  rdpnames: %s (update: %s)", __name__, inspect.stack()[0][3], rdpnames,update)
      # create users
      for rdpname in rdpnames:
         if rdpname not in self.m_cfg.GetRDPNames():
	    raise Exception ("rdpname %s not in config" % (rdpname))
         self.CreateRDP(vpn, rdpname, self.m_cfg.GetRDPData(rdpname), update)

   #-------------------------------------------------------
   # Create RDP Consumer
   #
   def CreateRDPConsumer(self, vpn, rdpname,  rvpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s RDP: %s consumer: %s", __name__, inspect.stack()[0][3], vpn, rdpname, rvpn)
      rprops =  self.m_cfg.GetRDPConsumerData(rdpname, rvpn)
      log.trace ("RDP consumer data = %s", rprops)
      #raddr =  rprops['ip-port']
      log.note ("    Adding Consumer %s to RDP %s", rvpn, rdpname)
      req = self.ReadSempReq('REST/CreateConsumer.xml') % (self.m_version, vpn, rdpname, rvpn)
      self.ProcessSemp("CreateRDPConsumer_%s_%s" % (rdpname,rvpn),  req)

      pmap = {}
      pmap ['SetRemoteHost'] = [rprops['remote-host']]
      pmap ['SetRemotePort'] = [rprops['remote-port']]
      if (self.m_vmr):
         log.note ("*** RDP SSL %s option ignored for VMR ***",  rprops['enable-ssl'])
      else:
         if rprops['enable-ssl'] == 'yes':
            pmap ['EnableSSL'] = None
         else:
            pmap ['DisableSSL'] = None
      for prop in pmap.keys():
	log.note ("    %s => %s", prop, pmap[prop])
        reqfile = "REST/%s.xml" % prop
	if pmap[prop] is None:
           req = self.ReadSempReq(reqfile) % (self.m_version, vpn, rdpname, rvpn)
	else:
	   log.debug ("property %s for RDP %s pmap %s len %d", prop, rdpname, pmap[prop], len(pmap[prop]))
           req = self.ReadSempReq(reqfile) % (self.m_version, vpn, rdpname, rvpn, pmap[prop][0])
        self.ProcessSemp("RDP_%s-%s" % (rdpname,prop), req)

   def CreateRDPConsumers(self, vpn, rdpname, rvpns):
      log = self.m_logger
      log.enter (" %s::%s  RDP: %s", __name__, inspect.stack()[0][3], rdpname)
      log.note ("Creating consumer for RDP %s", rdpname)
      # create users
      for rvpn in rvpns:
         if rvpn not in self.m_cfg.GetRDPConsumerNames(rdpname):
	    raise Exception ("Consumer %s for RDP %s not in config" % (rvpn, rdpname))
         self.CreateRDPConsumer(vpn, rdpname, rvpn)

   # Queue bindings
   def CreateRDPQueueBinding(self, vpn, rdpname,  rvpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s RDP: %s queue: %s", __name__, inspect.stack()[0][3], vpn, rdpname, rvpn)
      rprops =  self.m_cfg.GetRDPQueueBindingData(rdpname, rvpn)
      log.trace ("RDP consumer data = %s", rprops)
      #raddr =  rprops['ip-port']
      log.note ("    Adding QueueBinding %s to RDP %s", rvpn, rdpname)
      req = self.ReadSempReq('REST/CreateQueueBinding.xml') % (self.m_version, vpn, rdpname, rvpn)
      self.ProcessSemp("CreateRDPQueueBinding_%s_%s" % (rdpname,rvpn),  req)

      pmap = {}
      pmap ['SetRequestTarget'] = [rprops['request-target']]
      for prop in pmap.keys():
	log.note ("    %s => %s", prop, pmap[prop])
        reqfile = "REST/%s.xml" % prop
	if pmap[prop] is None:
           req = self.ReadSempReq(reqfile) % (self.m_version, vpn, rdpname, rvpn)
	else:
	   log.debug ("property %s for RDP %s pmap %s len %d", prop, rdpname, pmap[prop], len(pmap[prop]))
           req = self.ReadSempReq(reqfile) % (self.m_version, vpn, rdpname, rvpn, pmap[prop][0])
        self.ProcessSemp("RDP_%s-%s" % (rdpname,prop), req)

   def CreateRDPQueueBindings(self, vpn, rdpname, rvpns):
      log = self.m_logger
      log.enter (" %s::%s  RDP: %s", __name__, inspect.stack()[0][3], rdpname)
      log.note ("Creating QueueBindings for RDP %s", rdpname)
      # create users
      for rvpn in rvpns:
         if rvpn not in self.m_cfg.GetRDPQueueBindingNames(rdpname):
	    raise Exception ("QueueBinding %s for RDP %s not in config" % (rvpn, rdpname))
         self.CreateRDPQueueBinding(vpn, rdpname, rvpn)


   def CreateRDPsAndObjects(self, vpn, update=False):
       log = self.m_logger
       log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
       self.CreateRDPs(vpn, self.m_cfg.GetRDPNames(),update)
       for rdpname in self.m_cfg.GetRDPNames():
           # create remote consumers
	 if self.m_cfg.RDPHasConsumers(rdpname):
            self.CreateRDPConsumers(vpn, rdpname, self.m_cfg.GetRDPConsumerNames(rdpname))
         else:
	    self.m_logger.info ("No Consumer for RDP %s", rdpname)

           # create queue bindings
	 if self.m_cfg.RDPHasQueueBindings(rdpname):
            self.CreateRDPQueueBindings(vpn, rdpname, self.m_cfg.GetRDPQueueBindingNames(rdpname))
         else:
	    self.m_logger.info ("No QueueBindings for RDP %s", rdpname)


   #-------------------------------------------------------
   # Create JNDI
   #
   def CreateConnectionFactory(self, vpn, cfname = "jms/cf", cfdata = None, update=False):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s JNDI: %s", __name__, inspect.stack()[0][3], vpn, cfname)

      if not update:
         log.note ("Creating JNDI Connection Factor %s", cfname)
         req = self.ReadSempReq('JNDI/CreateConnectionFactory.xml') % (self.m_version, vpn, cfname)
         self.ProcessSemp("CreateConnectionFactory_%s" % (cfname),  req)
      else:
         log.note ("Updating JNDI Connection Factory %s", cfname)

      # Set JNDI properties
      pmap = {}
      pmap ['SetConnectRetries'] =  [cfdata['connect-retries']]
      pmap ['SetConnectRetriesPerHost'] =  [cfdata['connect-retries-per-host']]
      pmap ['SetConnectTimeout'] =  [cfdata['connect-timeout']]
      pmap ['SetReconnectRetries'] =  [cfdata['reconnect-retries']]
      pmap ['SetReconnectRetryWait'] =  [cfdata['reconnect-retry-wait']]
      pmap ['SetMaxKeepAliveCount'] =  [cfdata['max-keepalive-count']]
      pmap ['SetDefaultDeliveryMode'] =  [cfdata['default-delivery-mode']]
      pmap ['SetSendADWindowSize'] =  [cfdata['send-ad-window-size']]
      pmap ['SetReceiveADWindowSize'] =  [cfdata['receive-ad-window-size']]

      if cfdata['default-dmq-eligible'] == 'yes':
         pmap ['SetDefaultDMQEligible'] =  ['true']
      else:
         pmap ['SetDefaultDMQEligible'] =  ['false']

      if cfdata['dynamic-durables'] == 'yes':
         pmap ['SetDynamicDurables'] =  ['true']
      else:
         pmap ['SetDynamicDurables'] =  ['false']

      if cfdata['direct-transport'] == 'yes':
         pmap ['SetDirectTransport'] =  ['true']
      else:
         pmap ['SetDirectTransport'] =  ['false']

      if cfdata['respect-ttl'] == 'yes':
         pmap ['SetRespectTTL'] =  ['true']
      else:
         pmap ['SetRespectTTL'] =  ['false']

      for prop in sorted(pmap.keys()):
        reqfile = "JNDI/%s.xml" % prop
	if pmap[prop] is None:
	   log.note ("    %s", prop)
           req = self.ReadSempReq(reqfile) % (self.m_version, vpn, cfname)
	else:
	   log.note ("    %s => %s", prop, pmap[prop])
	   log.debug ("property %s for CF %s pmap %s len %d", prop, cfname, pmap[prop], len(pmap[prop]))
           req = self.ReadSempReq(reqfile) % (self.m_version, vpn, cfname, pmap[prop][0])
        self.ProcessSemp("JNDI_%s-%s" % (cfname,prop), req)

   def CreateConnectionFactories(self, vpn, cfnames, update=False):
      self.m_logger.enter (" %s::%s  CF names: %s", __name__, inspect.stack()[0][3], cfnames)
      for cfname in cfnames:
         if cfname not in self.m_cfg.GetConnectionFactoryNames():
	    raise Exception ("Connection Factory %s not in config" % (cfname))
         self.CreateConnectionFactory(vpn, cfname, self.m_cfg.GetConnectionFactoryData(cfname), update)


   #-------------------------------------------------------
   # Create VPN
   #
   def CreateMsgVpn(self, vpn, vpndata, update=False):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)

      if not update:
         log.note ("Creating Message VPN %s", vpn)
         req = self.ReadSempReq('MsgVpn/CreateMsgVpn.xml') % (self.m_version, vpn)
         rc = self.ProcessSemp("CreateMsgVpn",  req)
	 if rc is None:
	    return
      else:
         log.note ("Updating Message VPN %s", vpn)

      # Set VPN properties
      pmap = {}
      pmap ['SetVpnAuth'] = None
      if vpndata['semp-over-message-bus'] == 'yes':
         pmap ['EnableSempOverMsgBus'] = None
         pmap ['EnableSempOverMsgBusShow'] = None
      else:
         pmap ['DisableSempOverMsgBus'] = None
         pmap ['DisableSempOverMsgBusShow'] = None
      pmap ['SetLargeMsgThreshold'] = [vpndata['large-msg-threshold']]
      pmap ['SetMaxConnections'] =  [vpndata['max-connections']]
      pmap ['SetSpoolSize'] = [vpndata['spool-size']]
      pmap ['SetMaxEndpoints'] = [vpndata['max-endpoints']]
      pmap ['SetMaxTransactions'] = [vpndata['max-transactions']]
      pmap ['SetMaxTransactedSessions'] = [vpndata['max-transacted-sessions']]
      pmap ['SetMaxEgressFlows'] = [vpndata['max-egress-flows']]
      pmap ['SetMaxIngressFlows'] = [vpndata['max-ingress-flows']]
      pmap ['SetMaxSubscriptions'] = [vpndata['max-subscriptions']]
      ets = vpndata['event-thresholds']
      pmap ['SetSpoolUsageThreshold'] = [ets['spool-usage-set'],  ets['spool-usage-clear']]
      pmap ['SetConnectionsThreshold'] = [ets['connection-set'],  ets['connection-clear']]
      pmap ['SetEndpointsThreshold'] = [ets['endpoints-set'],  ets['endpoints-clear']]
      pmap ['SetIngressFlowsThreshold'] = [ets['ingress-flows-set'],  ets['ingress-flows-clear']]
      pmap ['SetEgressFlowsThreshold'] = [ets['egress-flows-set'],  ets['egress-flows-clear']]
      for prop in sorted(pmap.keys()):
        reqfile = "MsgVpn/%s.xml" % prop
	if pmap[prop] is None:
	   log.note ("    %s", prop)
           req = self.ReadSempReq(reqfile) % (self.m_version, vpn)
	else:
	   log.note ("    %s => %s", prop, pmap[prop])
           log.debug ("Calling ReadSempReq with %s additional args %s (%d)", reqfile, pmap[prop], len(pmap[prop]))
	   if len(pmap[prop]) == 1:
              req = self.ReadSempReq(reqfile) % (self.m_version, vpn, pmap[prop][0])
	   if len(pmap[prop]) == 2:
              req = self.ReadSempReq(reqfile) % (self.m_version, vpn, pmap[prop][0], pmap[prop][1])
	   if len(pmap[prop]) == 3:
              req = self.ReadSempReq(reqfile) % (self.m_version, vpn, pmap[prop][0], pmap[prop][1], pmap[prop][2])
        self.ProcessSemp("VPN-%s" % (prop),  req)

   def CreateMsgVpnAndObjects(self, vpn, update=False):
       log = self.m_logger
       log.enter (" %s::%s  VPN %s", __name__, inspect.stack()[0][3], vpn)
       self.CreateMsgVpn(vpn, self.m_cfg.GetVpnData(), update)
       if update:
          return
       self.CreateClientUsersAndObjects(vpn, update)
       self.CreateQueuesAndObjects(vpn, update)
       self.CreateBridgesAndObjects(vpn, update)
       self.CreateRDPsAndObjects(vpn, update)
       self.CreateConnectionFactories(vpn, self.m_cfg.GetConnectionFactoryNames(), update)
       if not update:
          self.EnableMsgVpn(vpn)
   #--------------------------------------------------------------------
   # DELETE FUNCTIONS
   #--------------------------------------------------------------------

   #--------------------------------------------------------------------
   # Delete clientprofile
   #
   def DeleteClientProfile(self, vpn, cpname, cpdata):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s clientprofile: %s", __name__, inspect.stack()[0][3], vpn, cpname)
      log.note ("Deleting ClientProfile %s in VPN %s", cpname, vpn)
      req = self.ReadSempReq('ClientProfile/DeleteClientProfile.xml') % (self.m_version, cpname, vpn)
      self.ProcessSemp("DeleteClientProfile_%s" % (cpname),  req)

   def DeleteClientProfiles(self, vpn, cpnames):
      log = self.m_logger
      log.enter (" %s::%s  ClientProfile names: %s", __name__, inspect.stack()[0][3], cpnames)
      for cpname in cpnames:
         if cpname not in self.m_cfg.GetClientProfileNames():
	    raise Exception ("ClientProfile name %s not in config" % (cpname))
         self.DeleteClientProfile(vpn, cpname, self.m_cfg.GetClientProfileData(cpname))

   #--------------------------------------------------------------------
   # Delete ACL Profile
   #
   def DeleteACLProfile(self, vpn, aclname, acldata):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s aclprofile: %s", __name__, inspect.stack()[0][3], vpn, aclname)
      log.note ("Deleting ACLProfile %s", aclname)
      req = self.ReadSempReq('ACLProfile/DeleteACLProfile.xml') % (self.m_version, aclname, vpn)
      self.ProcessSemp("DeleteACLProfile_%s" % (aclname),  req)

   def DeleteACLProfiles(self, vpn, aclnames):
      log = self.m_logger
      log.enter (" %s::%s  ACLProfile names: %s", __name__, inspect.stack()[0][3], aclnames)
      for aclname in aclnames:
         if aclname not in self.m_cfg.GetACLProfileNames():
	    raise Exception ("ACLProfile name %s not in config" % (aclname))
         self.DeleteACLProfile(vpn, aclname, self.m_cfg.GetACLProfileData(aclname))

   #--------------------------------------------------------------------
   # Delete Client user
   #
   def DeleteClientUser(self, vpn, cuname, cudata):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s clientuser: %s", __name__, inspect.stack()[0][3], vpn, cuname)
      log.note ("Deleting Client user %s", cuname)
      req = self.ReadSempReq('ClientUser/DeleteClientUser.xml') % (self.m_version, cuname, vpn)
      self.ProcessSemp("DeleteClientUser_%s" % (cuname),  req)

   def DeleteClientUsers(self, vpn, cunames):
      self.m_logger.enter (" %s::%s  client-usernames: %s", __name__, inspect.stack()[0][3], cunames)
      for cuname in cunames:
         if cuname not in self.m_cfg.GetClientUsernames():
	    raise Exception ("Client username %s not in config" % (cuname))
         self.DeleteClientUser(vpn, cuname, self.m_cfg.GetClientUserData(cuname))

   def DeleteClientUsersAndObjects(self, vpn):
       log = self.m_logger
       log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
       self.DeleteClientProfiles(vpn, self.m_cfg.GetClientProfileNames())
       self.DeleteACLProfiles (vpn, self.m_cfg.GetACLProfileNames())
       self.DeleteClientUsers(vpn, self.m_cfg.GetClientUsernames())

   #--------------------------------------------------------------------
   # Delete Queues
   #
   def DeleteQueue(self, vpn, qname, qdata):
      log = self.m_logger
      if qname == "DEAD_MSG_QUEUE" or qname == "DMQ":
         qname = "#DEAD_MSG_QUEUE"
      log.enter (" %s::%s  vpn: %s Queue: %s", __name__, inspect.stack()[0][3], vpn, qname)
      self.DisableQueue(vpn, qname)
      log.note ("Deleting Queue %s", qname)
      req = self.ReadSempReq('Queue/DeleteQueue.xml') % (self.m_version, vpn, qname)
      self.ProcessSemp("DeleteQueue_%s" % (qname),  req)

   def DeleteQueues(self, vpn, qnames):
      self.m_logger.enter (" %s::%s  queuenames: %s", __name__, inspect.stack()[0][3], qnames)
      for qname in qnames:
         if qname not in self.m_cfg.GetQueueNames():
	    raise Exception ("Queuename %s not in config" % (qname))
         self.DeleteQueue(vpn, qname, self.m_cfg.GetQueueData(qname))

   def DeleteQueueSub(self, vpn, qname, tsname):
      log = self.m_logger
      # fix DMQ name
      if qname == "DEAD_MSG_QUEUE" or qname == "DMQ":
         qname = "#DEAD_MSG_QUEUE"
      log.enter (" %s::%s  vpn: %s QueueSub: %s topic-sub: %s", __name__, inspect.stack()[0][3], vpn, qname, tsname)
      log.note ("Deleting Topic Subscription %s for queue %s", tsname, qname)
      req = self.ReadSempReq('Queue/DeleteQueueSub.xml') % (self.m_version, vpn, qname, tsname)
      self.ProcessSemp("DeleteQueueSub_%s_%s" % (qname, tsname),  req)

   def DeleteQueueSubs(self, vpn, qname, tsnames):
      self.m_logger.enter (" %s::%s  queue: %s", __name__, inspect.stack()[0][3], qname)
      for tsname in tsnames:
         self.m_logger.debug ("looking for qsub %s in q %s", tsname, qname)
         if tsname not in self.m_cfg.GetQueueSubs(qname):
	    raise Exception ("Topic subscription %s for queue %s not in config" % (tsname, qname))
         self.DeleteQueueSub(vpn, qname, tsname)

   def DeleteQueuesAndObjects(self, vpn):
      self.m_logger.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      for qname in self.m_cfg.GetQueueNames():
	 if self.m_cfg.QueueHasSubs(qname):
            self.DeleteQueueSubs(vpn, qname, self.m_cfg.GetQueueSubs(qname))
         else:
	    self.m_logger.info ("No topic subscriptions for queue %s", qname)
      self.DeleteQueues(vpn, self.m_cfg.GetQueueNames())

   #--------------------------------------------------------------------
   # Delete Bridges
   #
   def DeleteBridge(self, vpn, bridgename, bdata):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s Bridge: %s", __name__, inspect.stack()[0][3], vpn, bridgename)
      #FIXIT - this is broken due to remote vpn dependency
      # delete vpn calls this twice and hence fails
      #for now, disable bridges before deleting them
      #self.DisableBridge(vpn, bridgename)
      log.note ("Deleting Bridge %s", bridgename)
      req = self.ReadSempReq('Bridge/DeleteBridge.xml') % (self.m_version, bridgename, vpn)
      self.ProcessSemp("DeleteBridge_%s" % (bridgename),  req)

   def DeleteBridges(self, vpn, bridgenames):
      self.m_logger.enter (" %s::%s  Bridges: %s", __name__, inspect.stack()[0][3], bridgenames)
      for bridgename in bridgenames:
         if bridgename not in self.m_cfg.GetBridgeNames():
	    raise Exception ("Bridgename %s not in config" % (bridgename))
         self.DeleteBridge(vpn, bridgename, self.m_cfg.GetBridgeData(bridgename))

   def DeleteBridgeRemoteVpn(self, vpn, bridgename, rvpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s Bridge: %s remote-vpn: %s", __name__, inspect.stack()[0][3], vpn, bridgename, rvpn)
      #rvpn = self.m_cfg.GetBridgeRemoteVpnNames(bridgename)
      log.note ("   Deleting Remote VPN %s for bridge %s", rvpn, bridgename)
      #log.debug(" data = %s",   self.m_cfg.GetBridgeRemoteVpnData(bridgename, rvpn))
      raddr =  self.m_cfg.GetBridgeRemoteVpnData(bridgename, rvpn)['ip-port']
      req = self.ReadSempReq('Bridge/DeleteRemoteVpn.xml') % (self.m_version, bridgename, vpn, rvpn, raddr)
      self.ProcessSemp("DeleteBridgeRemoteVpn_%s_%s" % (bridgename, rvpn),  req)

   def DeleteBridgeRemoteVpns(self, vpn, bridgename, rvpns):
      self.m_logger.enter (" %s::%s  bride: %s", __name__, inspect.stack()[0][3], bridgename)
      for rvpn in rvpns:
         self.m_logger.debug ("looking for remote-vpn %s in bridge %s", rvpn, bridgename)
         if rvpn not in self.m_cfg.GetBridgeRemoteVpnNames(bridgename):
	    raise Exception ("Remote VPN %s for bridge %s not in config" % (rvpn, bridgename))
         self.DeleteBridgeRemoteVpn(vpn, bridgename, rvpn)

   def DeleteBridgesAndObjects(self, vpn):
      self.m_logger.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      for bridgename in self.m_cfg.GetBridgeNames():
	 if self.m_cfg.BridgeHasRemoteVpns(bridgename):
            self.DeleteBridgeRemoteVpns(vpn, bridgename, self.m_cfg.GetBridgeRemoteVpnNames(bridgename))
         else:
	    self.m_logger.info ("No remote vpn for bridge %s", bridgename)
      self.DeleteBridges(vpn, self.m_cfg.GetBridgeNames())

   #--------------------------------------------------------------------
   # Delete RDP
   #
   def DeleteRDP(self, vpn, rdp):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s RDP: %s", __name__, inspect.stack()[0][3], vpn, rdp)
      log.note ("Deleting RDP %s", rdp)
      req = self.ReadSempReq('REST/DeleteRDP.xml') % (self.m_version, vpn, rdp)
      self.ProcessSemp("DeleteRDP_%s" % (rdp),  req)

   def DeleteRDPs(self, vpn, rdps):
      self.m_logger.enter (" %s::%s  RDPs: %s", __name__, inspect.stack()[0][3], rdps)
      for rdp in rdps:
         if rdp not in self.m_cfg.GetRDPNames():
	    raise Exception ("RDP %s not in config" % (rdp))
         #self.DeleteRDP(vpn, rdp, self.m_cfg.GetRDPData(rdp))
         self.DeleteRDP(vpn, rdp)

   def DeleteRDPConsumer(self, vpn, rdp, rvpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s RDP: %s consumer: %s", __name__, inspect.stack()[0][3], vpn, rdp, rvpn)
      log.note ("   Deleting Consumer %s for RDP %s", rvpn, rdp)
      #log.debug(" data = %s",   self.m_cfg.GetRDPRemoteVpnData(rdp, rvpn))
      #raddr =  self.m_cfg.GetRDPRemoteVpnData(rdp, rvpn)['ip-port']
      req = self.ReadSempReq('REST/DeleteConsumer.xml') % (self.m_version, vpn, rdp)
      self.ProcessSemp("DeleteRDPConsumer_%s_%s" % (rdp, rvpn),  req)

   def DeleteRDPRConsumers(self, vpn, rdp, consumers):
      self.m_logger.enter (" %s::%s  rdp: %s", __name__, inspect.stack()[0][3], rdp)
      for consumer in consumers:
         self.m_logger.debug ("looking for consumer %s in RDP %s", consumer, rdp)
         if consumer not in self.m_cfg.GetRDPConsumerNames(rdp):
	    raise Exception ("Consumer %s for RDP %s not in config" % (rvpn, rdp))
         self.DeleteRDPConsumer(vpn, rdp, consumer)

   def DeleteRDPsAndObjects(self, vpn):
      self.m_logger.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      for rdp in self.m_cfg.GetRDPNames():
	 if self.m_cfg.RDPHasConsumers(rdp):
            self.DeleteRDPConsumers(vpn, rdp, self.m_cfg.GetRDPConsumerNames(rdp))
         else:
	    self.m_logger.info ("No Consumer for RDP %s", rdp)
      self.DeleteRDPs(vpn, self.m_cfg.GetRDPNames())

   #--------------------------------------------------------------------
   # Delete CF
   #
   def DeleteConnectionFactory(self, vpn, cfname = "jms/cf", cfdata = None):
      log = self.m_logger
      log.enter (" %s::%s  vpn: %s JNDI: %s", __name__, inspect.stack()[0][3], vpn, cfname)
      log.note ("Deleting JNDI ConnectionFactory %s", cfname)
      req = self.ReadSempReq('JNDI/DeleteConnectionFactory.xml') % (self.m_version, vpn, cfname)
      self.ProcessSemp("DeleteJNDI_%s" % (cfname),  req)

   def DeleteConnectionFactories(self, vpn, cfnames):
      self.m_logger.enter (" %s::%s  CF names: %s", __name__, inspect.stack()[0][3], cfnames)
      self.DisableJNDI(vpn)
      for cfname in cfnames:
         if cfname not in self.m_cfg.GetConnectionFactoryNames():
	    raise Exception ("Connection Factory %s not in config" % (cfname))
         self.DeleteConnectionFactory(vpn, cfname, self.m_cfg.GetConnectionFactoryData(cfname))

   #--------------------------------------------------------------------
   # Delete VPN
   #
   def DeleteMsgVpn(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("Deleting Message VPN %s", vpn)
      req = self.ReadSempReq('MsgVpn/DeleteMsgVpn.xml') % (self.m_version, vpn)
      self.ProcessSemp("DeleteMsgVpn",  req)

   def DeleteMsgVpnAndObjects(self, vpn):
       log = self.m_logger
       log.enter (" %s::%s  VPN %s", __name__, inspect.stack()[0][3], vpn)
       self.DisableMsgVpn(vpn)
       self.DeleteConnectionFactories(vpn, self.m_cfg.GetConnectionFactoryNames())
       self.DeleteBridgesAndObjects(vpn)
       self.DeleteQueuesAndObjects(vpn)
       self.DeleteClientUsersAndObjects(vpn)
       self.DeleteMsgVpn(vpn)



   #--------------------------------------------------------------------
   # ENABLE FUNCTIONS
   #--------------------------------------------------------------------

   #--------------------------------------------------------------------
   # Enable Clientuser
   #
   def EnableClientUser(self, vpn, cuname):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Enabling ClientUser %s", cuname)
      req = self.ReadSempReq('ClientUser/EnableClientUser.xml') % (self.m_version, cuname, vpn)
      self.ProcessSemp("EnableClientUser_%s" % (cuname),  req)

   def EnableClientUsers(self, vpn, cunames):
      log = self.m_logger
      log.enter (" %s::%s  cunames: %s", __name__, inspect.stack()[0][3], cunames)
      log.note ("Enabling ClientUsers")
      for cuname in cunames:
         if self.m_cfg and cuname not in self.m_cfg.GetClientUsernames():
	    raise Exception ("ClientUsername %s not in config" % (cuname))
         if re.search ('^#', cuname):
             continue
         self.EnableClientUser(vpn, cuname)

   #--------------------------------------------------------------------
   # Enable Queues
   #
   def EnableQueue(self, vpn, qname):
      log = self.m_logger
      if qname == "DEAD_MSG_QUEUE" or qname == "DMQ":
         qname = "#DEAD_MSG_QUEUE"
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Enabling Queue %s", qname)
      req = self.ReadSempReq('Queue/EnableQueue.xml') % (self.m_version, vpn, qname)
      self.ProcessSemp("EnableQueue_%s" % (qname),  req)

   def EnableQueues(self, vpn, qnames):
      log = self.m_logger
      log.enter (" %s::%s  qnames: %s", __name__, inspect.stack()[0][3], qnames)
      log.note ("Enabling Queues")
      for qname in qnames:
         if self.m_cfg and qname not in self.m_cfg.GetQueueNames():
	    raise Exception ("Queuename %s not in config" % (qname))
         self.EnableQueue(vpn, qname)

   #--------------------------------------------------------------------
   # Purge Queues
   #
   def PurgeQueue(self, vpn, qname):
      log = self.m_logger
      if qname == "DEAD_MSG_QUEUE" or qname == "DMQ":
         qname = "#DEAD_MSG_QUEUE"
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Purging Queue %s", qname)
      req = self.ReadSempReq('Queue/PurgeQueue.xml') % (self.m_version, vpn, qname)
      self.ProcessSemp("PurgeQueue_%s" % (qname),  req)

   def PurgeQueues(self, vpn, qnames):
      log = self.m_logger
      log.enter (" %s::%s  qnames: %s", __name__, inspect.stack()[0][3], qnames)
      log.note ("Purging Queues")
      for qname in qnames:
         self.PurgeQueue(vpn, qname)


   #--------------------------------------------------------------------
   # Enable Bridges
   #
   def EnableBridge(self, vpn, bridge):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Enabling Bridge %s", bridge)
      req = self.ReadSempReq('Bridge/EnableBridge.xml') % (self.m_version, bridge, vpn)
      self.ProcessSemp("EnableBridge_%s" % (bridge),  req)
      rbridges = self.m_cfg.GetBridgeRemoteVpnNames(bridge) if self.m_cfg else self.GetBridgeRemoteVpnNames(vpn, bridge)
      for rvpn in rbridges:
         log.note ("      Enabling Remote VPN %s for Bridge %s", rvpn, bridge)
         raddr = None
         if self.m_cfg:
            raddr =  self.m_cfg.GetBridgeRemoteVpnData(bridge, rvpn)['ip-port']
         else:
            raddr =  self.GetBridgeRemoteVpnAddr(vpn, bridge, rvpn)
         req = self.ReadSempReq('Bridge/EnableRemoteVpn.xml') % (self.m_version, bridge, vpn, rvpn, raddr)
         self.ProcessSemp("EnableBridgeRemoteVpn_%s_%s" % (bridge, rvpn),  req)

   def EnableBridges(self, vpn, bridgenames):
      log = self.m_logger
      log.enter (" %s::%s  bridgenames: %s", __name__, inspect.stack()[0][3], bridgenames)
      log.note ("Enabling Bridges")
      for bridgename in bridgenames:
         if re.search ('^#bridge', bridgename):
             log.info ("Skipping Bridge %s", bridge)
             continue
         if self.m_cfg and bridgename not in self.m_cfg.GetBridgeNames():
	    raise Exception ("Bridgename %s not in config" % (bridgename))
         self.EnableBridge(vpn, bridgename)


   #--------------------------------------------------------------------
   # Enable RDP
   #
   def EnableRDP(self, vpn, rdp):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Enabling RDP %s", rdp)
      # Enable consumers
      consumers = self.m_cfg.GetRDPConsumerNames(rdp) if self.m_cfg else self.GetRDPConsumerNames(vpn, rdp)
      for consumer in consumers:
         log.note ("      Enabling Consumer %s for RDP %s", consumer, rdp)
         req = self.ReadSempReq('REST/EnableConsumer.xml') % (self.m_version, vpn, rdp, consumer)
         self.ProcessSemp("EnableConsumer_%s_%s" % (vpn, consumer),  req)
      # Enable RDP
      req = self.ReadSempReq('REST/EnableRDP.xml') % (self.m_version, vpn, rdp)
      self.ProcessSemp("EnableRDP_%s" % (vpn),  req)

   def EnableRDPs(self, vpn, rdps):
      log = self.m_logger
      log.enter (" %s::%s  RDPs: %s", __name__, inspect.stack()[0][3], rdps)
      log.note ("Enabling RDPs")
      for rdp in rdps:
         if self.m_cfg and rdp not in self.m_cfg.GetRDPNames():
	    raise Exception ("RDP %s not in config" % (rdp))
         self.EnableRDP(vpn, rdp)

   #--------------------------------------------------------------------
   # Enable JNDI
   #
   def EnableJNDI(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Enabling JNDI")
      req = self.ReadSempReq('JNDI/EnableJNDI.xml') % (self.m_version, vpn)
      self.ProcessSemp("EnableJNDI",  req)

   #--------------------------------------------------------------------
   # Enable VPN
   #
   def EnableMsgVpn(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      self.EnableJNDI(vpn)
      self.EnableRDPs(vpn, self.m_cfg.GetRDPNames() if self.m_cfg else self.GetRDPNames(vpn))
      self.EnableBridges(vpn, self.m_cfg.GetBridgeNames() if self.m_cfg else self.GetBridgeNames(vpn))
      self.EnableQueues(vpn, self.m_cfg.GetQueueNames() if self.m_cfg else self.GetQueueNames(vpn))
      self.EnableClientUsers(vpn, self.m_cfg.GetClientUsernames() if self.m_cfg else self.GetClientUsernames(vpn))
      log.note ("Enabling Message VPN %s", vpn)
      req = self.ReadSempReq('MsgVpn/EnableMsgVpn.xml') % (self.m_version, vpn)
      self.ProcessSemp("EnableMsgVpn" ,  req)


   #--------------------------------------------------------------------
   # DISABLE FUNCTIONS
   #--------------------------------------------------------------------

   #--------------------------------------------------------------------
   # Disable Clientuser
   #
   def DisableClientUser(self, vpn, cuname):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Disabling ClientUser %s", cuname)
      req = self.ReadSempReq('ClientUser/DisableClientUser.xml') % (self.m_version, cuname, vpn)
      self.ProcessSemp("DisableClientUser_%s" % (cuname),  req)

   def DisableClientUsers(self, vpn, cunames):
      log = self.m_logger
      log.enter (" %s::%s  cunames: %s", __name__, inspect.stack()[0][3], cunames)
      log.note ("Disabling ClientUsers")
      for cuname in cunames:
         if self.m_cfg and cuname not in self.m_cfg.GetClientUsernames():
	    raise Exception ("ClientUsername %s not in config" % (cuname))
         if re.search ('^#', cuname):
             continue
         self.DisableClientUser(vpn, cuname)

   #--------------------------------------------------------------------
   # Disable Queues
   #
   def DisableQueue(self, vpn, qname):
      log = self.m_logger
      if qname == "DEAD_MSG_QUEUE" or qname == "DMQ":
         qname = "#DEAD_MSG_QUEUE"
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Disabling Queue %s", qname)
      req = self.ReadSempReq('Queue/DisableQueue.xml') % (self.m_version, vpn, qname)
      self.ProcessSemp("DisableQueue_%s" % (qname),  req)

   #--------------------------------------------------------------------
   # Disable Queues
   #
   def DisableQueues(self, vpn, qnames):
      log = self.m_logger
      log.enter (" %s::%s  vpn %s qnames: %s", __name__, inspect.stack()[0][3], vpn, qnames)
      log.note ("Disabling Queues")
      for qname in qnames:
         if self.m_cfg and qname not in self.m_cfg.GetQueueNames():
	    raise Exception ("Queuename %s not in config" % (qname))
         self.DisableQueue(vpn, qname)

   #--------------------------------------------------------------------
   # Disable Bridges
   #
   def DisableBridge(self, vpn, bridge):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Disabling Bridge %s", bridge)
      req = self.ReadSempReq('Bridge/DisableBridge.xml') % (self.m_version, bridge, vpn)
      self.ProcessSemp("DisbleBridge_%s" % (bridge),  req)
      rbridges = self.m_cfg.GetBridgeRemoteVpnNames(bridge) if self.m_cfg else self.GetBridgeRemoteVpnNames(vpn, bridge)
      for rvpn in rbridges:
         log.note ("      Disabling Remote VPN %s for Bridge %s", rvpn, bridge)
         raddr = None
         if self.m_cfg:
            raddr =  self.m_cfg.GetBridgeRemoteVpnData(bridge, rvpn)['ip-port']
         else:
            raddr =  self.GetBridgeRemoteVpnAddr(vpn, bridge, rvpn)
         req = self.ReadSempReq('Bridge/DisableRemoteVpn.xml') % (self.m_version, bridge, vpn, rvpn, raddr)
         self.ProcessSemp("DisableBridgeRemoteVpn_%s_%s" % (bridge, rvpn),  req)

   def DisableBridgeRemoteVpn(self, vpn, bridge):
      log = self.m_logger
      for rvpn in self.m_cfg.GetBridgeRemoteVpnNames(bridge):
         log.note ("    Disabling Remote VPN %s for Bridge %s", rvpn, bridge)
         raddr =  self.m_cfg.GetBridgeRemoteVpnData(bridge, rvpn)['ip-port']
         req = self.ReadSempReq('Bridge/DisableRemoteVpn.xml') % (self.m_version, bridge, vpn, rvpn, raddr)
         self.ProcessSemp("DisableBridgeRemoteVpn_%s_%s" % (bridge, rvpn),  req)

   def DisableBridges(self, vpn, bridgenames):
      log = self.m_logger
      log.enter (" %s::%s  bridgenames: %s", __name__, inspect.stack()[0][3], bridgenames)
      self.m_logger.enter (" %s::%s  bridgenames: %s", __name__, inspect.stack()[0][3], bridgenames)
      log.note ("Disabling Bridges")
      for bridgename in bridgenames:
         if self.m_cfg and bridgename not in self.m_cfg.GetBridgeNames():
	    raise Exception ("Bridgename %s not in config" % (bridgename))
         self.DisableBridge(vpn, bridgename)

   #--------------------------------------------------------------------
   # Disable JNDI
   #
   def DisableJNDI(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Disabling JNDI")
      req = self.ReadSempReq('JNDI/DisableJNDI.xml') % (self.m_version, vpn)
      self.ProcessSemp("DisableJNDI" ,  req)

   #--------------------------------------------------------------------
   # Disable RDP
   #
   def DisableRDP(self, vpn, rdp):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.note ("    Disabling RDP %s", rdp)
      # Disable consumers
      consumers = self.m_cfg.GetRDPConsumerNames(rdp) if self.m_cfg else self.GetRDPConsumerNames(vpn, rdp)
      for consumer in consumers:
         log.note ("      Disabling Consumer %s for RDP %s", consumer, rdp)
         req = self.ReadSempReq('REST/DisableConsumer.xml') % (self.m_version, vpn, rdp, consumer)
         self.ProcessSemp("DisableConsumer_%s_%s" % (vpn, consumer),  req)
      # Disable RDP
      req = self.ReadSempReq('REST/DisableRDP.xml') % (self.m_version, vpn, rdp)
      self.ProcessSemp("DisableRDP_%s" % (vpn),  req)

   def DisableRDPs(self, vpn, rdps):
      log = self.m_logger
      log.enter (" %s::%s  RDPs: %s", __name__, inspect.stack()[0][3], rdps)
      log.note ("Disabling RDPs")
      for rdp in rdps:
         if self.m_cfg and rdp not in self.m_cfg.GetRDPNames():
	    raise Exception ("RDP %s not in config" % (rdp))
         self.DisableRDP(vpn, rdp)

   #--------------------------------------------------------------------
   # Disable VPN
   #
   def DisableMsgVpn(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      self.DisableJNDI(vpn)
      self.DisableBridges(vpn, self.m_cfg.GetBridgeNames() if self.m_cfg else self.GetBridgeNames(vpn))
      self.DisableQueues(vpn, self.m_cfg.GetQueueNames() if self.m_cfg else self.GetQueueNames(vpn))
      self.DisableClientUsers(vpn, self.m_cfg.GetClientUsernames() if self.m_cfg else self.GetClientUsernames(vpn))
      log.note ("Disabling Message VPN %s", vpn)
      req = self.ReadSempReq('MsgVpn/DisableMsgVpn.xml') % (self.m_version, vpn)
      self.ProcessSemp("DisableMsgVpn" ,  req)

     # -------------------------------------------------------------------------
     # SHOW COMMANDS
     # -------------------------------------------------------------------------

   #-------------------------------------------------------
   # Show version
   #
   def ShowVersionSemp(self):
       self.m_logger.enter (" %s::%s ", __name__, inspect.stack()[0][3])

       r = '<show> <version/> </show>'
       return self.PostSemp(r)

   #--------------------------------------------------------------------
   # Show VPN
   #
   def ShowMsgVpn(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting Message VPN %s", vpn)
      req = self.ReadSempReq('MsgVpn/ShowMsgVpn.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowMsgVpn" ,  req)

   def ShowMsgSpool(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting Message Spool for VPN %s", vpn)
      req = self.ReadSempReq('MsgVpn/ShowMsgSpool.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowMsgSpool" ,  req)

   #--------------------------------------------------------------------
   # Show Queues
   #
   def ShowQueues(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting Queue details VPN %s", vpn)
      req = self.ReadSempReq('Queue/ShowQueues.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowQueue" ,  req)

   def ShowQueueSubscriptions(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting Queue subscription details VPN %s", vpn)
      req = self.ReadSempReq('Queue/ShowQueueSubscriptions.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowQueueSubscriptions" ,  req)

   #--------------------------------------------------------------------
   # Show Client Profile
   #
   def ShowClientProfiles(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting Client profiles for VPN %s", vpn)
      req = self.ReadSempReq('ClientProfile/ShowClientProfiles.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowClientProfiles" ,  req)

   #--------------------------------------------------------------------
   # Show ACL Profile
   #
   def ShowACLProfiles(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting ACL profiles for VPN %s", vpn)
      req = self.ReadSempReq('ACLProfile/ShowACLProfiles.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowACLProfiles" ,  req)

   #--------------------------------------------------------------------
   # Show Client username
   #
   def ShowClientUsernames(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting Client Usernames for VPN %s", vpn)
      req = self.ReadSempReq('ClientUser/ShowClientUsernames.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowClientUsernames" ,  req)

   #--------------------------------------------------------------------
   # Show Bridges
   #
   def ShowBridges(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting bridges for VPN %s", vpn)
      req = self.ReadSempReq('Bridge/ShowBridges.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowBridges" ,  req)

   def ShowBridgesSSL(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting bridges-ssl for VPN %s", vpn)
      req = self.ReadSempReq('Bridge/ShowBridgesSSL.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowBridgesSSL" ,  req)

   #--------------------------------------------------------------------
   # Show RDP
   #
   def ShowRDPs(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting RDP info for VPN %s", vpn)
      req = self.ReadSempReq('REST/ShowRDPs.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowRDPs" ,  req)

   def ShowRDPQueueBindings(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting RDP Queue Bindings for VPN %s", vpn)
      req = self.ReadSempReq('REST/ShowRDPQueueBindings.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowRDPQueueBindings" ,  req)

   def ShowRestConsumers(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting Rest Consumers info for VPN %s", vpn)
      req = self.ReadSempReq('REST/ShowRestConsumers.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowRestConsumers" ,  req)


   #--------------------------------------------------------------------
   # Show JNDI
   #
   def ShowJNDI(self, vpn):
      log = self.m_logger
      log.enter (" %s::%s  vpn = %s", __name__, inspect.stack()[0][3], vpn)
      log.info ("   Getting JNDI info for VPN %s", vpn)
      req = self.ReadSempReq('JNDI/ShowJNDI.xml') % (self.m_version, vpn)
      return self.ProcessSemp("ShowJNDI" ,  req)

     # -------------------------------------------------------------------------
     # GET FUNCTIONS
     # -------------------------------------------------------------------------

     #-----------------------------------------------------------------------------------
     # Get VPN
     #
   def GetMsgVpn(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         # show message vpn
         resp = self.ShowMsgVpn(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         vpninfo = rxml.GetMsgVpn()
         log.debug ("vpninfo: %s", vpninfo)

         # show message-spool
         resp = self.ShowMsgSpool(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         spoolinfo = rxml.GetMsgSpool()
         log.debug ("spoolinfo: %s", spoolinfo)

         vpninfo =  [merge(vpninfo, spoolinfo)]
         log.debug ("returning vpn+spoolinfo: %s", vpninfo)
         return vpninfo

     #-----------------------------------------------------------------------------------
     # Get Queues
     #
   def GetQueues(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         # show queue
         qinfolist = []
         resp = self.ShowQueues(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         qinfo = rxml.GetQueues()
         log.trace ("qinfo: %s", qinfo)

         # show queue subscriptions
         resp = self.ShowQueueSubscriptions(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         qsubs = rxml.GetQueueSubscriptions()
         for qi in qinfo:
            qname = qi['name']
   	    log.debug ("looking for qname: %s", qname)
            qs = filter(lambda qsubs: qsubs['name'] == qname, qsubs)[0]
   	    log.debug ("qinfo %s", qi)
   	    log.debug ("qsubs %s", qs)
   	    qinfolist.append(merge(qi,qs))
         log.trace ("qinfolist: %s", qinfolist)
         return qinfolist

     #-----------------------------------------------------------------------------------
     # Get client profiles
     #
   def GetClientProfiles(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowClientProfiles(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         cpinfolist = rxml.GetClientProfiles()
         log.debug ("client-profile info: %s", cpinfolist)
         return cpinfolist

     #-----------------------------------------------------------------------------------
     # Get ACL profiles
     #
   def GetACLProfiles(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowACLProfiles(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         aclinfolist = rxml.GetACLProfiles()
         log.debug ("acl-profile info: %s", aclinfolist)

         return aclinfolist

     #-----------------------------------------------------------------------------------
     # Get client user names
     #
   def GetClientUsernames(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowClientUsernames(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         names = rxml.GetClientUsernames()
         log.debug ("client usernames: %s", names)
         return names

     #-----------------------------------------------------------------------------------
     # Get client usernames
     #
   def GetClientUserInfo(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowClientUsernames(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         userinfolist = rxml.GetClientUserInfo()
         log.debug ("clientuser info: %s", userinfolist)
         return userinfolist

     #-----------------------------------------------------------------------------------
     # Get queue names
     #
   def GetQueueNames(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowQueues(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         names = rxml.GetQueueNames()
         log.debug ("queue names: %s", names)
         return names

     #-----------------------------------------------------------------------------------
     # Get remote bridge names
     #
   def GetBridgeRemoteVpnNames(self, vpn, bridge):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowBridges(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         names = rxml.GetBridgeRemoteVpnNames(bridge)
         log.debug ("remote bridge names: %s", names)
         return names

   def GetBridgeRemoteVpnAddr(self, vpn, bridge, rvpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowBridges(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         names = rxml.GetBridgeRemoteVpnAddr(bridge, rvpn)
         log.debug ("remote vpn %s/%s addr: %s", bridge, rvpn, names)
         return names

     #-----------------------------------------------------------------------------------
     # Get bridges
     #
   def GetBridges(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowBridges(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         bridgeinfolist = rxml.GetBridges()
         log.debug ("bridge info: %s", bridgeinfolist)

         # show bridge ssl
         resp = self.ShowBridgesSSL(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         sslinfo = rxml.GetBridgesSSL()
         i=0
         for b in bridgeinfolist:
            bridgeinfolist[i]['trusted-common-name'] = sslinfo[i]['trusted-common-name']
            i=i+1
         return bridgeinfolist

     #-----------------------------------------------------------------------------------
     # Get bridge names
     #
   def GetBridgeNames(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowBridges(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         names = rxml.GetBridgeNames()
         log.debug ("bridge names: %s", names)
         return names

     #-----------------------------------------------------------------------------------
     # Get RDP
     # TODO: This returns partial info only
   def GetRDPs(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowRDPs(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         rdplist = rxml.GetRDPs()
         log.debug ("RDP info: %s", rdplist)

         resp = self.ShowRDPQueueBindings(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         qinfolist = rxml.GetRDPQueueBindings()
         log.debug ("RDP Queue Binding info: %s", qinfolist)

         resp = self.ShowRestConsumers(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         cinfolist = rxml.GetRestConsumers()
         log.debug ("RDP Client info: %s", cinfolist)

         # merage consumer and queue-bindings info
         rdpinfolist = []
         for rdp in rdplist:
          rdpname = rdp['name']
          rdpinfo = {}
          #rdpinfo['name'] = rdpname
          rdpinfo = rdp
          for qinfo in qinfolist:
            if qinfo['rdp-name'] == rdpname:
              #del qinfo['rdp-name'] -- errors out ? 
              rdpinfo['queue-bindings'] = [qinfo]
          for cinfo in cinfolist:
             if cinfo['rdp-name'] == rdpname:
              #del cinfo['rdp-name']
              rdpinfo['consumers'] = [cinfo]
	  rdpinfolist.append(rdpinfo)

         log.debug ("RDP info (merged): %s", rdpinfolist)

         return rdpinfolist

     #-----------------------------------------------------------------------------------
     # Get rdp names
     #
   def GetRDPNames(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowRDPs(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         names = rxml.GetRDPNames()
         log.debug ("rdp names: %s", names)
         return names

     #-----------------------------------------------------------------------------------
     # Get jndi
     #
   def GetJNDI(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)

         resp = self.ShowJNDI(vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         jndiinfolist = rxml.GetJNDI()
         log.debug ("JNDI info: %s", jndiinfolist)
         return jndiinfolist

     #-----------------------------------------------------------------------------------
     # Get all VPN objects
     # FIXME: keys hard coded ..
   def GetMsgVpnConfig(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s  %s", __name__, inspect.stack()[0][3], vpn)
         log.note ("Getting VPN Config for %s", vpn)

         vpncfg = {}
         vpncfg['vpn'] = self.GetMsgVpn(vpn)
         vpncfg['client-profiles'] = self.GetClientProfiles(vpn)
         vpncfg['acl-profiles'] = self.GetACLProfiles(vpn)
         vpncfg['client-users'] = self.GetClientUserInfo(vpn)
         vpncfg['queues'] = self.GetQueues(vpn)
         vpncfg['bridges'] = self.GetBridges(vpn)
         vpncfg['rest-delivery-points'] = self.GetRDPs(vpn)
         vpncfg['jndi'] = self.GetJNDI(vpn)

         return vpncfg
	 # no need to make NameMap as VPN YAML cfg doesn't assume or accept it
         #return self.makeNameMap(vpncfg)

       #--------------------------------------------------------------------------------
       # Show Stats commands
       #
   def ShowMsgSpoolDetails(self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      log.info ("   Getting MsgSpool details")

       #--------------------------------------------------------------------------------
       # Show Stats commands
       #
   def GetSystemStats(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s", __name__, inspect.stack()[0][3])

         log.note ("Getting System details")

         log.info ("   Processing ShowHostname")
         req  = self.ReadSempReq('Show/ShowHostname.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowHostname",  req, vpn)

         log.info ("   Processing ShowMsgSpoolDetails")
         req  = self.ReadSempReq('Show/ShowMsgSpoolDetails.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowMsgSpoolDetails",  req, vpn)

         log.info ("   Processing ShowMsgSpoolStats")
         req  = self.ReadSempReq('Show/ShowMsgSpoolStats.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowMsgSpoolStats",  req, vpn)

         log.info ("   Processing ShowClientStats")
         req  = self.ReadSempReq('Show/ShowClientStats.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowClientStats",  req, vpn)

	 pxml = {}
         return pxml

   # -------------------------------------------------------------------------------
   # GetVpnDetails
   #  this is called from possolmon -> POSSolStats.py
   #  this generates response XML file which is readin by possolmon.py later
   #  the filename itself is returned by ReqRespXmlFiles method below
   # Arguments:
   #  vpn
   # Returns:
   #  None
   def GetVpnStats(self, vpn):
         log = self.m_logger
         log.enter (" %s::%s vpn: %s", __name__, inspect.stack()[0][3], vpn)

         log.note ("Getting VPN details for VPN %s", vpn)

	 # process single vpn
         log.info ("   Processing ShowVpnDetails")
         req  = self.ReadSempReq('Show/ShowVpnDetails.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ShowVpnDetails",  req, vpn)

         log.info ("   Processing ShowVpnStats")
         req  = self.ReadSempReq('Show/ShowVpnStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ShowVpnStats",  req, vpn)

         log.info ("   Processing ShowSpoolDetails")
         req  = self.ReadSempReq('Show/ShowSpoolDetails.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ShowSpoolDetails",  req, vpn)

         log.info ("   Processing ShowQueueDetails")
         req  = self.ReadSempReq('Show/ShowQueueDetails.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ShowQueueDetails",  req, vpn)

         log.info ("   Processing ShowClientDetails")
         req  = self.ReadSempReq('Show/ShowClientDetails.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ShowClientDetails",  req, vpn)

         log.info ("   Processing ShowBridgeDetails")
         req  = self.ReadSempReq('Show/ShowBridgeDetails.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ShowBridgeDetails",  req, vpn)

         return {}

   def GetVpnNames(self):
       if self.m_vpnnames is None:
           req  = self.ReadSempReq('Show/ShowAllSpoolDetails.xml') % (self.m_version)
           resp =  self.ProcessSemp("ShowSpoolDetails",  req)
           rxml = posxml.POSSolXml(self.m_prog, resp)
           rxml.BasePath('./rpc/show/message-spool/message-vpn/vpn')
           self.m_vpnnames = rxml.FindAll('/name')
       return self.m_vpnnames

       #--------------------------------------------------------------------------------
       # Get All VPNs Details
       # Note: keep the ProcesSemp arg names to be the same as GetVpnStats
       #
   def GetAllVpnStats(self, vpn = 'ALL'):
         log = self.m_logger
         log.enter (" %s::%s VPN: %s", __name__, inspect.stack()[0][3], vpn)
         log.note ("Getting All VPN details")

         log.info ("   Processing ShowAllVpnDetails")
         req  = self.ReadSempReq('Show/ShowAllVpnDetails.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowVpnDetails",  req, vpn)


         log.info ("   Processing ShowAllVpnStats")
         req  = self.ReadSempReq('Show/ShowAllVpnStats.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowVpnStats",  req, vpn)

         log.info ("   Processing ShowAllSpoolDetails")
         req  = self.ReadSempReq('Show/ShowAllSpoolDetails.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowSpoolDetails",  req, vpn)
         rxml = posxml.POSSolXml(self.m_prog, resp)
         rxml.BasePath('./rpc/show/message-spool/message-vpn/vpn')
         self.m_vpnnames = rxml.FindAll('/name')

         log.info ("   Processing ShowAllQueueDetails")
         req  = self.ReadSempReq('Show/ShowAllQueueDetails.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowQueueDetails",  req, vpn)

         log.info ("   Processing ShowAllClientDetails")
         req  = self.ReadSempReq('Show/ShowAllClientDetails.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowClientDetails",  req, vpn)

         log.info ("   Processing ShowAllBridgeDetails")
         req  = self.ReadSempReq('Show/ShowAllBridgeDetails.xml') % (self.m_version)
         resp =  self.ProcessSemp("ShowBridgeDetails",  req, vpn)

         return {}


       #--------------------------------------------------------------------------------
       # Clear stats
       #
   def ClearSystemStats(self):

         log = self.m_logger
         log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
         log.note ("Clearing System stats")

         log.note ("   Processing ClearSSLStats")
         req  = self.ReadSempReq('Clear/ClearSystemSSLStats.xml') % (self.m_version)
         resp =  self.ProcessSemp("ClearSystemSSLStats",  req)

         log.note ("   Processing ClearCompressionStats")
         req  = self.ReadSempReq('Clear/ClearSystemCompressionStats.xml') % (self.m_version)
         resp =  self.ProcessSemp("ClearSystemCompressionStats",  req)

         log.note ("   Processing ClearClientStats")
         req  = self.ReadSempReq('Clear/ClearSystemClientStats.xml') % (self.m_version)
         resp =  self.ProcessSemp("ClearSystemClientStats",  req)

         log.note ("   Processing ClearSpoolStats")
         req  = self.ReadSempReq('Clear/ClearSystemMessageSpoolStats.xml') % (self.m_version)
         resp =  self.ProcessSemp("ClearSystemMessageSpoolStats",  req)

         log.note ("   Processing ClearReplicationStats")
         req  = self.ReadSempReq('Clear/ClearSystemReplicationStats.xml') % (self.m_version)
         resp =  self.ProcessSemp("ClearSystemReplicationStats",  req)

   def ClearVpnStats(self, vpns ):

       for vpn in vpns:
         log = self.m_logger
         log.enter (" %s::%s VPN: %s", __name__, inspect.stack()[0][3], vpn)
         log.note ("Clearing VPN stats for %s" % (vpn))

         log.note ("   Processing ClearMsgVpnStats")
         req  = self.ReadSempReq('Clear/ClearMsgVpnStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearMsgVpnStats",  req, vpn)

         log.note ("   Processing ClearMsgVpnSpoolStats")
         req  = self.ReadSempReq('Clear/ClearMsgVpnSpoolStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearMsgVpnSpoolStats",  req, vpn)

         log.note ("   Processing ClearBridgeStats")
         req  = self.ReadSempReq('Clear/ClearBridgeStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearBridgeStats",  req, vpn)

         log.note ("   Processing ClearQueueStats")
         req  = self.ReadSempReq('Clear/ClearQueueStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearQueueStats",  req, vpn)

         log.note ("   Processing ClearDTEStats")
         req  = self.ReadSempReq('Clear/ClearDteStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearDteStats",  req, vpn)

         log.note ("   Processing ClearClientStats")
         req  = self.ReadSempReq('Clear/ClearClientStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearClientStats",  req, vpn)

         log.note ("   Processing ClearClientUserStats")
         req  = self.ReadSempReq('Clear/ClearClientUserStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearClientUserStats",  req, vpn)

         log.note ("   Processing ClearRestConsumerStats")
         req  = self.ReadSempReq('Clear/ClearRestConsumerStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearRestConsumerStats",  req, vpn)

         log.note ("   Processing ClearRestConsumerRDPStats")
         req  = self.ReadSempReq('Clear/ClearRestConsumerRdpStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearRestConsumerRdpStats",  req, vpn)

         log.note ("   Processing ClearRDPStats")
         req  = self.ReadSempReq('Clear/ClearRdpStats.xml') % (self.m_version, vpn)
         resp =  self.ProcessSemp("ClearRdpStats",  req, vpn)


     # -------------------------------------------------------------------------
     # UTIL FUNCTIONS
     # -------------------------------------------------------------------------

     #-----------------------------------------------------------------------------------
     # makeNameMap
     # convert { 'name' : 'myname', 'tag' : 'value' }, ... tp
     #         { 'myname' : { 'name' : 'myname', 'tag' : 'value' }, ... }
     # create a destination map (mapd) internally and return
     #
   def makeNameMap (self, maps):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      mapd = {}
      for k1 in  maps.keys():
          mapd[k1] = {} # destination map
          log.debug ("Processing root key: %s", k1)
          log.trace ("record len %d %s", len(maps[k1]), maps[k1])
	  vmap2 = {}
          for k2 in maps[k1]:
             log.trace ("key/elem = %s/%s", k1,k2)
	     v2 = {}
             if not k2.has_key('name'):
                continue
             kname = k2['name']
	     vmap2[kname] = k2
             log.trace (" - v2[%s] = %s", kname, k2)
          log.trace ("mapd[%s] = %s", k1, vmap2)
          mapd[k1] = vmap2
          log.trace ("mapd[%s] = %s", k1, vmap2)
      return mapd

   def ReqRespXmlFiles (self):
       return (self.m_reqxmlfile, self.m_respxmlfile)

     #-----------------------------------------------------------------------------------
     # non member functions
     #
def merge(source, destination):
       for key, value in source.items():
           if isinstance(value, dict):
               # get node or create one
               node = destination.setdefault(key, {})
               merge(value, node)
           else:
               destination[key] = value
       return destination
