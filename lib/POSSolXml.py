#!/usr/bin/python
# POSSolXml
#   Common XML functions used by Solace Tempale python scripts
#
# Ramesh Natarjan (Solace PSG)

import sys, os
import httplib, base64
import string, re
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import yaml
import logging, inspect

# import POSSol libs & Classes
mypath = os.path.dirname(__file__)
sys.path.append(mypath+"/lib")

class POSSolXml:
   'Solace SEMP XML Parsing implementation'

   #--------------------------------------------------------------
   # Constructor
   #--------------------------------------------------------------
   def __init__(self, me, xmlstr, fname = None):
      self.m_me = me
      self.m_logger = logging.getLogger(me)
      self.m_logger.enter ("%s::%s -e: xml ", __name__, inspect.stack()[0][3])
      #self.m_logger.trace ("%s::%s -e: xml %s", __name__, inspect.stack()[0][3], xmlstr)
      if xmlstr is None and fname is not None:
         self.m_logger.info ('Opening XML file %s', fname)
         with open(fname, 'r') as f:
            xmlstr = f.read()
         f.close() 
      self.m_xmlstr = xmlstr
      self.m_xmlroot = ET.fromstring(xmlstr)
      
      self.m_basepath = ""

   #-------------------------------------------------------------------------------
   # Save
   #-------------------------------------------------------------------------------
   def Save (self, fname, tag=""):
      log = self.m_logger
      log.enter ("%s::%s -e: fname %s", __name__, inspect.stack()[0][3], fname)
      log.info ("Writing %s data to file: %s", tag, fname)
      try:
         dname = os.path.dirname(fname)
         if not os.path.exists(dname):
            log.debug ("creating path %s for file", dname)
            os.makedirs(dname)
         f = open (fname, "w")
         print >>f, self.m_xmlstr
         f.close()
      except IOError as ex:
        log.exception (ex)
	raise ex
      except:
        log.exception ('Unexpected exception', sys.exc_info()[0])
	raise

   #-------------------------------------------------------------------------------
   # BasePath
   #-------------------------------------------------------------------------------
   def BasePath (self, path):
      self.m_logger.enter ("%s::%s -e: path %s", __name__, inspect.stack()[0][3], path)
      self.m_basepath = path

   #-------------------------------------------------------------------------------
   # Find : xpath query on xml string
   #
   def FindAll(self, tag):
      global cfg
      self.m_logger.enter ("%s::%s -e: %s", __name__, inspect.stack()[0][3], tag)
      k = self.m_basepath + tag
      self.m_logger.debug ("Finding %s", k)
      ret = self.m_xmlroot.findall(k)
      if not ret:
         self.m_logger.warning ("Tag \"%s\" not found in xml data", k)
	 return []
      else:
          rlist = []
          for r in ret:
             rlist.append(r.text)
          return rlist

   #-------------------------------------------------------------------------------
   # Find : xpath query on xml string
   #-------------------------------------------------------------------------------
   def Find(self, tag):
      global cfg
      self.m_logger.enter ("%s::%s -e: %s", __name__, inspect.stack()[0][3], tag)
      k = self.m_basepath + tag
      self.m_logger.debug ("Finding %s", k)
      n = self.m_xmlroot.find(k)
      if n is None:
         self.m_logger.warning ("Tag \"%s\" not found in xml data", k)
	 return None
      else:
        return n.text

   #-------------------------------------------------------------------------------
   # FindAt : xpath query on xml string
   #-------------------------------------------------------------------------------
   def FindAt(self, tag, attr):
      global cfg
      self.m_logger.enter ("%s::%s -e: %s @%s", __name__, inspect.stack()[0][3], tag, attr)
      #k = self.m_basepath + tag + "[@" + attr + "]"
      #poscom.vlog ("Finding", k)
      #n = self.m_xmlroot.find(k)
      k = self.m_basepath + tag 
      n = self.m_xmlroot.find(k).attrib[attr]
      if n is None:
         self.m_logger.warning ("Tag \"%s\" not found in response", k)
	 return None
      else:
        return n

   #-------------------------------------------------------------------------------
   # findTags :
   #
   def FindTags(self, tags):
      l = self.m_logger
      l.enter ("%s::%s -e: %s", __name__, inspect.stack()[0][3], tags)
      cfg = {}
      for k,v in tags.items():
         l.debug ("Finding %s", k)
         val = self.Find(k)
         if val is None:
           l.error ("Tag %s not found in response", k)
   	   val="NA"
	 if v is None:
	    v = k.split('/')[-1]
	 if v.find('/') > 0:
	    (v1,v2) = v.split('/')
            l.debug ("Adding %s.%s => %s", v1, v2, val)
	    if not cfg.has_key(v1):
               cfg[v1] = {}
            cfg[v1][v2] = val
	 else:
            l.debug ("Adding %s => %s", v,  val)
            cfg[v] = val
      return cfg

   #-------------------------------------------------------------------------------
   # import response parsing
   #
   def GetMsgVpn(self):
         log = self.m_logger 
         log.enter ("%s::%s", __name__, inspect.stack()[0][3])
         log.info ("Adding VPN")
         self.BasePath('./rpc/show/message-vpn/vpn/')
         #s = rxml.Find('name')
         #print "s = " , s
         tags = {"name" : "name",
                 "max-connections" : "max-connections",
                 "max-subscriptions" : None,
                 "semp-over-message-bus-configuration/semp-over-message-bus-allowed" : "semp-over-message-bus",
                 "event-configuration/large-message-threshold" : "large-msg-threshold",
                 "event-configuration/event-thresholds[name='connections']/set-percentage" : "event-thresholds/connection-set",
                 "event-configuration/event-thresholds[name='connections']/clear-percentage" : "event-thresholds/connection-clear"}
         vpninfo =  self.FindTags(tags)
	 vpninfo['large-msg-threshold'] = "%sK" % (vpninfo['large-msg-threshold'])
         # map True/False to yes/no
         tfmap = { 'true': 'yes', 'false': 'no' }
         for t in ['semp-over-message-bus']:
             vpninfo[t] = tfmap[vpninfo[t]]
	 return vpninfo
   
   def GetMsgSpool(self):
         self.BasePath('./rpc/show/message-spool/message-vpn/vpn/')
         tags = {"name" : "name",
                 "maximum-spool-usage-mb" : "spool-size",
                 "maximum-transactions" : "max-transactions",
                 "maximum-transacted-sessions" : "max-transacted-sessions",
                 "maximum-queues-and-topic-endpoints" : "max-endpoints",
                 "maximum-ingress-flows" : "max-ingress-flows",
                 "maximum-egress-flows" : "max-egress-flows",
                 "event-configuration/event-thresholds[name='spool-usage']/set-percentage" : "event-thresholds/spool-usage-set",
                 "event-configuration/event-thresholds[name='spool-usage']/clear-percentage" : "event-thresholds/spool-usage-clear",
                 "event-configuration/event-thresholds[name='egress-flows']/set-percentage" : "event-thresholds/egress-flows-set",
                 "event-configuration/event-thresholds[name='endpoints']/set-percentage" : "event-thresholds/endpoints-set",
                 "event-configuration/event-thresholds[name='endpoints']/clear-percentage" : "event-thresholds/endpoints-clear",
                 "event-configuration/event-thresholds[name='egress-flows']/set-percentage" : "event-thresholds/egress-flows-set",
                 "event-configuration/event-thresholds[name='egress-flows']/clear-percentage" : "event-thresholds/egress-flows-clear",
                 "event-configuration/event-thresholds[name='ingress-flows']/set-percentage" : "event-thresholds/ingress-flows-set",
                 "event-configuration/event-thresholds[name='ingress-flows']/clear-percentage" : "event-thresholds/ingress-flows-clear",
         }
         spoolinfo =  self.FindTags(tags)
	 spoolinfo['spool-size'] = "%sM" % (spoolinfo['spool-size'])
	 return spoolinfo

   def GetQueueNames(self):
       self.BasePath('./rpc/show/queue/queues/')
       return self.FindAll('queue/name')



   def GetQueues(self):
       self.BasePath('./rpc/show/queue/queues/')
       qnames = self.FindAll('queue/name')
       qinfolist = []
       for qname in qnames:
	  qinfo = {}
          tags = {"queue/[name='%s']/info/owner" % (qname) : "owner", 
                  "queue/[name='%s']/info/quota" % (qname) : "max-spool", 
                  "queue/[name='%s']/info/max-message-size" % (qname) : "max-msg-size", 
                  "queue/[name='%s']/info/max-bind-count" % (qname) : None,
                  "queue/[name='%s']/info/max-redelivery" % (qname) : None,
                  "queue/[name='%s']/info/max-delivered-unacked-msgs-per-flow" % (qname) : 'max-unacked-msgs',
                  "queue/[name='%s']/info/access-type" % (qname) : None,
                  "queue/[name='%s']/info/reject-msg-to-sender-on-discard" % (qname) : None,
                  "queue/[name='%s']/info/others-permission" % (qname) : None,
                  "queue/[name='%s']/info/respect-ttl" % (qname) : None,
                  "queue/[name='%s']/info/event/event-thresholds/[name='bind-count']/set-percentage" % (qname) : "event-thresholds/bind-count-set", 
                  "queue/[name='%s']/info/event/event-thresholds/[name='bind-count']/clear-percentage" % (qname) : "event-thresholds/bind-count-clear", 
                  "queue/[name='%s']/info/event/event-thresholds/[name='spool-usage']/set-percentage" % (qname) : "event-thresholds/spool-usage-set", 
                  "queue/[name='%s']/info/event/event-thresholds/[name='spool-usage']/clear-percentage" % (qname) : "event-thresholds/spool-usage-clear", 
	  }
          qinfo = self.FindTags(tags)
          # map True/False to yes/no
          tfmap = { 'true': 'yes', 'false': 'no' , 'Yes': 'yes', 'No' : 'no'}
          for t in ['reject-msg-to-sender-on-discard', 'respect-ttl']:
             qinfo[t] = tfmap[qinfo[t]].lower()
	  # convert 'Modify-Topic (1110)' -> modify-topic
	  qinfo['others-permission'] = qinfo['others-permission'].split(' ')[0].lower()
	  qinfo['name'] = qname
	  # Q max-spool is in MB
	  qinfo['max-spool'] = "%sM" % (qinfo['max-spool'])
	  qinfolist.append(qinfo)
       return qinfolist

   def GetQueueSubscriptions(self):
       self.BasePath('./rpc/show/queue/queues/')
       qnames = self.FindAll('queue/name')
       qsubslist = []
       for qname in qnames:
          qsubs = {}
          qsubs['topic-subscriptions'] = self.FindAll("queue/[name='%s']/subscriptions/subscription/topic" % (qname))
	  qsubs['name'] = qname
	  qsubslist.append(qsubs)
       return qsubslist

   def GetClientProfiles(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/client-profile/profiles/')
       cpnames = self.FindAll('profile/name')
       cpinfolist = []
       log.info ("Adding Client Profile")
       for cpname in cpnames:
           # skip default profile
          if cpname == 'default' or cpname == '#client-profile':
             log.info ("   Skipping %s", cpname)
             continue
          log.info ("   Adding %s", cpname)
	  cpinfo = {}
          tags = {"profile/[name='%s']/tcp/maximum-tcp-window-size-in-KB" % (cpname) : "tcp-win", 
                  "profile/[name='%s']/guaranteed-1-queue-min-burst" % (cpname) : "g1-queue-min-burst", 
                  "profile/[name='%s']/allow-guaranteed-message-send" % (cpname) : None,
                  "profile/[name='%s']/allow-guaranteed-message-receive" % (cpname) : None,
                  "profile/[name='%s']/allow-guaranteed-endpoint-create" % (cpname) : None,
                  "profile/[name='%s']/allow-transacted-sessions" % (cpname) : None,
                  "profile/[name='%s']/allow-bridge-connections" % (cpname) : None,
                  "profile/[name='%s']/max-connections-per-client-username" % (cpname) : 'max-connections',
                  "profile/[name='%s']/maximum-endpoints-per-client-username" % (cpname) : 'max-endpoints',
                  "profile/[name='%s']/maximum-ingress-flows" % (cpname) : 'max-ingress-flows',
                  "profile/[name='%s']/maximum-egress-flows" % (cpname) : 'max-egress-flows',
                  "profile/[name='%s']/max-subscriptions" % (cpname) : None,
                  "profile/[name='%s']/maximum-transactions" % (cpname) : 'max-transactions',
                  "profile/[name='%s']/maximum-transacted-sessions" % (cpname) : 'max-transacted-sessions',
	         }
          cpinfo = self.FindTags(tags)
	  cpinfo['name'] = cpname
          # map True/False to yes/no
          tfmap = { 'true': 'yes', 'false': 'no' }
          for t in ['allow-guaranteed-message-send', 'allow-guaranteed-message-receive', 'allow-guaranteed-endpoint-create','allow-bridge-connections','allow-transacted-sessions']:
             cpinfo[t] = tfmap[cpinfo[t]]
          # tcp-win is retured in K
          cpinfo['tcp-win'] = "%sK" % cpinfo['tcp-win']
	  cpinfolist.append(cpinfo)
       return cpinfolist

   def GetACLProfiles(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/acl-profile/acl-profiles/')
       aclnames = self.FindAll('acl-profile/profile-name')
       aclinfolist = []
       log.info ("Adding ACL Profiles")
       for aclname in aclnames:
         # skip default profile
         if aclname == 'default' or aclname == '#acl-profile':
             log.info ("   Skipping %s", aclname)
             continue
         log.info ("   Adding %s", aclname)
         tags = {"acl-profile/[profile-name='%s']/client-connect/allow-default-action" % (aclname) : 'client-connect-default-action', 
                  "acl-profile/[profile-name='%s']/publish-topic/allow-default-action" % (aclname) : 'publish-topic-default-action', 
                  "acl-profile/[profile-name='%s']/subscribe-topic/allow-default-action" % (aclname) : 'subscribe-topic-default-action', 
                 }
	 aclinfo = self.FindTags (tags)
         # map True/False to allow/disallow
         tfmap = { 'true': 'allow', 'false': 'disallow' }
         for t in ['client-connect-default-action', 'publish-topic-default-action', 'subscribe-topic-default-action']:
             if len(aclinfo[t]) > 0:
                aclinfo[t] = tfmap[aclinfo[t]]

         # Get ACL exceptions
         aclinfo['client-connect-exceptions'] = self.FindAll("acl-profile/[profile-name='%s']/client-connect/exceptions/exception" % (aclname))
         aclinfo['publish-topic-exceptions'] = self.FindAll("acl-profile/[profile-name='%s']/publish-topic/exceptions/exception" % (aclname))
         aclinfo['subscribe-topic-exceptions'] = self.FindAll("acl-profile/[profile-name='%s']/subscribe-topic/exceptions/exception" % (aclname))

	 aclinfo['name'] = aclname
	 aclinfolist.append(aclinfo)
       return aclinfolist

   def GetACLExceptions_(self):
       self.BasePath('./rpc/show/acl-profile/acl-profiles/')
       aclnames = self.FindAll('acl-profile/profile-name')
       explist = []
       for acl in aclnames:
          cexps = {}
	  exps['name'] = acl
          exps['client-connect-excepitions'] = self.FindAll("acl-profile/[profile-name='%s']/client-connect/exceptions/exception" % (acl))
          exps['publish-topic-excepitions'] = self.FindAll("acl-profile/[profile-name='%s']/publish-topic/exceptions/exception" % (acl))
          exps['subscribe-topic-excepitions'] = self.FindAll("acl-profile/[profile-name='%s']/subscribe-topic/exceptions/exception" % (acl))
	  explist.append(exps)
       return explist

   def GetClientUsernames(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/client-username/client-usernames/')
       usernames = self.FindAll('client-username/client-username')
       log.debug ("usernames: %s", usernames)
       return usernames

   def GetClientUserInfo(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/client-username/client-usernames/')
       usernames = self.FindAll('client-username/client-username')
       userinfolist = []
       log.info ("Adding Client usernames")
       for username in usernames:
         # skip default profile
         if username == 'default' or username == '#client-username' or re.search('^#', username):
             log.info ("   Skipping %s", username)
             continue
         log.info ("   Adding %s", username)
	 userinfo = {}
         tags = {"client-username/[client-username='%s']/profile" % (username) : "client-profile", 
                  "client-username/[client-username='%s']/acl-profile" % (username) : "acl-profile", 
	         }
         userinfo = self.FindTags(tags)
	 userinfo['name'] = username
	  # NOTE - can't get password.
	 userinfo['password'] = 'ONFILE'
	 userinfolist.append(userinfo)
       return userinfolist

   #-------------------------------------------------------------------
   # VPN Bridge 
   #
   def GetBridgeNames(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])

       self.BasePath('./rpc/show/bridge/bridges/')
       bridgenames = self.FindAll('bridge/bridge-name')
       log.debug ("bridge names %s", bridgenames)

       return bridgenames

   def GetBridgeRemoteVpnNames(self, bridge):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/bridge/bridges/')
       rbridgenames = self.FindAll("bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/vpn-name" % (bridge))
       log.debug ("remote bridge names %s", rbridgenames)
       return rbridgenames

   def GetBridgeRemoteVpnAddr(self, bridge, rvpn):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/bridge/bridges/')
       raddr = self.FindAll("bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/[vpn-name='%s']/connect-via-addr" % (bridge,rvpn))
       rport = self.FindAll("bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/[vpn-name='%s']/connect-via-port" % (bridge,rvpn))
       ret = "%s:%s" % (raddr[0], rport[0])
       log.debug ("remote bridge %s addr %s, rport %s, ret = %s", rvpn, raddr, rport, ret)
       return ret


   def GetBridges(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])

       self.BasePath('./rpc/show/bridge/bridges/')
       bridgenames = self.FindAll('bridge/bridge-name')
       bridgeinfolist = []
       log.info ("Adding Bridges")
       for bridgename in bridgenames:
          if re.search ('^#bridge', bridgename):
              log.info ("   Skipping %s", bridgename)
              continue
          log.info ("   Adding %s", bridgename)
	  # CHECK - remote username
          tags = {"bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/vpn-name" % (bridgename) : "remote-vpns/vpnname", 
                  "bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/connect-via-addr" % (bridgename) : "remote-vpns/ip-port", 
                  "bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/connect-via-port" % (bridgename) : "remote-vpns/ip-port-port", 
                  "bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/message-spool-window-size" % (bridgename) : "remote-vpns/window-size", 
                  "bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/queue-name" % (bridgename) : "remote-vpns/queue-name", 
                  "bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/connect-order" % (bridgename) : "remote-vpns/connect-order", 
                  "bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/ssl" % (bridgename) : "remote-vpns/ssl", 
                  "bridge/[bridge-name='%s']/authentication/basic/client-username" % (bridgename) : "remote-user/username", 
                  "bridge/[bridge-name='%s']/max-ttl" % (bridgename) : 'max-ttl',
	         }

          binfo = self.FindTags(tags)

	  bridgeinfo = {}
	  bridgeinfo['remote-vpns'] = []
	  bridgeinfo['remote-user'] = {}
	  remotevpn = {}
	  remotevpn['vpnname']     = binfo['remote-vpns']['vpnname']
	  remotevpn['window-size'] = binfo['remote-vpns']['window-size']
	  remotevpn['queue-name']  = binfo['remote-vpns']['queue-name']
	  remotevpn['connect-order']  = binfo['remote-vpns']['connect-order']
          remotevpn['ip-port']     = "%s:%s" % (binfo['remote-vpns']['ip-port'], binfo['remote-vpns']['ip-port-port'] )
          if binfo['remote-vpns']['ssl'].lower() == 'yes':
	      remotevpn['options']     = 'ssl'
          else:
	      remotevpn['options']     = 'none'
	  bridgeinfo['remote-vpns'].append(remotevpn)

	  bridgeinfo['remote-user']['username']           = binfo['remote-user']['username']
	  bridgeinfo['remote-user']['password']       = 'ONFILE' 
	  bridgeinfo['name']                          = bridgename
	  bridgeinfo['max-ttl']                       = binfo['max-ttl']
	  log.trace ("bridgeinfo = %s", bridgeinfo)
	  bridgeinfolist.append(bridgeinfo)
       return bridgeinfolist

   def GetBridgesSSL(self):
       self.BasePath('./rpc/show/bridge/bridges/')
       bridgenames = self.FindAll('bridge/bridge-name')
       bridgesslinfolist = []
       for bridgename in bridgenames:
	  bridgesslinfo = {}
	  # FIXME - returns the first entry
          tags = {"bridge/[bridge-name='%s']/ssl-config/trusted-common-name-list/trusted-common-name" % (bridgename) : "trusted-common-name", 
	         }
          bridgesslinfo = self.FindTags(tags)
	  bridgesslinfo['name'] = bridgename
	  bridgesslinfolist.append(bridgesslinfo)
       return bridgesslinfolist

   #-------------------------------------------------------------------
   # RDP and object
   #
   def GetRDPNames(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/message-vpn/rest/rest-delivery-points/')
       rdpnames = self.FindAll('rest-delivery-point/name')
       log.debug ("RDP names %s", rdpnames)
       return rdpnames

   # require: show message-vpn restvpn rest rest-consumer *
   def GetRDPConsumerNames(self, bridge):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/message-vpn/rest/rest-delivery-points/')
       # FIXME
       consumers = self.FindAll("bridge/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/vpn-name" % (bridge))
       log.debug ("RDP consumers %s", consumers)
       return consumers


   def GetRDPs(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])

       self.BasePath('./rpc/show/message-vpn/rest/rest-delivery-points/')
       rdpnames = self.FindAll('rest-delivery-point/name')
       rdpinfolist = []
       log.info ("Adding RDPs")
       for rdpname in rdpnames:
          log.info ("   Adding %s", rdpname)
          tags = {"rest-delivery-point/[name='%s']/client-profile" % (rdpname) : 'client-profile'
	         }
          rdpinfo = self.FindTags(tags)
	  rdpinfo['name'] = rdpname
	  log.trace ("rdp info = %s", rdpinfo)
	  rdpinfolist.append(rdpinfo)
       return rdpinfolist

   def GetRDPQueueBindings(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])

       self.BasePath('./rpc/show/message-vpn/rest/rest-delivery-points/')
       rdpnames = self.FindAll('rest-delivery-point/name')
       qinfolist = []
       log.info ("Adding RDP Queue Bindings")
       for rdpname in rdpnames:
          log.info ("   Adding %s", rdpname)
	  # FIXME - returns the first entry
          tags = {"rest-delivery-point/[name='%s']/queue-binding/name" % (rdpname) : 'queue-binding',
                  "rest-delivery-point/[name='%s']/queue-binding/post-request-target" % (rdpname) : 'request-target'
	         }
          qinfo = self.FindTags(tags)
	  qinfo['rdp-name'] = rdpname
	  log.trace ("rdp queue info = %s", qinfo)
	  qinfolist.append(qinfo)
       return qinfolist

   def GetRestConsumers(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])

       self.BasePath('./rpc/show/message-vpn/rest-consumer-info/')
       rdpnames = self.FindAll('detail-info/rest-consumer-header/rdp-name')
       cinfolist = []
       log.info ("Adding RDP Consumers")
       for rdpname in rdpnames:
          log.info ("   Adding %s", rdpname)
	  # FIXME - returns the first entry
          tags = {"detail-info/rest-consumer-header/[rdp-name='%s']/name" % (rdpname) : "consumer",
                  "detail-info/remote/host" : "remote-host",
                  "detail-info/remote/port" : "remote-port",
                  "detail-info/remote/ssl" : "enable-ssl",
                  }
          cinfo = self.FindTags(tags)
	  cinfo['rdp-name'] = rdpname
	  log.trace ("rest consumers = %s", cinfo)
	  cinfolist.append(cinfo)
       return cinfolist


   #-------------------------------------------------------------------
   # JNDI
   #
   def GetJNDI(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/jndi/connection-factory/connection-factories/')
       cfnames = self.FindAll('connection-factory/name')
       cfinfolist = []
       log.info ("Adding Connection Factories")
       for cfname in cfnames:
          log.info ("   Adding %s", cfname)
	  cfinfo = {}
          # messaging
          tags = {"connection-factory/[name='%s']/property-lists/property-list/[name='messaging-properties']/properties/property/[name='default-delivery-mode']/value" % (cfname) : "default-delivery-mode", 
                  "connection-factory/[name='%s']/property-lists/property-list/[name='messaging-properties']/properties/property/[name='default-dmq-eligible']/value" % (cfname) : "default-dmq-eligible", 
                  # transport
                  "connection-factory/[name='%s']/property-lists/property-list/[name='transport-properties']/properties/property/[name='connect-retries']/value" % (cfname) : "connect-retries", 
                  "connection-factory/[name='%s']/property-lists/property-list/[name='transport-properties']/properties/property/[name='connect-timeout']/value" % (cfname) : "connect-timeout", 
                  "connection-factory/[name='%s']/property-lists/property-list/[name='transport-properties']/properties/property/[name='connect-retries-per-host']/value" % (cfname) : "connect-retries-per-host", 
                  "connection-factory/[name='%s']/property-lists/property-list/[name='transport-properties']/properties/property/[name='reconnect-retries']/value" % (cfname) : "reconnect-retries", 
                  "connection-factory/[name='%s']/property-lists/property-list/[name='transport-properties']/properties/property/[name='reconnect-retry-wait']/value" % (cfname) : "reconnect-retry-wait", 
                  "connection-factory/[name='%s']/property-lists/property-list/[name='transport-properties']/properties/property/[name='direct-transport']/value" % (cfname) : "direct-transport", 
                  "connection-factory/[name='%s']/property-lists/property-list/[name='transport-properties']/properties/property/[name='keep-alive-count-max']/value" % (cfname) : "max-keepalive-count", 
                  # Assured delivery
                  "connection-factory/[name='%s']/property-lists/property-list/[name='ad-properties']/properties/property/[name='send-ad-window-size']/value" % (cfname) : "send-ad-window-size", 
                  "connection-factory/[name='%s']/property-lists/property-list/[name='ad-properties']/properties/property/[name='receive-ad-window-size']/value" % (cfname) : "receive-ad-window-size", 
                  # Dynamic durable
                  "connection-factory/[name='%s']/property-lists/property-list/[name='dynamic-endpoint-properties']/properties/property/[name='dynamic-durables']/value" % (cfname) : "dynamic-durables", 
                  "connection-factory/[name='%s']/property-lists/property-list/[name='dynamic-endpoint-properties']/properties/property/[name='respect-ttl']/value" % (cfname) : "respect-ttl", 
	         }
          cfinfo = self.FindTags(tags)
          cfinfo['name'] = cfname
          # map True/False to yes/no
          tfmap = { 'true': 'yes', 'false': 'no' }
          for t in ['default-dmq-eligible', 'direct-transport', 'dynamic-durables', 'respect-ttl']:
             cfinfo[t] = tfmap[cfinfo[t]]
          cfinfolist.append(cfinfo)
       return cfinfolist
   
   def GetHostname(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/hostname')
       statslist = []
       stats = {}
       tags = {"/hostname" : None }
       stats = self.FindTags(tags)
       log.debug ("hostname : %s", stats)
       return stats


       #-----------------------------------------------------------------------------------------
       # show stats parsing
       #

   def MsgSpoolDetails (self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/message-spool/message-spool-info/')
       tags = {"ingress-flow-count" : None,
              "ingress-flows-allowed" : None,
              "active-flow-count" : None,
              "inactive-flow-count" : None,
              "flows-allowed" : None,
              "active-disk-partition-usage" : None,
              "transacted-sessions-used" : None,
              "max-transacted-sessions" : None,
              "config-status" : None,
	      }
       stats = self.FindTags(tags)
       log.debug ("spool details : %s", stats)
       return stats

   def ClientStats(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/stats/client/global/stats/')
       tags = {"total-clients" : None,
	      }
       stats = self.FindTags(tags)
       log.debug ("client details : %s", stats)
       return stats

   
   def VpnClientUserStats (self, vpn):
       log = self.m_logger 
       log.enter ("%s::%s vpn: %s", __name__, inspect.stack()[0][3], vpn)
       self.BasePath('./rpc/show/client-username/client-usernames/client-username')
       names = self.FindAll('/client-username')
       statslist = []
       stats = {}
       for name in names:
          if self.Find("/[client-username='%s']/message-vpn" % (name)) != vpn:
              continue
          log.debug ('looing for stats for %s', name)
          tags = {"/[client-username='%s']/enabled" % (name) : None,
                  "/[client-username='%s']/num-clients" % (name) : None,
                  "/[client-username='%s']/max-connections" % (name) : None,
                  "/[client-username='%s']/max-endpoints" % (name) : None,
		  }
          stats[name] = self.FindTags(tags)
          log.debug ("%s all clientusername details : %s", name, stats)
       return stats
   
   def VpnBridgeStats (self, vpn):
       log = self.m_logger 
       log.enter ("%s::%s vpn: %s", __name__, inspect.stack()[0][3], vpn)
       self.BasePath('./rpc/show/bridge/bridges/bridge')
       names = self.FindAll("/[local-vpn-name='%s']/bridge-name" % (vpn))
       statslist = []
       stats = {}
       for name in names:
          if re.search('^#bridge',name):
               log.info ('skipping stats for VPN %s:%s', vpn, name)
               continue
          log.info ('looing for stats for VPN %s:%s', vpn, name)
          tags = {"/[local-vpn-name='%s']/[bridge-name='%s']/inbound-operational-state" % (vpn, name) : None,
                  "/[local-vpn-name='%s']/[bridge-name='%s']/admin-state" % (vpn, name) : None,
                  "/[local-vpn-name='%s']/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/connect-via-addr" % (vpn, name) : 'remote-addr',
                  "/[local-vpn-name='%s']/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/admin-state" % (vpn, name) : 'remote-admin-state',
                  "/[local-vpn-name='%s']/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/connection-state" % (vpn, name) : 'remote-connection-state',
                  "/[local-vpn-name='%s']/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/queue-name" % (vpn, name) : 'remote-queue-name',
                  "/[local-vpn-name='%s']/[bridge-name='%s']/remote-message-vpn-list/remote-message-vpn/queue-bind-state" % (vpn, name) : 'remote-queue-bind-state',
		  }
          stats[name] = self.FindTags(tags)
          log.debug ("%s all clientusername details : %s", name, stats)
       return stats

   # FIXME : this is just dup of  ParseShowMsgVpn 
   def VpnQueueStats (self, vpn):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/queue/queues/queue')
       names = self.FindAll('/name')
       #names = self.FindAll("/name/info/[message-vpn='%s']" %(vpn))
       statslist = []
       stats = {}
       for name in names:
           # FIXME: hack to fit all vpn support
          if self.Find("/[name='%s']/info/message-vpn" % (name)) != vpn:
              continue
          log.debug ('looing for stats for VPN %s Queue %s', vpn, name)
          tags = {"/[name='%s']/info/[message-vpn='%s']/ingress-config-status" % (name, vpn) : None,
                  "/[name='%s']/info/[message-vpn='%s']/egress-config-status" % (name, vpn) : None,
                  "/[name='%s']/info/[message-vpn='%s']/num-messages-spooled" % (name, vpn) : None,
                  "/[name='%s']/info/[message-vpn='%s']/current-spool-usage-in-mb" % (name, vpn) : None,
                  "/[name='%s']/info/[message-vpn='%s']/quota" % (name, vpn) : None,
                  "/[name='%s']/info/[message-vpn='%s']/total-delivered-unacked-msgs" % (name, vpn) : None,
                  "/[name='%s']/info/[message-vpn='%s']/bind-count" % (name, vpn) : None,
                  "/[name='%s']/info/[message-vpn='%s']/max-bind-count" % (name, vpn) : None,
                  "/[name='%s']/info/[message-vpn='%s']/max-redelivery" % (name, vpn) : None,
                  "/[name='%s']/info/[message-vpn='%s']/max-delivered-unacked-msgs-per-flow" % (name, vpn) : 'max-unacked-msgs',
                  "/[name='%s']/info/[message-vpn='%s']/message-vpn" % (name, vpn) : None,
	          }
          stats[name] = self.FindTags(tags)
       log.trace ("%s queue details : %s", vpn, stats)
       return stats

   def VpnSpoolStats(self, vpn):
       log = self.m_logger 
       log.enter ("%s::%s vpn: %s", __name__, inspect.stack()[0][3], vpn)
       self.BasePath("./rpc/show/message-spool/message-vpn/vpn/[name='%s']" % (vpn))
       statslist = []
       stats = {}
       log.debug ('looing for stats for %s', vpn)
       tags = {"/current-queues-and-topic-endpoints" : None,
                  "/maximum-queues-and-topic-endpoints" : None,
                  "/current-spool-usage-mb"  : None,
                  "/maximum-spool-usage-mb" : None,
                  "/current-transacted-sessions" : None,
                  "/maximum-transacted-sessions" : None,
                  "/current-egress-flows" : None,
                  "/maximum-egress-flows" : None,
                  "/current-ingress-flows" : None,
                  "/maximum-ingress-flows" : None,
	          }
       stats[vpn] = self.FindTags(tags)
       log.debug ("%s spool details : %s", vpn, stats)
       return stats

   def VpnStats (self, vpn):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath("./rpc/show/message-vpn/vpn/[name='%s']" % (vpn))
       statslist = []
       stats = {}
       log.debug ('looing for stats for %s', vpn)
       tags = {"/enabled" : None,
                  "/operational" : None,
                  "/local-status" : None,
                  "/connections" : None,
                  "/max-connections" : None,
                  "/unique-subscriptions" : None,
                  "/max-subscriptions" : None,
	          }
       stats[vpn] = self.FindTags(tags)
       log.debug ("%s vpn details : %s", vpn, stats)
       return stats

   def ParseAllVpnDetails(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/message-vpn/vpn')
       names = self.FindAll('/name')
       statslist = []
       stats = {}
       for name in names:
          log.debug ('looing for stats for %s', name)
          tags = {"/[name='%s']/enabled" % (name) : None,
                  "/[name='%s']/operational" % (name) : None,
                  "/[name='%s']/local-status" % (name) : None,
                  "/[name='%s']/connections" % (name) : None,
                  "/[name='%s']/max-connections" % (name) : None,
                  "/[name='%s']/unique-subscriptions" % (name) : None,
                  "/[name='%s']/max-subscriptions" % (name) : None,
	          }
          stats[name] = self.FindTags(tags)
          log.debug ("%s stats : %s", name, stats)
       return stats


   def ParseAllVpnSpoolDetails(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/message-spool/message-vpn/vpn')
       names = self.FindAll('/name')
       statslist = []
       stats = {}
       for name in names:
          log.debug ('looing for stats for %s', name)
          tags = {"/[name='%s']/current-queues-and-topic-endpoints" % (name) : None,
                  "/[name='%s']/maximum-queues-and-topic-endpoints" % (name) : None,
                  "/[name='%s']/current-spool-usage-mb" % (name) : None,
                  "/[name='%s']/maximum-spool-usage-mb" % (name) : None,
                  "/[name='%s']/current-transacted-sessions" % (name) : None,
                  "/[name='%s']/maximum-transacted-sessions" % (name) : None,
                  "/[name='%s']/current-egress-flows" % (name) : None,
                  "/[name='%s']/maximum-egress-flows" % (name) : None,
                  "/[name='%s']/current-ingress-flows" % (name) : None,
                  "/[name='%s']/maximum-ingress-flows" % (name) : None,
	          }
          stats[name] = self.FindTags(tags)
          log.debug ("%s stats : %s", name, stats)
       return stats

   def ParseAllVpnStats(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/message-spool/message-spool-info/')
       tags = { }
       stats = self.FindTags(tags)
       log.debug ("stats : %s", stats)
       return stats


   def ParseVpnStats(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/message-spool/message-spool-info/')
       tags = { }
       stats = self.FindTags(tags)
       log.debug ("parse stats : %s", stats)
       return stats

   def ParseMsgSpoolStats(self):
       log = self.m_logger 
       log.enter ("%s::%s", __name__, inspect.stack()[0][3])
       self.BasePath('./rpc/show/message-spool/message-spool-stats/')
       # nothing for now to scrap here .. all runtime stats
       tags = { }
       stats = self.FindTags(tags)
       log.debug ("stats : %s", stats)
       return stats

   def ParseVpnClientDetails(self, vpn):
       log = self.m_logger 
       log.enter ("%s::%s vpn: %s", __name__, inspect.stack()[0][3], vpn)
       self.BasePath('./rpc/show/client/primary-virtual-router/client')
       names = self.FindAll('/name')
       statslist = []
       stats = {}
       for name in names:
          log.debug ('looing for stats for %s', name)
          tags = {"/[name='%s']/total-ingress-flows" % (name) : None,
                  "/[name='%s']/total-egress-flows" % (name) : None,
                  "/[name='%s']/message-vpn" % (name) : None,
		  }
          stats[name] = self.FindTags(tags)
          log.debug ("%s all client details : %s", name, stats)
       return stats
