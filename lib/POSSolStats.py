#!/usr/bin/python
# This file implements solace system capture and display
#
# Ramesh Natarajan, Solace PSG 

import sys, os
import httplib, base64
import string, re
import xml.etree.ElementTree as ET
import logging, inspect
import yaml
import time
# Import libraries
sys.path.append(os.getcwd()+"/lib")
import POSSolLogger as poslog
import POSSolSemp   as possemp
import POSSolHttp   as poshttp
import POSSolXml    as posxml

class POSSolStats:
   'Solace Stats implementation'

	#--------------------------------------------------------------
	# Constructor
	#--------------------------------------------------------------
   def __init__(self, prog, path, compact):
      self.m_prog = prog
      self.m_logger = logging.getLogger(prog)
      self.m_logger.enter ("%s::%s : path %s", __name__, inspect.stack()[0][3], path)

      self.m_syspath = path
      self.m_vpnpath = path
      self.m_hostname = 'solace'
      self.m_vpn = 'novpn'
      self.m_compact = compact

   def SystemStats(self):
      log = self.m_logger
      log.enter ("%s::%s ", __name__, inspect.stack()[0][3])

      fname = self.m_syspath + "/ShowHostname.xml"
      xml = posxml.POSSolXml(self.m_prog, None, fname)
      log.trace('xml: %s', xml)
      hnm = xml.GetHostname()
      log.trace('hostname: %s', hnm)
      self.m_hostname = hnm['hostname']

      #-----------------------------------------------------
      # message spool details
      #
      fname = self.m_syspath + "/ShowMsgSpoolDetails.xml"
      xml = posxml.POSSolXml(self.m_prog, None, fname)
      log.trace('xml: %s', xml)
      mss = xml.MsgSpoolDetails()
      log.trace('mss: %s', mss)

      fname = self.m_syspath + "/ShowClientStats.xml"
      xml = posxml.POSSolXml(self.m_prog, None, fname)
      log.trace('xml: %s', xml)
      msd = xml.ClientStats()
      log.trace('msd: %s', msd)

      self.m_msd = msd 
      self.m_mss = mss
      # system stats prined below in VpnStats so they can be
      # printed to file


      #-----------------------------------------------------
      # message spool stats
      #
   def VpnStats(self, vpn):
      log = self.m_logger
      log.enter ("%s::%s  vpn: %s", __name__, inspect.stack()[0][3], vpn)

      self.m_vpn = vpn

      ts = time.strftime("%Y%m%d-%H%M%S")
      self.m_ofname = 'log/%s_%s_%s.txt' % (self.m_hostname, vpn, ts)
      log.info ('Opening file %s', self.m_ofname)
      self.m_ofh = open (self.m_ofname, 'w') 
      print >> self.m_ofh, 'Status as of ', time.strftime("%m/%d/%Y %H:%M:%S")
      #-----------------------------------------------------
      # print system stats for reference
      #
      mss = self.m_mss
      msd = self.m_msd
      if (self.m_compact):
         print ('-----------------------------------------------------------------------------')
      self.prh ('System')
      if mss['config-status'].find('Enabled') >= 0: 
         self.prs ("Status", '', 'Up (%s)' % mss['config-status'])
      else:
         self.prs ("Status", ' ', 'UNKNOWN (%s)' % mss['config-status'], '### Unknown ###')
      self.prt ("Active Disk Partition",
            float(mss['active-disk-partition-usage']), 100)
      self.prt ("Connections",
           int(msd['total-clients']), 9000, 1)
      self.prt ("Egress flows",
           int(mss['active-flow-count']) + int(mss['inactive-flow-count']),
           int(mss['flows-allowed']), 1)
      self.prt ("Ingress flows",
           int(mss['ingress-flow-count']),
           int(mss['ingress-flows-allowed']), 1)
      self.prt ("Transacted Sessions",
           int(mss['transacted-sessions-used']),
           int(mss['max-transacted-sessions']))
      #-----------------------------------------------------
      # vpn details
      #
      fname = self.m_vpnpath + "/ShowVpnDetails.xml"
      xml = posxml.POSSolXml(self.m_prog, None, fname)
      log.trace('xml: %s', xml)
      vpnds = xml.VpnStats(vpn)
      log.trace('vpnds: %s', vpnds)

      #-----------------------------------------------------
      # Spool details
      fname = self.m_vpnpath + "/ShowSpoolDetails.xml"
      xml = posxml.POSSolXml(self.m_prog, None, fname)
      log.trace('xml: %s', xml)
      vpnsp = xml.VpnSpoolStats(vpn)

      log.trace('vpnsp: %s', vpnsp)
      self.prh ('VPN', vpn)
      vpnd = vpnds[vpn] # vpn detail
      vpns = vpnsp[vpn] # spool detail
      if vpnd['enabled'].find('true') >= 0 and \
	    vpnd['local-status'].find('Up') >= 0 and \
	    vpnd['operational'].find('true') >= 0: 
            self.prs ("Status", '', 'Up')
      else:
            self.prs ("Status", '', 'DOWN (Not enabled or local status/oper down')
      self.prt ("Connections",
           int(vpnd['connections']),
           int(vpnd['max-connections']), 1)
      self.prt ("Subscriptions",
           int(vpnd['unique-subscriptions']),
           int(vpnd['max-subscriptions']), 1)
      self.prt ("Endpoints",
           int(vpns['current-queues-and-topic-endpoints']),
           int(vpns['maximum-queues-and-topic-endpoints']))
      self.prt ("Spool",
           int(float(vpns['current-spool-usage-mb'])),
           int(float(vpns['maximum-spool-usage-mb'])))
      self.prt ("Transacted Sessions",
           int(vpns['current-transacted-sessions']),
           int(vpns['maximum-transacted-sessions']))
      self.prt ("Ingress flows",
           int(vpns['current-ingress-flows']),
           int(vpns['maximum-ingress-flows']), 1)
      self.prt ("Egress flows",
           int(vpns['current-egress-flows']),
           int(vpns['maximum-egress-flows']), 1)

   def VpnQueueStats(self, vpn):
      log = self.m_logger
      log.enter ("%s::%s  vpn: %s", __name__, inspect.stack()[0][3], vpn)

      fname = self.m_vpnpath + "/ShowQueueDetails.xml"
      xml = posxml.POSSolXml(self.m_prog, None, fname)
      log.trace('xml: %s', xml)
      qs = xml.VpnQueueStats(vpn)
      log.trace('Queue details: %s', qs)

      self.prh ('Queue')
      for q in sorted(qs.keys()):
         if qs[q]['ingress-config-status'].find('Up') < 0:
            self.prs (q, '', 'DOWN (ingress down)')
         elif qs[q]['egress-config-status'].find('Up') < 0:
            self.prs (q, '', 'DOWN (egress down)')
	 else:
              self.prs (q, '', 'Up')
         #self.prt (' Bind',
         #  int(qs[q]['bind-count']),
         #  int(qs[q]['max-bind-count']))
         #self.prt (' Spool',
         #  int(float(qs[q]['current-spool-usage-in-mb'])),
         #  int(qs[q]['quota']))

      self.prh ('Queue bind count')
      for q in sorted(qs.keys()):
         if re.search('^BRIDGE', q):
            self.prt (q, int(qs[q]['bind-count']),
              int(qs[q]['max-bind-count']), 1, True)
         else:
            self.prt (q, int(qs[q]['bind-count']),
              int(qs[q]['max-bind-count']), 1)

      self.prh ('Queue spool usage')
      for q in sorted(qs.keys()):
         self.prt (q, int(float(qs[q]['current-spool-usage-in-mb'])),
           int(qs[q]['quota']))

   def VpnClientUserStats(self, vpn):
      log = self.m_logger
      log.enter ("%s::%s  vpn: %s", __name__, inspect.stack()[0][3], vpn)

      fname = self.m_vpnpath + "/ShowClientDetails.xml"
      xml = posxml.POSSolXml(self.m_prog, None, fname)
      cs = xml.VpnClientUserStats(vpn)
      #log.trace('ClientUsername details: %s', cs)
      self.prh ('Client Username')
      for cu in sorted(cs.keys()):
         if cs[cu]['enabled'].find('true') >= 0:
            self.prs (cu, '', 'Up')
         else:
            if cu == 'default':
              self.prs (cu, 'OK to ignore', 'DOWN')
            else:
              self.prs (cu, '', 'DOWN')

   def VpnBridgeStats(self, vpn):
      log = self.m_logger
      log.enter ("%s::%s  vpn: %s", __name__, inspect.stack()[0][3], vpn)

      fname = self.m_vpnpath + "/ShowBridgeDetails.xml"
      xml = posxml.POSSolXml(self.m_prog, None, fname)
      bs = xml.VpnBridgeStats (vpn)
      log.trace('Bridge details: %s', bs)
      self.prh ('Bridge')
      for b in sorted(bs.keys()):
         if bs[b]['admin-state'].find('Enabled') >= 0:
            self.prs (b, '', 'Up')
         else:
            self.prs (b, '', 'DOWN')
         if bs[b]['remote-admin-state'].find('Enabled') >= 0:
            self.prs (' Remote :'+bs[b]['remote-addr'], '', 'Up')
         else:
            self.prs (' Remote :'+bs[b]['remote-addr'], '', 'DOWN')
         if bs[b]['remote-queue-bind-state'].find('Up') >= 0:
            self.prs (' Queue:'+bs[b]['remote-queue-name'], '', 'Up')
         else:
            self.prs (' Queue:'+bs[b]['remote-queue-name'], '', 'DOWN')

   def prh (self,hdr, vpn=None):
      self.m_hdr = hdr
      if (self.m_compact):
          if vpn:
             print ('VPN: {:s}' . format(vpn))
             print >> self.m_ofh, '{:s} stats for vpn {:s}' . format(vpn,hdr)
          #else:
          #   print '{:s} stats' . format(hdr)
          #   print >> self.m_ofh, '{:s} stats' . format(vpn)
          return
      print ('\n'+ hdr + ' (' + self.m_vpn + ' ) ['+self.m_hostname+']')
      print ('-----------------------------------------------------------------------------')
      print ('{:40s} {:>10s} {:>10s} {:>6s}% {:10s}' .\
             format('Resource', 'Usage', 'Limit', '', 'Status'))
      print ('-----------------------------------------------------------------------------')

      print >> self.m_ofh, '\n'+ hdr +' ['+self.m_hostname+']'
      print >> self.m_ofh, '-----------------------------------------------------------------------------'
      print >> self.m_ofh, '{:40s} {:>10s} {:>10s} {:>6s}% {:10s}' .\
             format('Resource', 'Usage', 'Limit', '', 'Status')
      print >> self.m_ofh, '-----------------------------------------------------------------------------'

   def prs (self,t, v, s):
      if self.m_compact:
        if re.search('^Up', s) or re.search('^OK', v):
           return
        print (self.m_hdr, t, 'is', s, '(', v, ')')
        print >> self.m_ofh, self.m_hdr, t, 'is', s, '(', v, ')'
        return
      print ('{:40s} {:>29s} {:10s}' . format(t, v, s))
      print >> self.m_ofh, '{:40s} {:>29s} {:10s}' . format(t, v, s)

   def prt (self,t, v, vmax, vmin = 0, maxok = False):
      if vmax == 0:
         s = 'NA'
         vp = 0
      else:
         vp = 100.0*v/vmax
         if maxok:
             s = 'OK'
         elif vp >= 80:
            s = 'CRITICAL'
         elif vp >= 60:
            s = 'WARNING'
         else:
            s = 'OK'
      if v < vmin:
            s = 'CRITICAL: Too low'
      if self.m_compact:
        if s != 'OK':
            print ('{:s} {:s} is {:s} ({:d}/{:d} - {:6.2f}%)' . format(self.m_hdr, t, s, v, vmax, vp))
            print >> self.m_ofh, '{:s} {:s} is {:s} ({:d}/{:d} - {:6.2f}%)' . format(self.m_hdr, t, s, v, vmax, vp)
        return
      print ('{:40s} {:10d} {:10d} {:6.2f}% {:10s}' . format(t, int(v), vmax, vp, s))
      print >> self.m_ofh, '{:40s} {:10d} {:10d} {:6.2f}% {:10s}' . format(t, int(v), vmax, vp, s)

   def cleanup (self):
      log = self.m_logger
      log.enter (" %s::%s ", __name__, inspect.stack()[0][3])
      print ('-----------------------------------------------------------------------------')
      #log.note ("Status file %s", self.m_ofname)
      self.m_ofh.close()
