#!/usr/bin/python
# diffvpns.py -- run diff on two VPN YAML config files
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

me = 'diffvpns'
#--------------------------------------------------------------
# main
#--------------------------------------------------------------
def main(argv):

   p = argparse.ArgumentParser( prog=me,
   	description='diffvpns : diff two VPN Yaml config files',
        formatter_class=argparse.RawDescriptionHelpFormatter)
   p.add_argument('--files',  action="store", nargs="+", required=True, 
           help='Config files (reads first 2)')
   p.add_argument('--sitecfg', '-s', default='cfg/sample/site-config.yaml', 
        help='site defaults file (default: in/sample/site-config.yaml)') 
   p.add_argument('--pwdfile', '-p', default='cfg/sample/passwords.yaml', 
           help='password file (default: in/sample/passwords.yaml)') 
   p.add_argument('--tags',  action="store", nargs="+", 
           help='Tags to use in display for files (default: file name)')
   p.add_argument('-v','--verbose', action="count", 
           help='Verbose mode: -v verbose, -vv debug, -vvv trace')
   r = p.parse_args()

   if not (r.files):
      raise Exception("Missing Vpn list Argument. exiting")

   if not (r.tags):
      tags = r.files
   else:
      tags = r.tags

   # init logging
   log = poslog.POSSolLogger(me, r.verbose).GetLogger()
   if log is None:
      raise Exception("Logger not defined")
   log.info("=== %s Starting", me)
   log.debug ("args %s", r)
   sys.tracebacklimit = 0
   if r.verbose:
      sys.tracebacklimit = int(r.verbose)

   # read configs
   log.note("Reading config file : %s (%s)", r.files[0], tags[0])
   cfg0 = posyam.POSSolYaml(me, r.files[0], r.sitecfg, r.pwdfile)
   vpn0 = cfg0.GetVpnName()
   log.info ("VPN %s config read from %s", vpn0, r.files[0])

   log.note("Reading config file : %s (%s)", r.files[1], tags[1])
   cfg1 = posyam.POSSolYaml(me, r.files[1], r.sitecfg, r.pwdfile)
   vpn1 = cfg1.GetVpnName()
   log.info ("VPN %s config read from %s", vpn1, r.files[1])

   if cfg0.Compare(cfg1.GetMap(), tags[0], tags[1]) == True:
     log.note("*** Config files are same ***")
   else:
      log.note("### Config files are different ###")

if __name__ == "__main__":
   main(sys.argv[1:])
