#!/usr/bin/python
# ParseStatsCSV

#%matplotlib inline
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
import time
plt.style.use('ggplot')

p = argparse.ArgumentParser ()
pr = p.add_argument_group("Required Arguments")
pr.add_argument('--csvfile', action='store', required=True, help='CSV file to process')
p.add_argument('--style', action='store', default='2', help='Graph Style use 2/3 (Default:2)')
p.add_argument('-v','--verbose', action='count', help='Verbose mode (-vvv for debug)')
r = p.parse_args()
Verbose = r.verbose
style = int(r.style)

print "Reading CSG file %s" % (r.csvfile)
df = pd.read_csv (r.csvfile, skiprows=1)
if Verbose:
    print df.head()
for c in ['INGRESS_MSG_RATE', 'EGRESS_MSG_RATE']:
    print "%-20s Min: %10d Max: %10d Mean: %10d" % (c, df[c].min(), df[c].max(), df[c].mean())

if style == 3:
   df1 = df[['INGRESS_MSG_RATE', 'EGRESS_MSG_RATE', 'MSGS_SPOOLED']]
   subp=True
else:
   df1 = df[['INGRESS_MSG_RATE', 'EGRESS_MSG_RATE']]
   subp=False
ts = df['TIMESTAMP'].str.split()
#df1['TIMESTAMP'] = ts.str[1] # only get HH:MM:SS into timestamp
df1.loc[:,('TIMESTAMP')] = ts.str[1] # only get HH:MM:SS into timestamp
if (Verbose):
   print df1.head()
#plt.figure()
df1.plot(x='TIMESTAMP', subplots=subp, label=r.csvfile)
plt.title(r.csvfile)
pngfile = "%s/plot_%s.png" % ('plots', time.strftime("%Y%m%d_%H%M%S"))
print 'Saving plot to %s' % pngfile
plt.savefig(pngfile)
plt.show()
