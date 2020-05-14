#!/bin/bash
echo "Checking for required python modules:"
[ -d tmp ] || mkdir tmp
{
echo 'import sys, os' 
echo 'sys.path.append(os.getcwd()+"/lib")' 
grep '^import' bin/*py lib/*py |cut -f2 -d:|sort -u 
} > tmp/python_modules.py
python tmp/python_modules.py || { echo "ERROR: Some required modules may be missing"; exit 2; }
echo "Everything looks good"
