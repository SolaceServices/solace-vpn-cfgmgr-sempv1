# POSSolMgr
POSSolMgr is python tool for managing Solace VPNs 

This has 3 python scripts and support scripts
```
bin/possolmgr.py : VPN Provisioning script. This script is used for creating
    vpn off YAML config file, making changes, etc.
bin/possoladm.py : VPN admin script. Used for enabling/disabling objects,
    purging queues, clearing stats, etc
bin/possolmon.py : Script to gather VPN stats and store locally and display
   in human friendy format
```

### Sample Config
```
import/<timestamp>/<dc>/<dc>-<vpn>.yaml
cfg/sample/site-defaults.yaml 
cfg/sample/passwords.yaml
```

### Installation
```
Unzip the package POSSolMgr-<verson>.zip
If file permissions are not set,
   cd possolmgr
   chmod +x bin/*.py bin/*.sh
If running for the first time, check if all required modules are present
  bin/check_env.sh
If any modules are reported missing, follow standard Python module install
process for your OS
For e.g, on MacOS
  brew install python pip
  sudo pip install pyyaml
PyYaml is also packaged under pkg/ dir
   cd pkg
   ./setup.sh
Verify things are working ok with
  bin/possolmgr.py -h
  or 
  python bin/possolmgr.py -h
```

### Running
```
Pl refer usage
   bin/possolmgr.py -h
   bin/possoladm.py -h
   bin/possolmon.py -h
```

## Built with
* [SEMPv1](https://docs.solace.com/SEMP/Using-Legacy-SEMP.htm)

## Authors
* Ramesh Natarajan

## Licence
(c) Solace Systems. **The code is not free for use.**

## Resources
* [Solace Dev Portal](http://dev.solace.com)
* [Solace Documentation](http://docs.solace.com)
* [Solace Community](http://solace.community)