#!/bin/bash

echo "@reboot /usr/local/bin/ccndstart" > crontab_file
echo "@reboot /usr/local/bin/jabberd -h localhost" >> crontab_file
echo "@reboot cd `pwd` && src/mu-conference -c muc.xml" >> crontab_file

