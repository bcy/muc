#!/bin/bash

USAGE="Usage: `basename $0` [NAME_PREFIX]"

if [ $# != 1 ]; then
  echo $USAGE
  exit 1
fi

CONFIG_FILE=./muc.xml

sed "s|<name_prefix>.*</name_prefix>|<name_prefix>${1:-/ndn/ucla.edu}</name_prefix>|" $CONFIG_FILE > $CONFIG_FILE.tmp
mv $CONFIG_FILE.tmp $CONFIG_FILE

