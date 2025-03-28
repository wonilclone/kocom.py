#!/bin/sh
ps ax | grep kocom_main.py | grep -v grep | awk '{print "kill " $1}'|sh
