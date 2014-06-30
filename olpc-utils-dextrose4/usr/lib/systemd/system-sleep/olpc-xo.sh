#!/bin/bash
# systemd suspend hook for OLPC XO
# Turn display off while going into suspend, and turn it on when coming out
case $1 in
	pre)  echo 1 > /sys/devices/platform/dcon/sleep ;;
	post) echo 0 > /sys/devices/platform/dcon/sleep ;;
esac
