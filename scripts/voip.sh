#!/bin/bash
# Flusso UDP costante attraverso il trunk.
while true; do iperf -c 10.0.0.100 -u -p 5010 -b 64k -t 60; done
