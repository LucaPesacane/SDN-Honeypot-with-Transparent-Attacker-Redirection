#!/bin/bash
# Servizi esposti dalla vittima e replicati sull'honeypot.
for p in 5001 5002 5003 5004 5005; do iperf -s -p $p & done
iperf -s -u -p 5010 &
wait
