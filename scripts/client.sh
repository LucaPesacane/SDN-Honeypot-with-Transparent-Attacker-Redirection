#!/bin/bash
# Traffico legittimo: sessioni brevi verso porte casuali, attesa esponenziale.
while true; do
  iperf -c 10.0.0.100 -p 500$((RANDOM%5+1)) -n 200K
  sleep $(awk -v s=$RANDOM 'BEGIN{srand(s); print -log(1-rand())/2}')
done
