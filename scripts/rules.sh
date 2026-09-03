#!/bin/bash
for s in s1 s2; do
  echo "=== $s ==="
  ovs-ofctl -O OpenFlow13 dump-flows $s --sort=priority
done
