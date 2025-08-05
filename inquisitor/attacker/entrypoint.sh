#!/bin/bash

gcc -o inquisitor inquisitor.c -lpcap
stdbuf -o0 -e0 ./inquisitor $ATTACKER_IP $ATTACKER_MAC $VICTIM_IP $VICTIM_MAC
