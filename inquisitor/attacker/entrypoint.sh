#!/bin/bash

gcc -o inquisitor inquisitor.c -lpcap
stdbuf -o0 -e0 ./inquisitor $SRC_IP $SRC_MAC $TARGET_IP $TARGET_MAC
