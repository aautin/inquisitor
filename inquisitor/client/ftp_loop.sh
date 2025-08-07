#!/bin/sh

sleep 3
arp -d 172.20.0.4

while true; do
    lftp -u anonymous, -e "ls; bye" ftp://$SERVER_IP
    sleep 5
done