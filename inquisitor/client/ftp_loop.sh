#!/bin/sh

while true; do
    lftp -u anonymous, -e "ls; bye" ftp://$SERVER_IP
    sleep 3
done