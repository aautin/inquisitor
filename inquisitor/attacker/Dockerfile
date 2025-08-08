FROM ubuntu:22.04

RUN apt-get update && apt-get install -y pip net-tools iproute2 gcc libpcap-dev

RUN pip install scapy

COPY . .

ENTRYPOINT python3 inquisitor.py $SRC_IP $SRC_MAC $TARGET_IP $TARGET_MAC