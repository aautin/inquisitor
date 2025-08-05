FROM ubuntu:22.04

RUN apt-get update && apt-get install -y net-tools iproute2 gcc libpcap-dev

COPY . .

ENTRYPOINT ["bash", "entrypoint.sh"]