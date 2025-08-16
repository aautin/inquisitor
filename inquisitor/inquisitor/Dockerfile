FROM debian:latest

RUN apt update && apt install -y \
    build-essential \
    cmake \
    libpcap-dev \
    g++ \
    libc6-dev \
    linux-libc-dev

WORKDIR /inquisitor

COPY . .
RUN rm -f Dockerfile

CMD tail -f