FROM alpine:3.13

RUN apk add --no-cache lftp tcpdump

WORKDIR /root

COPY ftp_loop.sh /root/ftp_loop.sh
RUN chmod +x /root/ftp_loop.sh

CMD ["/root/ftp_loop.sh"]