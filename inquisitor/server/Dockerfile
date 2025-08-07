FROM busybox

RUN mkdir -p /home/ftp

COPY files /home/ftp/

EXPOSE 21

ENTRYPOINT ["tcpsvd", "-vE", "0.0.0.0", "21", "ftpd", "-w", "-A", "/home/ftp"]