FROM python:3.10

RUN apt-get update && apt-get install -y net-tools iproute2
RUN pip install libpcap

COPY . .

ENTRYPOINT ["python", "script.py"]