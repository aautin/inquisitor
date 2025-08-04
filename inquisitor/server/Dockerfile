FROM python:3.10

RUN apt-get update && apt-get install -y python3-pip
RUN pip install pyftpdlib

COPY . .

ENTRYPOINT ["python", "script.py"]