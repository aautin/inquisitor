FROM python:3.10

RUN apt-get update && apt-get install -y python3-pip

COPY . .

ENTRYPOINT ["python", "-u", "script.py"]