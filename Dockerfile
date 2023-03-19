FROM ubuntu:20.04

MAINTAINER luciano@citrait.com.br

RUN apt-get -y update && apt-get -y dist-upgrade
RUN apt-get -y install python3 python3-pip nmap
COPY src /app
WORKDIR /app
RUN python3 -m pip install flask
EXPOSE 80
ENTRYPOINT ["python3", "app.py"]

