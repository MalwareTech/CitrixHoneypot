FROM python:3
LABEL maintainer="@Tu5k4rr"
RUN mkdir /CitrixHoneypot
RUN mkdir /CitrixHoneypot/logs
RUN mkdir /CitrixHoneypot/ssl
COPY ./. /CitrixHoneypot
WORKDIR /CitrixHoneypot
CMD [ "python", "./CitrixHoneypot.py"]
