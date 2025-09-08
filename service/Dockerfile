FROM python:3.13.7-alpine3.22
RUN apk add gmp build-base
RUN pip3 install pymongo --break-system-packages

RUN addgroup -S service && adduser -S -s /bin/sh service
RUN mkdir /data/
RUN chown -R service:service /data

ADD --chmod=755 entrypoint.sh /

COPY src/ /service

USER service
WORKDIR /service/

ENTRYPOINT ["/entrypoint.sh"]
