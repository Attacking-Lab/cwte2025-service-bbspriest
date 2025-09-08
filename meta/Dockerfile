FROM python:3.13.7-alpine3.22

RUN addgroup -S service && adduser -S -s /bin/sh service
RUN apk update && apk add git build-base cmake gmp gmp-dev vim

COPY . /service
RUN chown -R service:service /service

# USER service
WORKDIR /service/

ENTRYPOINT ["/service/buildmodule.sh"]
