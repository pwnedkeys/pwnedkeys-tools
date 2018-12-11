FROM ruby:2.5-alpine

ARG GEM_VERSION

COPY pkg/pwnedkeys-tools-$GEM_VERSION.gem /tmp/pwnedkeys-tools.gem

RUN apk update \
	&& apk add build-base \
	&& gem install /tmp/pwnedkeys-tools.gem \
	&& apk del build-base \
	&& rm -rf /tmp/pwnedkeys-tools.gem /var/cache/apk/*
