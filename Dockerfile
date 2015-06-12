FROM debian:sid
MAINTAINER Vladimir Terekhov <zarkzork@gmail.com>

RUN apt-get update && \
    apt-get install -y locales && \
    dpkg-reconfigure locales && \
    locale-gen C.UTF-8 && \
    /usr/sbin/update-locale LANG=C.UTF-8

ENV LC_ALL C.UTF-8

# Installing ruby

RUN apt-get install -y build-essential nasm ruby ruby-dev python-pygments && gem install rocco curl

CMD /bin/bash