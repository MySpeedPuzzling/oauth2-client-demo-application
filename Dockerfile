FROM ghcr.io/myspeedpuzzling/web-base-php85:main

ENV PHP_OPCACHE_VALIDATE_TIMESTAMPS=0

RUN rm $PHP_INI_DIR/conf.d/docker-php-ext-xdebug.ini

COPY ./public /app/public
