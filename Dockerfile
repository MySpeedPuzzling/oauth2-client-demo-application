FROM ghcr.io/myspeedpuzzling/web-base-php85:main

ENV PHP_OPCACHE_VALIDATE_TIMESTAMPS=0

# Make sure xdebug is never loaded in the production image. The base image used to
# ship this ini enabled; it now ships it as *.disabled (xdebug already not loaded),
# so an unconditional `rm` fails the build. `-f` keeps this correct either way.
RUN rm -f $PHP_INI_DIR/conf.d/docker-php-ext-xdebug.ini

COPY ./public /app/public
