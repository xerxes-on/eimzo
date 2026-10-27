FROM php:8.3-cli-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends git unzip ca-certificates curl openjdk-17-jdk-headless libonig-dev libxml2-dev libsodium-dev \
    && docker-php-ext-install mbstring dom xml xmlwriter sodium \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
COPY runtime/install.sh runtime/EimzoBridge.java /tmp/eimzo-bridge/
RUN --mount=type=bind,source=runtime,target=/runtime-source \
    if [ -f /runtime-source/E-IMZO-v6.4.7.tar.gz ]; then \
        bash /tmp/eimzo-bridge/install.sh /opt/eimzo-provider /runtime-source/E-IMZO-v6.4.7.tar.gz; \
    else \
        bash /tmp/eimzo-bridge/install.sh /opt/eimzo-provider; \
    fi
WORKDIR /workspace
COPY composer.json composer.lock phpunit.xml phpstan.neon ./
COPY src ./src
COPY tests ./tests
ENV COMPOSER_ROOT_VERSION=dev-main EIMZO_NATIVE_RUNTIME=/opt/eimzo-provider
RUN composer install --no-interaction --prefer-dist --no-progress \
    && useradd --create-home --uid 10001 signer \
    && chown -R signer:signer /workspace
USER signer
CMD ["composer", "check"]
