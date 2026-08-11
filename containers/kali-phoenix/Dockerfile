FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        ffuf \
        jq \
        nikto \
        nmap \
        openssl \
        python3 \
        sslscan \
        wafw00f \
        whatweb \
        whois \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="Phoenix Guardian Kali Toolkit" \
      org.opencontainers.image.description="Curated defensive and authorized-assessment utilities for registered Phoenix actions" \
      org.opencontainers.image.source="https://www.kali.org/docs/containers/official-kalilinux-docker-images/"

USER 65534:65534
ENV HOME=/tmp
WORKDIR /tmp

CMD ["bash", "-lc", "echo 'Phoenix Guardian Kali toolkit ready for registered actions.'"]
