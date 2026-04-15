FROM ubuntu:22.04

RUN apt-get update -q && \
    apt-get install -y -q --no-install-recommends \
      hping3 nmap netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
