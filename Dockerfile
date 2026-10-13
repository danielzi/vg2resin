FROM alpine:3.20 AS builder

RUN apk add --no-cache build-base git
RUN git clone --depth 1 https://github.com/rofl0r/microsocks.git /tmp/microsocks \
    && cd /tmp/microsocks \
    && make \
    && strip microsocks

FROM alpine:3.20

RUN apk add --no-cache \
    openvpn \
    python3 \
    iproute2 \
    procps \
    bash \
    curl \
    ca-certificates

COPY --from=builder /tmp/microsocks/microsocks /usr/bin/microsocks

WORKDIR /app
COPY templates /app/templates
COPY up_hook.sh /app/up_hook.sh
COPY app.py /app/app.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/up_hook.sh /app/entrypoint.sh /usr/bin/microsocks

EXPOSE 28080 10801-10820
ENTRYPOINT ["/app/entrypoint.sh"]
