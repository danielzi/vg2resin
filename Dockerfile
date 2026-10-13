FROM alpine:3.20

RUN apk add --no-cache \
    openvpn \
    microsocks \
    python3 \
    iproute2 \
    procps \
    bash \
    curl \
    ca-certificates

WORKDIR /app
COPY up_hook.sh /app/up_hook.sh
COPY app.py /app/app.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/up_hook.sh /app/entrypoint.sh

EXPOSE 8080 10801-10820
ENTRYPOINT ["/app/entrypoint.sh"]
