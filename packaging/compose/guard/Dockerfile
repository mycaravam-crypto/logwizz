# Experimental only. Runs nftables in its OWN Linux container network namespace.
FROM python:3.13-alpine
RUN apk add --no-cache nftables
COPY packaging/compose/guard/guard.py /usr/local/bin/logwizz-guard
ENTRYPOINT ["python3", "/usr/local/bin/logwizz-guard"]
