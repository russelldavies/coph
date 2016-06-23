FROM alpine:3.4

RUN apk add --no-cache alpine-sdk go
WORKDIR /coph
ENTRYPOINT ["make"]
