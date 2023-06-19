# Support setting various labels on the final image
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

FROM thundercore/librng as rng

# Build Geth in a stock Go builder container
FROM golang:1.16-alpine as builder

RUN apk add --no-cache gcc musl-dev linux-headers git

ADD . /thunder

COPY --from=rng /usr/local/lib/thunder/librng.so /usr/local/lib/thunder/librng.so
COPY --from=rng /usr/local/include/thunder/librng.h /usr/local/include/thunder/librng.h

RUN cd /thunder && go run build/ci.go install ./cmd/thundertool ./cmd/pala ./cmd/generategenesis

FROM alpine:3.11.2

# Alpine Linux packages
RUN apk --no-cache add ca-certificates && update-ca-certificates && \
    apk add socat vim jq wget tini

#install glibc
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub
RUN wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.28-r0/glibc-2.28-r0.apk
RUN apk add glibc-2.28-r0.apk

# Use `tini` as PID 1
# Adding `tini` manually instead of using Docker's `init` parameter to
# support Kubernetes
ENV TINI_VERBOSITY 3
ENV TINI_KILL_PROCESS_GROUP 1

# Add starting scripts
ADD docker/bashrc /
ADD docker/bash.ash /bin/bash

ENV CONFIG_DIR          /config
ENV FASTPATH_CONFIG_DIR ${CONFIG_DIR}/fastpath/pala/

# Add default configs
# NOTE: `localchain` further bind mounts these same config files through `docker-compose.yaml` for
#       a faster edit-restart cycle.
ADD config/hardfork.yaml ${FASTPATH_CONFIG_DIR}
ADD config/thunder.yaml ${FASTPATH_CONFIG_DIR}

COPY --from=builder /thunder/build/bin/generategenesis /usr/local/bin/
COPY --from=builder /thunder/build/bin/thundertool /usr/local/bin/
COPY --from=builder /thunder/build/bin/pala /usr/local/bin/
COPY --from=rng /usr/local/lib/thunder/librng.so /usr/local/lib/thunder/librng.so

ADD docker/entrypoint.sh /

ENTRYPOINT ["/sbin/tini", "--"]

