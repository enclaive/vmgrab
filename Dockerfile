################################################################
# Stage 1 - Builder
################################################################
FROM golang:1.21 AS builder

WORKDIR /src
# allow overriding these at docker build time; Makefile will also compute defaults if not supplied
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=1970-01-01_00:00:00

# make sure modules are downloaded first for caching
COPY go.mod go.sum ./
RUN go env -w GOPROXY=https://proxy.golang.org
RUN go mod download

# copy rest of the repo
COPY . .

# Build statically (CGO disabled). We pass args to make so your Makefile's LDFLAGS are used as intended.
# If .git is present inside build context, the Makefile's git-based defaults will work; otherwise pass build-args.
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# Run your Makefile build target, injecting build-time metadata from build args.
RUN --mount=type=cache,target=/root/.cache/go-build \
    make build VERSION=${VERSION} COMMIT=${COMMIT} BUILD_TIME=${BUILD_TIME}
################################################################
# Stage 2 - Minimal runtime
################################################################
FROM scratch AS runtime

# copy the statically-built binary from builder
COPY --from=builder /src/bin/vmgrab /vmgrab

# non-root UID/GID values cannot be created in scratch; choose to run as root here
# (if you want non-root, switch to a small base like gcr.io/distroless/static:nonroot or add user in earlier stage)
ENTRYPOINT ["/vmgrab"]
