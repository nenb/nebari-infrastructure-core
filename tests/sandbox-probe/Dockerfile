ARG GO_IMAGE=golang:1.26.9-alpine
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build

ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY tests/sandbox-probe/go.mod tests/sandbox-probe/go.sum ./
RUN go mod download
COPY tests/sandbox-probe/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/psr-probe \
    .

FROM scratch
COPY --from=build /out/psr-probe /psr-probe
USER 65532:65532
ENTRYPOINT ["/psr-probe"]
