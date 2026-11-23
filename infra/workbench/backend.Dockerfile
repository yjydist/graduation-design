FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build
ARG TARGETARCH
ARG TARGETOS
WORKDIR /src
COPY protocol/go.mod protocol/go.sum ./protocol/
COPY platform/go.mod platform/go.sum ./platform/
WORKDIR /src/platform
ENV GOWORK=off CGO_ENABLED=0
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY protocol /src/protocol
COPY platform /src/platform
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/workbench ./cmd/workbench

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/workbench /usr/local/bin/workbench
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/workbench"]
