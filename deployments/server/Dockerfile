FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ghost-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/ghost-server /app/ghost-server
COPY configs/server.yaml /app/configs/server.yaml
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/app/ghost-server", "-config", "/app/configs/server.yaml"]
