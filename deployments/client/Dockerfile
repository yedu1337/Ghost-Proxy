FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ghost-client ./cmd/client

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/ghost-client /app/ghost-client
COPY configs/client.yaml /app/configs/client.yaml
USER 65532:65532
EXPOSE 1080
ENTRYPOINT ["/app/ghost-client", "-config", "/app/configs/client.yaml"]
