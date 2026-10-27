# Build stage: compile the Go app. The SQLite driver uses cgo, so this image
# needs a C compiler, which the official golang image already has.
FROM golang:1.27-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /cfp-desk .

# Run stage: a small image with just the compiled app.
FROM debian:trixie-slim
RUN useradd --create-home app && mkdir /data && chown app /data
USER app
COPY --from=build /cfp-desk /usr/local/bin/cfp-desk
ENV DB_PATH=/data/cfp-desk.db PORT=8080
EXPOSE 8080
CMD ["cfp-desk"]
