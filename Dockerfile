FROM golang:1.24-alpine
LABEL authors="steplet"

WORKDIR /app

COPY go.mod ./

RUN go mod download

COPY . .

RUN go build -o main

CMD ["./main"]