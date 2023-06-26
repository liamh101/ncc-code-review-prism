FROM golang:1.20

ENV GO111MODULE=on

ADD . /usr/local/go/src/ncc
WORKDIR /usr/local/go/src/ncc
RUN go mod download && go mod verify 
RUN go build -v

CMD ["app"]