FROM golang:1.13

WORKDIR /go/src/app

RUN apt update && apt install -y libpcap0.8-dev 

COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

#CMD ["sleep", "infinetly"]
CMD ["app"]
