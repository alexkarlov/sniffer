#/bin/bash
up:
	docker build --no-cache -t sniffer .
	docker run --net=host -it --rm --name my-sniffer sniffer
