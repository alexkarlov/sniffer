#/bin/bash
up:
	docker build --no-cache -t sniffer .
	docker run -it --rm --name my-sniffer sniffer
