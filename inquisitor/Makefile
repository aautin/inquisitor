all:
	DOCKER_IGNORE_BR_NETFILTER_ERROR=1 docker-compose up -d --build

clean:
	docker-compose down --rmi all --remove-orphans

re: clean all
