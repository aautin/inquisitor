all:
	docker-compose up -d --build

clean:
	docker-compose down --rmi all --remove-orphans

re: clean all
