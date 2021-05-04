.PHONY: run docker-build docker-run clean-docker clean-container clean-image get-token
.DEFAULT_GOAL := run

export CONTAINER_NAME = compass-numapp-downloader
export IMAGE_NAME = compass-numapp-downloader
export LOG_DIR = /your/path/to/compass-numapp-downloader/logs


run: ## execute downloader script
	python downloader.py

docker-build: ## build docker image
	docker build -t $(IMAGE_NAME) .

docker-run: ## run docker image
ifeq ("$(wildcard $(LOG_DIR))","")
$(error Please specify path to logs directory by adapting value of variable 'LOG_DIR')
endif
	echo 'Logging to directory $(LOG_DIR)'
	docker run -v $(LOG_DIR):/logs --name $(CONTAINER_NAME) $(IMAGE_NAME)
	docker rm $(CONTAINER_NAME)

clean-docker: ## remove Docker image and container
	clean-container clean-image 

clean-container: ## remove Docker container
	docker rm $(CONTAINER_NAME)

clean-image: ## remove Docker image
	docker image rm $(IMAGE_NAME)

get-token: ## overwrite docker entry to retrieve auth token
	docker run --name $(CONTAINER_NAME) $(IMAGE_NAME) \
	python -c \
	'from downloader import get_authentication_token; \
	import sys; \
	print(get_authentication_token(), file=sys.stderr) \
	' 2>&1 1>/dev/null

