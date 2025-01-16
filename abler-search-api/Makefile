.PHONY: install run clean build-docker run-docker

install:
	pip install -r requirements.txt

run:
	uvicorn main:app --reload --host 0.0.0.0 --port 8001

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build-docker:
	docker build -t abler-search-api .

run-docker:
	docker run -p 8000:8000 --env-file .env abler-search-api