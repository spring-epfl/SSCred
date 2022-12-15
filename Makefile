CURRENT_VERSION ?= `poetry version -s`
SEMVERS := major minor patch

install_dependencies:
	sudo apt-get install python-dev
	sudo apt-get install libssl-dev
	sudo apt-get install libffi-dev

install: install_poetry

install_poetry:
		poetry install

tests:
		poetry run pytest

clean:
		find . -name "*.pyc" -exec rm -rf {} \;
		rm -rf dist *.egg-info __pycache__ .eggs

dist:
		poetry build

tag_version: 
		git commit -m "build: bump to ${CURRENT_VERSION}" pyproject.toml
		git tag ${CURRENT_VERSION}

$(SEMVERS):
		poetry version $@
		$(MAKE) tag_version

set_version:
		poetry version ${CURRENT_VERSION}
		$(MAKE) tag_version