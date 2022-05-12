# HINT
# Use this file to override variables here.
# For example, to run with podman put `DOCKER=podman` there.
-include Makefile.env

# NOTE
# Variables specified in `.env` file are used to pick and setup specific
# component versions, both when building a development image and when running
# CI workflows on GH Actions. This ensures that tasks run with `wc-` prefix
# (like `wc-dialyze`) are reproducible between local machine and CI runners.
DOTENV := $(shell grep -v '^\#' .env)

# Development images
DEV_IMAGE_TAG = wapi-lib-dev
DEV_IMAGE_ID = $(file < .image.dev)

DOCKER ?= docker
REBAR ?= rebar3

all: compile

.PHONY: dev-image clean-dev-image wc-shell test

dev-image: .image.dev

.image.dev: Dockerfile.dev .env
	$(DOCKER) build $(DOTENV:%=--build-arg %) -f Dockerfile.dev -t $(DEV_IMAGE_TAG) .
	$(DOCKER) image ls -q -f "reference=$(DEV_IMAGE_TAG)" | head -n1 > $@

clean-dev-image:
ifneq ($(DEV_IMAGE_ID),)
	$(DOCKER) image rm -f $(DEV_IMAGE_TAG)
	rm .image.dev
endif

DOCKER_WC_OPTIONS := -v $(PWD):$(PWD) --workdir $(PWD)
DOCKER_WC_EXTRA_OPTIONS ?= --rm
DOCKER_RUN = $(DOCKER) run -t $(DOCKER_WC_OPTIONS) $(DOCKER_WC_EXTRA_OPTIONS)

# Utility tasks

wc-shell: dev-image
	$(DOCKER_RUN) --interactive --tty $(DEV_IMAGE_TAG)

wc-%: dev-image
	$(DOCKER_RUN) $(DEV_IMAGE_TAG) make $*

# Rebar tasks

rebar-shell:
	$(REBAR) shell

compile:
	$(REBAR) compile

xref:
	$(REBAR) xref

lint:
	$(REBAR) lint

check-format:
	$(REBAR) fmt -c

dialyze:
	$(REBAR) as test dialyzer

release:
	$(REBAR) as prod release

eunit:
	$(REBAR) eunit --cover

common-test:
	$(REBAR) ct --cover

cover:
	$(REBAR) covertool generate

format:
	$(REBAR) fmt -w

clean:
	$(REBAR) clean

distclean: clean-build-image
	rm -rf _build

test: eunit common-test

cover-report:
	$(REBAR) cover
