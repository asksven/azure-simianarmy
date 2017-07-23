# Container Monkey

aims at detecting vulnerabilities in Docker images from the local Docker host (uses `docker image list` as input, this can easily be changed to any other source).

Container Monkey uses anchore (https://github.com/anchore/anchore) for inspecting the containers. 

Currently it runs as a script on a Docker host but in the future I may look into packaging it into a container. 

`container-monkey.sh` scans all images from the local Docker host and reports whether high vulns have been found

## Features
Checks all Docker images on the Docker host (using `docker image list`) and reports if high vulnerabilities have been found

## Setup

In order to run Container Monkey you must have docker installed on your host and have the anchore-cli running as a container on it:

```
docker pull anchore/cli
docker run -d -v /var/run/docker.sock:/var/run/docker.sock --name anchore_cli anchore/cli:latest
# initialize the database
docker exec anchore_cli anchore feeds sync
```

Following environment variables can be set:
- `SlackURL`      : can be empty, in that case nothing will get sent to slack. We use this implementation: https://github.com/asksven/azure-functions-slack-bot
- `SlackChannel`  : can be empty, default will be used in that case



## Usage

1. Set the environment variables
2. Run `container-monkey.ps1`

