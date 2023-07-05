#!/bin/bash

DOCKER_BUILDKIT=1 docker build -t gzmaxsum/fcbreak-client:test --target=client .
DOCKER_BUILDKIT=1 docker build -t gzmaxsum/fcbreak-server:test --target=server .

docker push gzmaxsum/fcbreak-client:test
docker push gzmaxsum/fcbreak-server:test