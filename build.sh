#!/bin/bash

DOCKER_BUILDKIT=1 docker build -t gzmaxsum/fcbreak:client --target=client .
DOCKER_BUILDKIT=1 docker build -t gzmaxsum/fcbreak:server --target=server .
