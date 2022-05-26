#!/bin/bash

docker build -t gzmaxsum/fcbreak:client --target=client
docker build -t gzmaxsum/fcbreak:server --target=server