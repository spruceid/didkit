#!/bin/bash

cd ../..
docker build -t didkit-demo -f lib/web/Dockerfile .
docker run -v `pwd`/lib/web/demo/pkg:/workspace/output didkit-demo