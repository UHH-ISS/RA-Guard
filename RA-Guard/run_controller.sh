#!/usr/bin/bash

sudo docker run -ti --rm=true -v ${PWD}/controller_src:/p4runtime-sh/src --entrypoint /p4runtime-sh/src/p4runtime_entrypoint.sh p4runtime-sh $@

# sudo docker run -ti -v ${PWD}/controller_src:/p4runtime-sh/src p4lang/p4runtime-sh --grpc-addr 172.17.0.2:50051 --device-id 0 --election-id 0,1 # --config src/p4build/raguard.p4info.txt,src/p4build/raguard.json
