#!/bin/bash

# Run graphical app in docker: 
#   https://blog.yadutaf.fr/2017/09/10/running-a-graphical-app-in-a-docker-container-on-a-remote-server/
#   https://stackoverflow.com/questions/48235040/run-x-application-in-a-docker-container-reliably-on-a-server-connected-via-ssh-w

# Prepare target env
CONTAINER_HOSTNAME="ra-guard"

# Get the DISPLAY slot
DISPLAY_NUMBER=$(echo $DISPLAY | cut -d. -f1 | cut -d: -f2)

# Extract current authentication cookie
AUTH_COOKIE=$(xauth list | grep "^$(hostname)/unix:${DISPLAY_NUMBER} " | awk '{print $3}')

# Create the new X Authority file
XAUTH=/tmp/.docker.xauth
sudo rm -f $XAUTH
touch $XAUTH
sudo xauth -f $XAUTH add ${CONTAINER_HOSTNAME}/unix:${DISPLAY_NUMBER} MIT-MAGIC-COOKIE-1 ${AUTH_COOKIE}
sudo chown 1000 $XAUTH

# Launch the container
sudo docker stop ${CONTAINER_HOSTNAME} 2> /dev/null
sudo docker rm ${CONTAINER_HOSTNAME} 2> /dev/null
sudo docker run -it --rm=false --privileged \
  -e DISPLAY=$DISPLAY \
  -v /lib/modules:/lib/modules \
  -e XAUTHORITY=$XAUTH \
  -v $XAUTH:$XAUTH \
  -v ${PWD}/mininet_src:/home/user \
  --name=${CONTAINER_HOSTNAME} \
  --hostname ${CONTAINER_HOSTNAME} \
  --ip 172.17.0.2 \
  --expose=50051 \
  ipmininet \
  sudo -E python3 main.py $@
  # --net host \
