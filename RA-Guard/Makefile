TOPO=attack-bmv2
P4PROGRAM=stateful_raguard
CONTROLLER_ARGS='--monitor'

source = $(wildcard p4_src/*.p4)
compiled_json := $(source:.p4=.json)

all: p4build run

install: dependencies build

dependencies:
	./Setup/docker.sh 
	sudo apt install tmuxinator

build:
	sudo docker build -t ipmininet ./Setup/IPMininet/
	sudo docker build -t p4c ./Setup/P4C
	sudo docker build -t p4runtime-sh ./Setup/P4RuntimeShell

run:
	tmuxinator start -p tmux/${TOPO}.yml p4=${P4PROGRAM} c_args="${CONTROLLER_ARGS}"

test:
	tmuxinator start -p tmux/${TOPO}.yml --test p4=${P4PROGRAM} c_args="${CONTROLLER_ARGS}"

stop: 
	tmux kill-session

p4build: dirs $(compiled_json)

dirs:
	mkdir -p controller_src/p4build

%.json: %.p4
	sudo docker run -it --rm=true --privileged \
	-v ${PWD}/controller_src/p4build:/p4c/p4build \
	-v ${PWD}/p4_src:/p4c/p4_src \
	p4c \
	p4c-bm2-ss --p4v 16 --p4runtime-files p4build/$(basename $(notdir $@)).p4info.txt -o p4build/$(notdir $@) $<

clean:
	rm -rf controller_src/p4build
