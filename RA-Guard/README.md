# P4 RA-Guard implementation

This repository contains a proof-of-concept implementation of the IPv6 Router Advertisement Guard (RA-Guard) proposed by RFC6105.


## Installation

This setup is tested on Debian 10 and Ubuntu 18.

Install dependencies and build docker images:

    make install


## Usage

Build the P4-programs:

    make p4build

Run the whole setup: the IPMininet-Topology, the P4Runtime Controller and monitor the logfiles and traffic

    make run

Run the whole setup with a test

    make test

Select a topology:

    make run TOPO=simple

Available topologies:

- simple
- simple-bmv2
- attack
- attack-bmv2 (default)

Select a P4 program:

    make run P4PROGRAM=raguard

Available P4 programs:

- basic
    - only packet forwarding
- simple_raguard
    - simple stateless Router Advertisement filtering
- eh_raguard 
    - can parse IPV6 extension header
- raguard 
    - can handle fragmentation 
- stateful_raguard 
    - final version

Specify controller arguments:
    
    make run CONTROLLER_ARGS='--default-router --stateless'

Possible controller arguments:

    --default-router, -d  Insert preconfigured router information for RA filtering
    --monitor, -m         Monitor RA incidents
    Following arguments only work with the final program "stateful_raguard"
    --stateful, -sf       Initiate stateful RA learning
    --stateless, -sl      Set RA-Guard in stateless mode
    --off, -o             Deactivate RA-Guard filtering
    --learning-period LEARNING_PERIOD, -p LEARNING_PERIOD
                          set the time period in seconds for the LEARNING state

Further network topologies can be added in `mininet_src/topo/topo.py`.
All static match+action table entries for forwarding and stateless filtering can be found in `controller_src/table_entries.py`. 
