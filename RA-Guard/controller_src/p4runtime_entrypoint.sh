#!/usr/bin/env bash

source $VENV/bin/activate
export PYTHONPATH=${PYTHONPATH}:/p4runtime-sh
cd src
python3 mycontroller.py $@
