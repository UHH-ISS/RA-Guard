# from https://github.com/p4lang/p4runtime-shell/blob/master/Dockerfile
FROM ubuntu:20.04 AS deps

ARG COMMIT=74527de8c068db0b241322205037a9e2b63c2070

SHELL ["/bin/bash", "-c"]
ENV PKG_DEPS python3 python3-venv git
ENV VENV /p4runtime-sh/venv

RUN apt-get update && \
    apt-get install -y --no-install-recommends $PKG_DEPS && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*

RUN git clone https://github.com/p4lang/p4runtime-shell /p4runtime-sh/
WORKDIR /p4runtime-sh/
RUN git checkout ${COMMIT}
RUN git submodule update --init --recursive

RUN python3 -m venv $VENV && \
    source $VENV/bin/activate && \
    pip3 install --upgrade pip && \
    pip3 install --upgrade setuptools && \
    pip3 install scapy && \
    pip3 install -r requirements.txt && \
    rm -rf ~/.cache/pip

FROM ubuntu:20.04
LABEL maintainer="Antonin Bas <antonin@barefootnetworks.com>"
LABEL description="A shell based on ipython3 for P4Runtime"

# Any easy way to avoid installing these packages again?
ENV PKG_DEPS python3 python3-venv
ENV VENV /p4runtime-sh/venv

RUN apt-get update && \
    apt-get install -y --no-install-recommends $PKG_DEPS && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*

COPY --from=deps /p4runtime-sh/ /p4runtime-sh/

WORKDIR /p4runtime-sh/

ENTRYPOINT ["/p4runtime-sh/docker_entry_point.sh"]
