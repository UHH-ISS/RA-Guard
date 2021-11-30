FROM ubuntu:18.04

ARG IPMININET_VER=0.9
## GRPC_VER recommended by PI:
#ARG GRPC_VER=1.17.2
## Newest:
#ARG GRPC_VER=1.34.0
## GRPC_VER used by p4mn:
ARG GRPC_VER=1.19.0
# PI with P4Runtime v1.3.0
ARG PI_COMMIT=7b29612fe6a0f33d8668b7fce20457116179eda2
ARG THRIFT_VER=0.11.0
ARG NANOMSG_VER=1.0.0
ARG NNPY_COMMIT=c7e718a5173447c85182dc45f99e2abcf9cd4065
ARG BMV2_VER=1.14.0 
#ARG BMV2_COMMIT=a6330594486261b87560881ad2fd7db35f13ddfd
ARG JOBS=4

RUN apt-get update
RUN apt-get dist-upgrade -y

# Build dependencies:
RUN apt-get install --no-install-recommends -y \
    wget \
    git \
    sudo \
    python3-pip \
    python-pip \
    libjudy-dev \
    libssl1.0-dev \
    libgmp-dev

WORKDIR /tmp

RUN pip3 install --upgrade --force pip setuptools
RUN pip2 install --upgrade --force pip setuptools
RUN python3 -m pip install --upgrade git+https://github.com/cnp3/ipmininet.git@v${IPMININET_VER}
# some Docker workarounds
RUN apt-get download resolvconf
RUN dpkg --unpack resolvconf*.deb
RUN sed -i '/ln -nsf .*resolv.conf$/d' /var/lib/dpkg/info/resolvconf.postinst
RUN dpkg --configure resolvconf
RUN apt-get install -yf
RUN touch /etc/default/grub
RUN sed -i '/update_grub()$/d' /usr/local/lib/python3.6/dist-packages/ipmininet/install/install.py
# Install IPMininet
RUN python3 -m ipmininet.install -af


# Clone Grpc with protobuf dependencies
RUN git clone https://github.com/grpc/grpc.git
WORKDIR /tmp/grpc 
RUN git fetch --tags
RUN git checkout v$GRPC_VER
RUN git submodule update --init --recursive

# Install Protobuf
WORKDIR /tmp/grpc/third_party/protobuf
RUN ./autogen.sh
RUN ./configure --enable-shared
RUN make -j$JOBS
RUN make install-strip
RUN ldconfig
WORKDIR /tmp/grpc/third_party/protobuf/python
RUN python3 setup.py install
RUN python2 setup.py install

# Install grpc
WORKDIR /tmp/grpc 
# https://helperbyte.com/questions/439352/how-to-collect-grpc
RUN sed -i 's/-Werror//g' Makefile
RUN make -j${JOBS}
RUN make install
RUN ldconfig
RUN python3 setup.py install; exit 0
# failed frist time because setuptools?
RUN python3 setup.py install
RUN python2 setup.py install

# Build PI
WORKDIR /tmp
RUN git clone https://github.com/p4lang/PI.git
WORKDIR /tmp/PI
RUN git checkout ${PI_COMMIT}
RUN git submodule update --init --recursive
RUN ./autogen.sh
RUN ./configure --with-proto
RUN make -j $JOBS
RUN make install
RUN ldconfig

# Build Thrift
WORKDIR /tmp
RUN git clone -b ${THRIFT_VER} https://github.com/apache/thrift.git
WORKDIR /tmp/thrift
RUN ./bootstrap.sh
RUN ./configure --with-cpp=yes --with-c_glib=no --with-java=no --with-ruby=no --with-erlang=no --with-go=no --with-nodejs=no
RUN make -j $JOBS 
RUN sudo make install
RUN cd lib/py && sudo python2 setup.py install

# Build Nanomsg
WORKDIR /tmp
RUN wget https://github.com/nanomsg/nanomsg/archive/${NANOMSG_VER}.tar.gz -O nanomsg-${NANOMSG_VER}.tar.gz
RUN tar -xzvf nanomsg-${NANOMSG_VER}.tar.gz
WORKDIR /tmp/nanomsg-${NANOMSG_VER}
RUN mkdir build
WORKDIR /tmp/nanomsg-${NANOMSG_VER}/build
RUN cmake .. # -DCMAKE_INSTALL_PREFIX=/usr
RUN cmake --build .
RUN cmake --build . --target install
RUN ldconfig

# Build nnpy
# WORKDIR /tmp
# RUN git clone https://github.com/nanomsg/nnpy.git
# WORKDIR /tmp/nnpy
# RUN git checkout ${NNPY_COMMIT}
# RUN pip2 install cffi
# RUN pip2 install .
RUN pip2 install nnpy==1.4.2

# Build BMV2
WORKDIR /tmp
RUN git clone https://github.com/p4lang/behavioral-model.git
WORKDIR /tmp/behavioral-model
RUN git checkout ${BMV2_VER}
RUN ./autogen.sh
# Build only simple_switch and simple_switch_grpc
#RUN ./configure --with-pi --disable-elogger --without-nanomsg --without-thrift --without-targets CPPFLAGS="-I${PWD}/targets/simple_switch -DWITH_SIMPLE_SWITCH"
RUN ./configure --with-pi --enable-debugger 
RUN make -j${JOBS}
RUN make install
RUN ldconfig
# Build simple_switch
WORKDIR /tmp/behavioral-model/targets/simple_switch
RUN make -j${JOBS}
RUN make install
RUN ldconfig
# Build simple_switch_grpc
WORKDIR /tmp/behavioral-model/targets/simple_switch_grpc
RUN ./autogen.sh
RUN ./configure --with-thrift
RUN make -j${JOBS}
RUN make install
RUN ldconfig

# Other dependencies
RUN pip2 install ipaddr==2.2.0

# Useful tools
RUN apt-get install --no-install-recommends -y \
    ssh \
    net-tools \
    iputils-ping \
    iptables \
    net-tools \
    xauth \
    less \
    vim \
    arping \
    screen \
    thc-ipv6 \
    ipv6toolkit \
    netcat
RUN pip3 install psutil

RUN service openvswitch-switch start

RUN useradd -m -d /home/user -s /bin/bash user
RUN echo "user:user" | chpasswd
RUN echo "user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99_user
RUN chmod 440 /etc/sudoers.d/99_user
USER user
WORKDIR /home/user

CMD /bin/bash
