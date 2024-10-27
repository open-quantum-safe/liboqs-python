# Multi-stage build: First the full builder image:

# define the liboqs tag to be used
ARG LIBOQS_TAG=main

# define the oqsprovider tag to be used
ARG OQSPROVIDER_TAG=main

# Default location where all binaries wind up:
ARG INSTALLDIR=/opt/oqssa

# liboqs build type variant; maximum portability of image:
ARG LIBOQS_BUILD_DEFINES="-DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON"

# Default root CA signature algorithm; can be set to any listed at https://github.com/open-quantum-safe/oqs-provider#algorithms
ARG SIG_ALG="dilithium2"

# Default KEM algorithms; can be set to any listed at https://github.com/open-quantum-safe/oqs-provider#algorithms
ARG DEFAULT_GROUPS="x25519:x448:kyber512:p256_kyber512:kyber768:p384_kyber768:kyber1024:p521_kyber1024"

# Define the degree of parallelism when building the image; leave the number away only if you know what you are doing
ARG MAKE_DEFINES="-j 4"

ARG PYTHON_VERSION=3.11.0

FROM alpine:latest as intermediate
# Take in all global args
ARG LIBOQS_TAG
ARG OQSPROVIDER_TAG
ARG INSTALLDIR
ARG LIBOQS_BUILD_DEFINES
ARG SIG_ALG
ARG DEFAULT_GROUPS
ARG MAKE_DEFINES

LABEL version="4"

ENV DEBIAN_FRONTEND=noninteractive

RUN apk update && apk upgrade

# Get all software packages required for builing all components:
RUN apk add build-base linux-headers \
            libffi-dev zlib-dev xz-dev bzip2-dev \
            libtool automake autoconf cmake ninja \
            make \
            openssl3 openssl3-dev \
            git wget \
            py3-pip python3

# get all sources
WORKDIR /opt
RUN git clone --depth 1 --branch ${LIBOQS_TAG} https://github.com/open-quantum-safe/liboqs && \
    git clone --depth 1 --branch master https://github.com/openssl/openssl.git && \
    git clone --depth 1 --branch ${OQSPROVIDER_TAG} https://github.com/open-quantum-safe/oqs-provider.git && \
    git clone https://github.com/gobbledy-gook/liboqs-python.git

    
# build liboqs
WORKDIR /opt/liboqs
RUN mkdir build && cd build && cmake -G"Ninja" .. ${LIBOQS_BUILD_DEFINES} -DCMAKE_INSTALL_PREFIX=${INSTALLDIR} && ninja install

# build OpenSSL3
WORKDIR /opt/openssl
RUN LDFLAGS="-Wl,-rpath -Wl,${INSTALLDIR}/lib64:${INSTALLDIR}/lib" ./config shared --prefix=${INSTALLDIR} && \
    make ${MAKE_DEFINES} && make install_sw install_ssldirs;

# set path to use 'new' openssl. Dyn libs have been properly linked in to match
ENV PATH="${INSTALLDIR}/bin:${PATH}"

# build & install provider (and activate by default)
WORKDIR /opt/oqs-provider
RUN ln -s ../openssl . && cmake -DOPENSSL_ROOT_DIR=${INSTALLDIR} -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=${INSTALLDIR} -S . -B _build && cmake --build _build  && cp _build/lib/oqsprovider.so ${INSTALLDIR}/lib64/ossl-modules && sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" /opt/oqssa/ssl/openssl.cnf && sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" /opt/oqssa/ssl/openssl.cnf && sed -i "s/providers = provider_sect/providers = provider_sect\nssl_conf = ssl_sect\n\n\[ssl_sect\]\nsystem_default = system_default_sect\n\n\[system_default_sect\]\nGroups = \$ENV\:\:DEFAULT_GROUPS\n/g" /opt/oqssa/ssl/openssl.cnf && sed -i "s/\# Use this in order to automatically load providers/\# Set default KEM groups if not set via environment variable\nKDEFAULT_GROUPS = $DEFAULT_GROUPS\n\n# Use this in order to automatically load providers/g" /opt/oqssa/ssl/openssl.cnf && sed -i "s/HOME\t\t\t= ./HOME\t\t= .\nDEFAULT_GROUPS\t= ${DEFAULT_GROUPS}/g" /opt/oqssa/ssl/openssl.cnf
    
# Building Python using OPENSSL3
# WORKDIR /usr/local
# RUN wget https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tgz
# RUN tar -xzf Python-3.11.0.tgz
# RUN cd Python-3.11.0 && ./configure --with-openssl=${INSTALLDIR} --with-openssl-rpath=${INSTALLDIR}/lib64 --enable-optimizations && \
#  make && make altinstall
# # Check where Python is installed
# RUN echo "Checking installed binaries:" && ls -l /usr/local/bin && ls -l /usr/bin
# generate certificates for openssl s_server, which is what we will test curl against
ENV OPENSSL=${INSTALLDIR}/bin/openssl
ENV OPENSSL_CONF=${INSTALLDIR}/ssl/openssl.cnf


# Download and integrate LetsEncrypt Root CA to CA bundle
WORKDIR /opt
RUN wget https://letsencrypt.org/certs/isrgrootx1.pem


## second stage: Only create minimal image without build tooling and intermediate build results generated above:
FROM alpine:latest
# Take in all global args
ARG INSTALLDIR
ARG SIG_ALG

RUN apk update && apk upgrade
RUN apk add py3-pip python3

# Only retain the ${INSTALLDIR} contents in the final image
COPY --from=intermediate ${INSTALLDIR} ${INSTALLDIR}
COPY --from=intermediate /usr/local /usr/local
COPY --from=intermediate /opt/liboqs-python /opt/liboqs-python

# set path to use 'new' openssl. Dyn libs have been properly linked in to match
ENV PATH="${INSTALLDIR}/bin:${PATH}"
ENV PYTHONPATH=/opt/liboqs-python

# generate certificates for openssl s_server, which is what we will test curl against
ENV OPENSSL=${INSTALLDIR}/bin/openssl
ENV OPENSSL_CONF=${INSTALLDIR}/ssl/openssl.cnf

# Install liboqs-python
RUN cd /opt/liboqs-python && python3 setup.py install

RUN addgroup -g 1000 -S oqs && adduser --uid 1000 -S oqs -G oqs 

USER oqs
WORKDIR /home/oqs
COPY ./liboqs-python/docker/minitest.py /home/oqs/minitest.py
COPY --from=intermediate /opt/isrgrootx1.pem /home/oqs/isrgrootx1.pem

# ensure oqs libs are found. Unset if interested in using stock openssl:
ENV LD_LIBRARY_PATH=${INSTALLDIR}/lib64
CMD ["python3", "minitest.py"]
