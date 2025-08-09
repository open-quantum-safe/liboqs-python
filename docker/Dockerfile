# Multi-stage build: First the full builder image:

# liboqs build type variant; maximum portability of image; no openssl dependency:
ARG LIBOQS_BUILD_DEFINES="-DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF \
    -DOQS_ENABLE_SIG_STFL_LMS=ON -DOQS_ENABLE_SIG_STFL_XMSS=ON \
    -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON"

# make build arguments: Adding -j here speeds up build but may tax hardware
ARG MAKE_DEFINES="-j 2"

# Define default versions for Python and Alpine
ARG PYTHON_VERSION=3.10.16
ARG ALPINE_VERSION=3.20

FROM alpine:${ALPINE_VERSION} AS intermediate
# Take in all global args
ARG LIBOQS_BUILD_DEFINES
ARG MAKE_DEFINES

LABEL version="2"

ENV DEBIAN_FRONTEND=noninteractive

RUN apk update && apk upgrade

# Get all software packages required for building all components:
RUN apk add build-base linux-headers cmake ninja git

# get all sources
WORKDIR /opt
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs && \
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs-python.git 

# build liboqs 
WORKDIR /opt/liboqs
RUN mkdir build && cd build && cmake -GNinja .. ${LIBOQS_BUILD_DEFINES} && ninja install

WORKDIR /opt
RUN git clone --depth 1 --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git && cd liboqs && mkdir build-openssl && cd build-openssl && cmake -G"Ninja" .. ${LIBOQS_BUILD_DEFINES} -DCMAKE_INSTALL_PREFIX=/opt/openssl/oqs && ninja install

RUN apk add automake autoconf && cd /opt/openssl && LDFLAGS="-Wl,-rpath -Wl,/usr/local/lib64" ./Configure shared linux-x86_64 -lm && make ${MAKE_DEFINES} && make install_sw

# Get LetsEncrypt root
RUN wget https://letsencrypt.org/certs/isrgrootx1.pem

## second stage: Only create minimal image without build tooling and intermediate build results generated above:
FROM python:${PYTHON_VERSION}-alpine${ALPINE_VERSION}

# Only retain the binary contents in the final image
COPY --from=intermediate /usr/local /usr/local
COPY --from=intermediate /opt/liboqs-python /opt/liboqs-python

ENV PYTHONPATH=/opt/liboqs-python

# Install liboqs-python
RUN cd /opt/liboqs-python && pip install .

# Enable a normal user 
RUN addgroup -g 1000 -S oqs && adduser --uid 1000 -S oqs -G oqs 

USER oqs
WORKDIR /home/oqs
COPY minitest.py /home/oqs/minitest.py
COPY --from=intermediate /opt/isrgrootx1.pem /home/oqs/isrgrootx1.pem

# ensure oqs libs are found. Unset if interested in using stock openssl:
ENV LD_LIBRARY_PATH=/usr/local/
ENV OQS_INSTALL_PATH=/usr/local/
CMD ["python3", "minitest.py"]
