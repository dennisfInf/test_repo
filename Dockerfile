#To Do: use a smaller image than gcc
FROM gcc:11.4.0 AS build-env
RUN apt-get update && apt-get install -y wget cmake protobuf-compiler build-essential autoconf libtool pkg-config git libsodium-dev libboost-dev libboost-thread-dev libboost-filesystem-dev iproute2
RUN git clone --recurse-submodules -b v1.60.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc
WORKDIR /grpc
RUN mkdir -p cmake/build
WORKDIR /grpc/cmake/build

RUN cmake -DgRPC_INSTALL=ON \
    -DgRPC_BUILD_TESTS=OFF \
    -DCMAKE_INSTALL_PREFIX=$MY_INSTALL_DIR \
    ../..
RUN make -j 4
RUN make install
COPY ./lib /app/lib
WORKDIR /app/lib
ARG ENABLE_GDORAM=OFF
RUN echo "GigaDORAM enabled: $ENABLE_GDORAM"
RUN if [ "$ENABLE_GDORAM" = "ON" ]; then \
    apt-get update && \
    apt-get install -y wget python3 libssl-dev libgmp3-dev && \
    wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py && \
    python3 install.py --deps --tool --ot --sh2pc; \
    else \
    echo "Feature DORAM is disabled"; \
    fi
#COPY ./lib/gmp /app/lib/gmp
#COPY ./lib/relic /app/lib/relic
WORKDIR /app
COPY ./src /app/src
COPY ./inc /app/inc 
COPY ./CMakeLists.txt /app/
COPY ./protos /app/protos
#RUN git clone https://github.com/data61/MP-SPDZ.git --branch v0.3.8
RUN cmake --no-warn-unused-cli \
    -DCMAKE_BUILD_TYPE:STRING=Debug \
    -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
    -DENABLE_GDORAM=${ENABLE_GDORAM}\
    -S. -B./build -G "Unix Makefiles"
RUN cmake --build ./build --config Debug --target all -j 18 --
FROM gcc:11.4.0 AS env
RUN apt-get update && apt-get install -y build-essential autoconf libtool pkg-config git libsodium-dev  libboost-dev libboost-filesystem-dev libboost-thread-dev iproute2 gdb
COPY --from=build-env /app /app
WORKDIR /app
COPY ./scripts/Player-Data ./Player-Data
RUN c_rehash ./Player-Data
#OPTIONAL FOR DEBUGGING
#RUN apt-get install -y gdb
RUN mkdir -p /app/benchmarks
ENTRYPOINT ["./build/poba"]
