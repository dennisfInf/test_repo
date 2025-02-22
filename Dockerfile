#To Do: use a smaller image than gcc
FROM gcc:11.4.0 as build-env

RUN apt-get update && apt-get install -y wget cmake protobuf-compiler build-essential autoconf libtool pkg-config git libsodium-dev libboost-dev libboost-thread-dev iproute2
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
#COPY ./lib/gmp /app/lib/gmp
#COPY ./lib/relic /app/lib/relic
WORKDIR /app
COPY ./src /app/src
COPY ./inc /app/inc 
COPY ./CMakeLists.txt /app/
COPY ./protos /app/protos
RUN apt-get install -y libboost-filesystem-dev
#RUN git clone https://github.com/data61/MP-SPDZ.git --branch v0.3.8
RUN cmake --no-warn-unused-cli \
    -DCMAKE_BUILD_TYPE:STRING=Debug \
    -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
    -S. -B./build -G "Unix Makefiles"
RUN cmake --build ./build --config Debug --target all -j 18 --
FROM gcc:11.4.0 as env
RUN apt-get update && apt-get install -y build-essential autoconf libtool pkg-config git libsodium-dev  libboost-dev libboost-filesystem-dev libboost-thread-dev iproute2 gdb
COPY --from=build-env /app /app
WORKDIR /app
RUN groupadd -r user
RUN useradd -r -g user user
RUN chown -R user:user ./build/ippa
COPY ./scripts/Player-Data ./Player-Data
RUN chown -R user:user ./Player-Data
RUN c_rehash ./Player-Data
RUN apt-get install -y gdb
USER user
ENTRYPOINT ["./build/ippa"]
