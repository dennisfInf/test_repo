#To Do: use a smaller image than gcc
FROM gcc:14.2.0 as build-env

RUN apt-get update && apt-get install -y wget cmake build-essential autoconf libtool pkg-config iproute2 gdb libcurl4-openssl-dev meson git
RUN git clone --depth=1 --branch 1.9.6 https://github.com/open-source-parsers/jsoncpp.git
WORKDIR /jsoncpp
RUN meson setup build
RUN meson compile -C build
RUN meson install -C build
#COPY ./lib/gmp /app/lib/gmp
#COPY ./lib/relic /app/lib/relic
RUN ln -s /usr/lib/x86_64-linux-gnu/libjsoncpp.so.25 /usr/lib/x86_64-linux-gnu/libjsoncpp.so.26
RUN groupadd -r user
RUN useradd -r -g user user
WORKDIR /app
#RUN git clone https://github.com/data61/MP-SPDZ.git --branch v0.3.8
WORKDIR /app/lib
RUN apt-get update && apt-get install -y wget python3 libssl-dev libgmp3-dev
RUN wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
RUN python3 install.py --deps --tool --ot --sh2pc
WORKDIR /app
COPY ./doram /app/doram
COPY ./circuits /app/lib/circuits
COPY ./src /app/src
COPY ./hostnames.txt /app/
COPY ./CMakeLists.txt /app/

RUN cmake --no-warn-unused-cli \
    -DCMAKE_BUILD_TYPE:STRING=Debug \
    -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
    -S. -B./build -G "Unix Makefiles"
RUN cmake --build ./build --config Debug --target all -j 18 --
RUN chown -R user:user ./build/doram
ENTRYPOINT ["./build/doram"]
