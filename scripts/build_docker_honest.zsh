#!/bin/zsh
#
#
#
script_path=$(realpath "$0")

script_dir=$(dirname "$script_path")
if [[ -n $(find $script_dir/Player-Data/*  -mindepth 1 -print -quit) ]]; then
  echo "The folder has content."
else
  $script_dir/../lib/MP-SPDZ/Scripts/setup-ssl.sh 20 $script_dir/Player-Data
  $script_dir/../lib/MP-SPDZ/Scripts/setup-clients.sh 20 $script_dir/Player-Data
  c_rehash $script_dir/Player-Data
fi
docker build -t mpspdz -f "$script_dir/../Dockerfile-MPSPDZ" \
    --build-arg arch=x86-64 \
    --build-arg cxx=g++ \
    --build-arg use_ntl=1 \
    --build-arg machine=shamir-party.x \
    --build-arg gfp_mod_sz=6 $script_dir/..

if [[ "$1" == "--gigadoram" ]]; then
  docker build -t poba --build-arg ENABLE_GDORAM=ON $script_dir/..
  echo "Gigadoram enabled.."
else
  docker build -t poba $script_dir/..
fi



