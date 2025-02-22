#!/bin/zsh
#
#
#
script_path=$(realpath "$0")

script_dir=$(dirname "$script_path")

docker build -t poba $script_dir/..