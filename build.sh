#!/bin/bash

cmake ..
make -C modules/kernel
make -C modules/patch
make -C modules/user
make -C modules/kplugin
make -C modules/uplugin
make

