#!/bin/bash
mkdir -p ~/myapp/prefix
export WINEPREFIX=$HOME/myapp/prefix
export WINEARCH=win32
export WINEPATH=$HOME/myapp
wineboot -- init
winetricks
