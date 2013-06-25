#!/bin/bash

# Copyright 2012
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

if [ "$(id -u)" != "0" ]; then
	echo -e "\033[31m\033[1m[!]\033[0m This script must be run as root." 1>&2
	exit 1
fi

echo -e "\033[1m\033[36m[*]\033[0m Installing packages ..."
apt-get install python python-dev python-pip build-essential
# Install MinGW for C payloads
apt-get install mingw-w64

# install mono for C# payloads
apt-get install monodoc-browser
apt-get install monodevelop
apt-get install mono-mcs


echo -e "\033[1m\033[36m[*]\033[0m Installing Python libs ..."

pip install twisted
pip install sqlalchemy

