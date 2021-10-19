#!/usr/bin/env sh

# A basic script used to check if a TCP port is open using curl on a host.
# Will continue to check the host every 5 second.
#
# NOTE: This will attempt to do both nc and curl and is expecting the image to have one of these executables installed
#
# Inspired by the wait-for-postgres.sh from https://docs.docker.com/compose/startup-order/
#
# Usage: ./wait-for-it.sh host:port

host=$(printf "%s\n" "$1" | cut -d : -f 1)
port=$(printf "%s\n" "$1" | cut -d : -f 2)
shift
cmd="$@"

echo "Testing if $host:$port is ready"

success=false

function testConnection() {
  if timeout 2s curl -v telnet://"$host":"$port" 2>&1 | grep "Connected to"; then
    echo "${host}:${port} is available with cURL."
    success=true
  elif nc -z ${host} ${port}; then
    echo "${host}:${port} is available with nc."
    success=true
  else
    echo "${host}:${port} is not available"
    success=false
  fi
}

testConnection

until $success ; do
  testConnection
  >&2 echo "${host}:${port} is unavailable - sleeping"
  sleep 5
done


echo "${host}:${port} is up - executing command ${cmd}"
exec $cmd
