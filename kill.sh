#!/bin/bash

# Find the PID of the running server.sh script
SERVER_PID=$(pgrep -f "./server.sh")

# Kill the whole process group if found
if [ -n "$SERVER_PID" ]; then
  echo "Killing process group of PID $SERVER_PID"
  kill -- -"$SERVER_PID"
else
  echo "No server.sh process found."
fi
