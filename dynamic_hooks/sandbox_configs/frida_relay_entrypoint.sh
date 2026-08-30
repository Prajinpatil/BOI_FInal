#!/bin/bash
set -e

echo "Starting Frida Relay..."
echo "Waiting for ADB target: ${ADB_SERIAL}"

# Start adb server
adb start-server

# Wait for device to connect (MobSF emulator)
until adb -s ${ADB_SERIAL} get-state 1>/dev/null 2>&1; do
    echo "Waiting for emulator to come online..."
    sleep 5
done

echo "Emulator is online! Connecting and forwarding port..."
adb -s ${ADB_SERIAL} forward tcp:27042 tcp:27042

# Keep the container alive and monitor connection
while true; do
    adb -s ${ADB_SERIAL} get-state 1>/dev/null 2>&1 || exit 1
    sleep 10
done
