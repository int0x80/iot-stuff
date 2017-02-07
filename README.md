# iot-stuff
Internet of Things lol


# iotables.py
IoTables analyzes packets captured from a device and tries to generate relevant iptables rules. The goal is to assist in properly isolating IoT devices on a network.

## Note about MAC addresses

IoTables makes a best guess for the target device's MAC address based on the most frequently seen MAC that is not one of the whitelisted MACs.  This should reveal the target device MAC but actual results have been inconsistent.  If you want to be certain, bring down the internet-facing interface and associate the target device to the AP.  The only non-broadcast MACs should be the WLAN interface and the target device.
