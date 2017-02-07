# iot-stuff
Internet of Things lol


# iotables.py
IoTables analyzes packets captured from a device and tries to generate relevant iptables rules. The goal is to assist in properly isolating IoT devices on a network.

```
Usage: iotables.py [OPTIONS] <PCAP FILE...>
OPTIONS
 -d <NAME>, --device <NAME>
       Name for the device from which the pcap originated; e.g. Nest, Sonos, etc

 -o <PREFIX>, --output <PREFIX>
       Prefix for file names created with result output. Defaults to device name.

Example: python iotables.py -d Sonos -o sonos5 /tmp/sonos*.pcap
```

## Note about MAC addresses

IoTables makes a best guess for the target device's MAC address based on the most frequently seen MAC that is not one of the whitelisted MACs.  This should reveal the target device MAC but actual results have been inconsistent.  If you want to be certain, bring down the internet-facing interface and associate the target device to the AP.  The only non-broadcast MACs should be the WLAN interface and the target device.
