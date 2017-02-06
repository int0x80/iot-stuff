#!/usr/bin/env python
# -----------------------------------------------------------
# Author: int0x80
# License: WTFPL (http://www.wtfpl.net/)
# Usage: iotables.py <device name> <pcap file>
#
# IoTables analyzes packets captured from a device and tries
# to generate relevant iptables rules. The goal is to assist
# in properly isolating IoT devices on a network.
#
# I currently use an ALFA with a Raspberry Pi to create a 
# wifi network. A target device is associated to the network,
# and all traffic is sniffed on the Pi. Whitelist the IP and
# MAC of the lab network and wifi interface, respectively,
# via the LAB_NETWORK and WLAN_MAC variables below.
# -----------------------------------------------------------

from scapy.all import *
from scapy.layers import http
from sys import argv, exit


# -----------------------------------------------------------
# User configuration
# -----------------------------------------------------------
LAB_NETWORK = '10.99.1.'
WLAN_MAC = '00:c0:ca:57:2d:99'


# -----------------------------------------------------------
# DNS queries made
# -----------------------------------------------------------
def get_dns(packets):
  dns_queries = []
  for p in packets:
    if p.haslayer(DNSRR):
      if p.getlayer(DNSRR).rrname not in dns_queries:
        dns_queries.append(p.getlayer(DNSRR).rrname)

  return dns_queries


# -----------------------------------------------------------
# HTTP requests detected
# -----------------------------------------------------------
def get_http(packets):
  http_requests = []

  for p in packets:
    if p.haslayer(http.HTTPRequest):
      layer = p.getlayer(http.HTTPRequest)
      request = '{} http://{}{}'.format(layer.Method, layer.Host, layer.Path)

      # -----------------------------------------------------------
      # Append the request if we haven't seen it yet
      # -----------------------------------------------------------
      if request not in http_requests:
        http_requests.append(request)

  return http_requests


# -----------------------------------------------------------
# MAC addresses seen, and count
# -----------------------------------------------------------
def get_mac(packets, pi=WLAN_MAC):
  mac_addresses = {}
  mac = ''

  # -----------------------------------------------------------
  # Iterate over packets and extract MAC addresses that are not
  # our sensor device
  # -----------------------------------------------------------
  for p in packets:
    if p.haslayer(Ether):
      mac = p[Ether].src
      if p[Ether].dst != pi:
        mac = p[Ether].dst
      
    # -----------------------------------------------------------
    # Update the amount of times the MAC address was seen
    # -----------------------------------------------------------
    if not mac_addresses.has_key(mac):
      mac_addresses[mac] = 1

    else:
      mac_addresses[mac] += 1

  # -----------------------------------------------------------
  # MAC with the highest count should be the MAC of the target;
  # but return all MACs in case multiple devices needed, e.g.
  # phone controls the thermostat
  # -----------------------------------------------------------
  return sorted(mac_addresses.items(), key=(lambda key: key[1]), reverse=True)


# -----------------------------------------------------------
# IP addresses, ports, and protocols seen
# -----------------------------------------------------------
def get_traffic(packets, lab_network=LAB_NETWORK):
  transmissions = []
  ip = ''
  port = ''
  protocol = ''

  # -----------------------------------------------------------
  # Collect external IP addresses
  # -----------------------------------------------------------
  for p in packets:
    if p.haslayer(IP):

      # -----------------------------------------------------------
      # Quick check for intranet transmissions we can discard
      # -----------------------------------------------------------
      if lab_network in p[IP].dst and lab_network in p[IP].src:
        continue

      # -----------------------------------------------------------
      # Get the protocol
      # -----------------------------------------------------------
      protocol = 'udp'
      if p.haslayer(TCP): 
        protocol = 'tcp'

      # -----------------------------------------------------------
      # Get the IP address and port
      # -----------------------------------------------------------
      ip = p[IP].src
      port = p[IP].sport
      if lab_network not in p[IP].dst:
        ip = p[IP].dst
        port = p[IP].dport

      # -----------------------------------------------------------
      # Construct the transmission and add it to dictionary
      # -----------------------------------------------------------
      transmission = [ip, port, protocol]
      if transmission not in transmissions:
        transmissions.append(transmission)

  return transmissions


# -----------------------------------------------------------
# Create basic iptables rules for filtering
# -----------------------------------------------------------
def iptables_rules(device, mac_address, transmissions):

  # -----------------------------------------------------------
  # Format the device name for a chain
  # -----------------------------------------------------------
  non_alphanumeric = ''.join(c for c in map(chr, range(256)) if not c.isalnum())
  chain_name = device.translate(None, non_alphanumeric).upper()
  print 'iptables -N {}'.format(chain_name)

  # -----------------------------------------------------------
  # Process the transmissions from the pcap for filter rules
  # -----------------------------------------------------------
  print 'iptables -I FORWARD -m mac --mac-source {} -j {}'.format(mac_address, chain_name)
  for transmission in transmissions:    
    print 'iptables -A {} -p {} -d {} --dport {} -j ACCEPT'.format(chain_name, transmission[2], transmission[0], transmission[1])

  # -----------------------------------------------------------
  # Log and reject anything else
  # -----------------------------------------------------------
  print 'iptables -A {} -m limit --limit 2/day -j LOG --log-prefix {}'.format(chain_name, chain_name)
  print 'iptables -A {} -j REJECT'.format(chain_name)


# -----------------------------------------------------------
# Display usage
# -----------------------------------------------------------
def usage():
  print '[*] Usage: {} <device name> <pcap file>'.format(sys.argv[0])
  print '[*] Example: {} Sonos /tmp/sonos.pcap'.format(sys.argv[0])


# -----------------------------------------------------------
# Make it do the thing
# -----------------------------------------------------------
if __name__ == '__main__':
  print '[*] IoTables -- IoT pcap analyzer'
  try:

    # -----------------------------------------------------------
    # Process the pcap with scapy
    # -----------------------------------------------------------
    device = sys.argv[1]
    packets = rdpcap(sys.argv[2])
    print '[*] Analyzing {} from {}'.format(sys.argv[2], sys.argv[1])

    # -----------------------------------------------------------
    # Display the MAC addresses
    # -----------------------------------------------------------
    mac_addresses = get_mac(packets)
    print ''
    print '[+] MAC addresses observed: {}'.format(len(mac_addresses))
    for mac in mac_addresses:
      print '{}: {}'.format(' '*4 + mac[0], mac[1])

    # -----------------------------------------------------------
    # Display the DNS queries
    # -----------------------------------------------------------
    domain_number = 1
    dns = get_dns(packets)
    print ''
    print '[+] Domains queried: {}'.format(len(dns))
    for domain in dns:
      print '{}. {}'.format(str(domain_number).rjust(5), domain)
      domain_number += 1


    # -----------------------------------------------------------
    # Display the HTTP requests
    # -----------------------------------------------------------
    http_number = 1
    http_requests = get_http(packets)
    print ''
    print '[+] URLs requested: {}'.format(len(http_requests))
    for request in http_requests:
      print '{}. {}'.format(str(http_number).rjust(5), request)
      http_number += 1


    # -----------------------------------------------------------
    # Display the transmissions
    # -----------------------------------------------------------
    transmission_number = 1
    transmissions = get_traffic(packets)
    print ''
    print '[+] Transmissions observed: {}'.format(len(transmissions))
    for transmission in transmissions:
      print '{}. {} on {}/{}'.format(str(transmission_number).rjust(5), transmission[0], transmission[1], transmission[2])
      transmission_number += 1
    
    # -----------------------------------------------------------
    # Generate iptables rules
    # -----------------------------------------------------------
    print ''
    print '[+] Generating iptables rules.'
    iptables_rules(device, mac_addresses[0][0], transmissions)

  except:
    print '[-] FATAL: Something went wrong and I did no error handling.'
    usage()
    sys.exit(1)
