#!/usr/bin/env python
# -----------------------------------------------------------
# Author: int0x80
# License: WTFPL (http://www.wtfpl.net/)
# Usage: iotables.py [OPTIONS] <PCAP FILE...>
#
# IoTables analyzes packets captured from a device and tries
# to generate relevant iptables rules. The goal is to assist
# in properly isolating IoT devices on a network.
#
# I currently use an ALFA with a Raspberry Pi to create a 
# wifi network. A target device is associated to the network,
# and all traffic is sniffed on the Pi. Whitelist the IPs and
# MACs of the lab network and NICs, respectively, via the
# LAB_NETWORKS and PI_MACS variables below.
# -----------------------------------------------------------

import optparse

from scapy.all import *
from scapy.layers import http
from sys import argv, exit


# -----------------------------------------------------------
# User configuration
# -----------------------------------------------------------
LAB_NETWORKS = ['10.99.1.', '192.168.1.']
PI_MACS = ['00:c0:ca:57:2d:99', 'b8:27:eb:cb:fc:1a', 'ff:ff:ff:ff:ff:ff']


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
def get_mac(packets, pi=PI_MACS):
  mac_addresses = {}
  mac = ''

  # -----------------------------------------------------------
  # Iterate over packets and extract MAC addresses that are not
  # our sensor device
  # -----------------------------------------------------------
  for p in packets:
    if p.haslayer(Ether):

      # -----------------------------------------------------------
      # Discard traffic going between the WLAN and LAN NICs
      # -----------------------------------------------------------
      if any(pi_mac in p[Ether].src for pi_mac in pi) and any(pi_mac in p[Ether].dst for pi_mac in pi):
        continue

      # -----------------------------------------------------------
      # Select the non-Pi MAC address
      # -----------------------------------------------------------
      mac = p[Ether].src
      if not any(pi_mac in p[Ether].dst for pi_mac in pi):
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
def get_traffic(packets, lab_network=LAB_NETWORKS):
  transmissions = []

  # -----------------------------------------------------------
  # Collect external IP addresses
  # -----------------------------------------------------------
  for p in packets:
    if p.haslayer(IP):

      # -----------------------------------------------------------
      # Quick check for intranet transmissions we can discard
      # -----------------------------------------------------------
      if any(lab_net in p[IP].src for lab_net in lab_network) and any(lab_net in p[IP].dst for lab_net in lab_network):
        continue

      # -----------------------------------------------------------
      # Get the protocol
      # -----------------------------------------------------------
      if p.haslayer(TCP): 
        protocol = 'tcp'
      elif p.haslayer(UDP):
        protocol = 'udp'
      elif p.haslayer(ICMP):
        protocol = 'icmp'
        port = ''
      else:
        continue

      # -----------------------------------------------------------
      # Get the IP address, and port if the protocol is not ICMP
      # -----------------------------------------------------------
      if protocol != 'icmp':
        port = p[protocol.upper()].sport

      ip = p[IP].src
      if not any(lab_net in p[IP].dst for lab_net in lab_network):
        if protocol != 'icmp':
          ip = p[IP].dst
          port = p[protocol.upper()].dport


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
def iptables_rules(prefix, device, mac_address, transmissions):

  # -----------------------------------------------------------
  # Format the device name for a chain
  # -----------------------------------------------------------
  non_alphanumeric = ''.join(c for c in map(chr, range(256)) if not c.isalnum())
  chain_name = device.translate(None, non_alphanumeric).upper()

  with open('{}-iptables.txt'.format(prefix), 'a') as iptables_file:
    iptables_file.write('iptables -N {}\n'.format(chain_name))

    # -----------------------------------------------------------
    # Process the transmissions from the pcap for filter rules
    # -----------------------------------------------------------
    iptables_file.write('iptables -I OUTPUT -m mac --mac-source {} -j {}\n'.format(mac_address, chain_name))
    for transmission in transmissions:
      if transmission[2] == 'icmp':
        iptables_file.write('iptables -A {} -p {} -d {} -j ACCEPT\n'.format(chain_name, transmission[2], transmission[0]))
      else:
        iptables_file.write('iptables -A {} -p {} -d {} --dport {} -j ACCEPT\n'.format(chain_name, transmission[2], transmission[0], transmission[1]))

    # -----------------------------------------------------------
    # Log and reject anything else
    # -----------------------------------------------------------
    iptables_file.write('iptables -A {} -m limit --limit 2/day -j LOG --log-prefix {}\n'.format(chain_name, chain_name))
    iptables_file.write('iptables -A {} -j REJECT\n'.format(chain_name))


# -----------------------------------------------------------
# Display usage
# -----------------------------------------------------------
def usage():
  print '[*] Usage: {} [OPTIONS] <PCAP FILE...>'.format(sys.argv[0])
  print '[*] OPTIONS'
  print '     -d <NAME>, --device <NAME>'
  print '           Name for the device from which the pcap originated; e.g. Nest, Sonos, etc'
  print ''
  print '     -o <PREFIX>, --output <PREFIX>'
  print '           Prefix for file names created with result output. Defaults to device name.'
  print ''
  print '[*] Example: {} -d Sonos -o sonos5 /tmp/sonos*.pcap'.format(sys.argv[0])


# -----------------------------------------------------------
# Make it do the thing
# -----------------------------------------------------------
def main():
  print '[*] IoTables -- IoT pcap analyzer'

  # -----------------------------------------------------------
  # Process the command line arguments
  # -----------------------------------------------------------
  parser = optparse.OptionParser()
  parser.add_option('-d', '--device',
                    dest='device',
                    default='device')

  parser.add_option('-o', '--output',
                    dest='prefix',
                    default='PERFECT5OUTOF7')

  options, pcaps = parser.parse_args()
  if options.prefix == 'PERFECT5OUTOF7':
    options.prefix = options.device

  # -----------------------------------------------------------
  # Unique transmissions, MACs by count, from all pcaps
  # -----------------------------------------------------------
  unique_transmissions = []
  mac_with_count = {}


  # -----------------------------------------------------------
  # The pcaps list should contain one or more filenames, 
  # potentially using file globbing
  # -----------------------------------------------------------
  for capture_file in pcaps:

    try:
      # -----------------------------------------------------------
      # Process the pcap with scapy
      # -----------------------------------------------------------
      packets = rdpcap(capture_file)
      print '[*] Analyzing {} from {}'.format(capture_file, options.device)

      # -----------------------------------------------------------
      # Display the MAC addresses
      # -----------------------------------------------------------
      mac_addresses = get_mac(packets)
      print ''
      print '[+] MAC addresses observed: {}'.format(len(mac_addresses))

      with open('{}-mac.txt'.format(options.prefix), 'a') as mac_file:  
        for mac in mac_addresses:
          mac_file.write('{}\n'.format(mac[0]))
          print '{}: {}'.format(' '*4 + mac[0], mac[1])

          # -----------------------------------------------------------
          # Save MAC address count to dictionary. This will be used at
          # the end after all pcaps have been processed to generate a
          # set of iptables rules
          # -----------------------------------------------------------
          if mac_with_count.has_key(mac[0]):
            mac_with_count[mac[0]] += mac[1]

          else:
            mac_with_count[mac[0]] = mac[1]


      # -----------------------------------------------------------
      # Display the DNS queries
      # -----------------------------------------------------------
      domain_count = 1
      dns = get_dns(packets)
      print ''
      print '[+] Domains queried: {}'.format(len(dns))

      with open('{}-dns.txt'.format(options.prefix), 'a') as dns_file:  
        for domain in dns:
          dns_file.write('{}\n'.format(domain))
          print '{}. {}'.format(str(domain_count).rjust(5), domain)
          domain_count += 1


      # -----------------------------------------------------------
      # Display the HTTP requests
      # -----------------------------------------------------------
      http_count = 1
      http_requests = get_http(packets)
      print ''
      print '[+] URLs requested: {}'.format(len(http_requests))

      with open('{}-http.txt'.format(options.prefix), 'a') as http_file:  
        for request in http_requests:
          http_file.write('{}\n'.format(request))
          print '{}. {}'.format(str(http_count).rjust(5), request)
          http_count += 1


      # -----------------------------------------------------------
      # Display the transmissions
      # -----------------------------------------------------------
      transmission_count = 1
      transmissions = get_traffic(packets)
      print ''
      print '[+] Transmissions observed: {}'.format(len(transmissions))

      with open('{}-transmissions.txt'.format(options.prefix), 'a') as transmission_file:  
        for transmission in transmissions:
          transmission_file.write('{} on {}/{}\n'.format(transmission[0], transmission[1], transmission[2]))
          print '{}. {} on {}/{}'.format(str(transmission_count).rjust(5), transmission[0], transmission[1], transmission[2])
          transmission_count += 1

          # -----------------------------------------------------------
          # Save unique transmissions to a list. These will be used at
          # the end after all pcaps have been processed to generate a
          # set of iptables rules
          # -----------------------------------------------------------
          if transmission not in unique_transmissions:
            unique_transmissions.append(transmission)

    # -----------------------------------------------------------
    # Something went wrong, my bad
    # -----------------------------------------------------------
    except Exception as ex:
      print '[-] EXCEPTION while processing {}: {}'.format(capture_file, ex.__class__)
      print '     Arguments: {}'.format(ex.args)
      pass
    
  # -----------------------------------------------------------
  # Generate iptables rules
  # -----------------------------------------------------------
  mac_with_count = sorted(mac_with_count.items(), key=(lambda key: key[1]), reverse=True)

  print ''
  print '[+] Generating iptables rules.'
  iptables_rules(options.prefix, options.device, mac_with_count[0][0], unique_transmissions)



# -----------------------------------------------------------
# Do the thing that makes it do the thing
# -----------------------------------------------------------
if __name__ == '__main__':
  main()
