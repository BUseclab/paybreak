#!/usr/bin/env bash
# Set up the iptables, and ipv4 forwarding for Cuckoo Sandbox
sudo iptables -A FORWARD -o eth0 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT;
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT;
sudo iptables -A POSTROUTING -t nat -j MASQUERADE;
sudo sysctl -w net.ipv4.ip_forward=1;

