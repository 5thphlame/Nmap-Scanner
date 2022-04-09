#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner

print ("Welcome, This is a simple nmap automation tool")
print ("<---------------------------------------------------->")

ip_address = input("please enter ipaddress you want to scan: ")
print("The ip you entered is: ", ip_address)
type(ip_address)

 