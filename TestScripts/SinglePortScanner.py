import socket
import argparse
import ipaddress
import ssl
import re

def printServiceOnPort(portNumber, protocol):

    serviceName = socket.getservbyport(portNumber, protocol)

    print("Name of the service running at port number %d : %s"%(portNumber, serviceName))
    