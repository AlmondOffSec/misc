#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Client for secureChat.py

Note: expects an existing user, to be created manually
"""

from __future__ import print_function
import sys
import argparse
import base64
import socket

def hexdump(src, length=32):
    """Hexdump utility function
    Source: https://gist.github.com/sbz/1080258
    """
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

class ChatClient:
    def __init__(self, host, port, username, password, verbose=False):
        self.sock = self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.username = username
        self.password = password
        self.verbose = verbose
        self.PROMPT = "Enter your choice : \n"

    def send(self, line):
        sent = self.sock.sendall(line)
        if(self.verbose):
            print("SENT\t" + line, file=sys.stderr)
    
    def receive(self):
        r = self.sock.recv(4096)
        if r == '':
            print("INFO: server closed connection!", file=sys.stderr)
            sys.exit()
        elif(self.verbose):
            print("RECV\t" + r, file=sys.stderr)
        return r
    
    def expect(self, expected):
        r = self.receive()
        if r != expected:
            print("INFO: Expected:\n" + hexdump(expected), file=sys.stderr)
            print("INFO: Received:\n" + hexdump(r), file=sys.stderr)
            return False
        return True
    
    def get_flag(self):
        # recv banner
        r = self.receive()
        r = self.receive()
        # connect user
        self.send("2\n")
        self.expect("Enter your pseudo : ")
        self.send(self.username + "\n")
        self.expect("\n")
        self.expect("Enter your password : \n")
        self.send(self.password + "\n")
        if not self.expect("You're now connected as " + self.username):
            return False
        self.expect("\n\n" + self.PROMPT)
        # send xored flag to self (redo until the decoded version does not have a \n in it)
        xored_flag = '\n'
        while '\n' in xored_flag:
            self.send("6\n")
            self.expect("Enter pseudo of the receiver : ")
            self.send(self.username + "\n")
            self.expect("\n")
            if not self.expect("Flag successfully sent!\n\n" + self.PROMPT):
                return False
            # get xored flag from message
            self.send("4\n")
            if not self.expect("\nFrom : " + self.username):
                return False
            r = self.receive()
            xored_flag_b64 = r.split('\n')[1]
            print("XOR-ED FLAG:\t" + xored_flag_b64)
            xored_flag = base64.b64decode(xored_flag_b64)
            print(hexdump(xored_flag))
        # send xored flag to self with an invalid key (to "reuse" the last one thanks to numpy.empty)
        self.send("5\n")
        self.expect("Enter pseudo of the receiver : ")
        self.send(self.username + "\n")
        self.expect("\n")
        self.expect("Enter your message : \n")
        self.send(xored_flag + "\n")
        self.expect("Enter encryption key (Array of integer):")
        self.send("zzz\n")
        self.expect("\n")
        if not self.expect("Message successfully sent! \n\n\n" + self.PROMPT):
            return False
        # get xor-xored flag from message
        self.send("4\n")
        if not self.expect("\nFrom : " + self.username):
            return False
        r = self.receive()
        flag_b64 = r.split('\n')[1]
        print("FLAG:\t" + flag_b64)
        flag = base64.b64decode(flag_b64)
        print(flag)
        # send message to self (to replace the flag in case someone is using the same user)
        self.send("5\n")
        self.expect("Enter pseudo of the receiver : ")
        self.send(self.username + "\n")
        self.expect("\n")
        self.expect("Enter your message : \n")
        self.send("a\n")
        self.expect("Enter encryption key (Array of integer):")
        self.send("0\n")
        self.expect("\n")
        self.expect("Message successfully sent! \n\n\n" + self.PROMPT)
        return True

def main ():
    global options, args
    if args.verbose: print("Connecting to host" + args.host + " on port " + str(args.port), file=sys.stderr)
    ChatClient(args.host, args.port, args.username, args.password, args.verbose).get_flag()

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=globals()['__doc__'])
        parser.add_argument('-v', '--verbose', action='store_true', default=False, help='verbose output')
        parser.add_argument("-H", "--host", help="server hostname or ip address", default="ctf-ao2019.westeurope.cloudapp.azure.com")
        parser.add_argument("-P", "--port", help="port number", type=int, default=1331)
        parser.add_argument("-u", "--username", help="username", default="ccc")
        parser.add_argument("-p", "--password", help="password", default="ccc")
        args = parser.parse_args()
        main()
        sys.exit(0)
    except KeyboardInterrupt, e: # Ctrl-C
        print('User cancelled')
    except SystemExit, e: # sys.exit()
        raise e
    except Exception, e:
        print('ERROR, UNEXPECTED EXCEPTION')
        print(str(e))
        sys.exit(1)
