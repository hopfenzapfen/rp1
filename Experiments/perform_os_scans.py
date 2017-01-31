# -*- coding: utf-8 -*-
"""
Created on Mon Jan 30 16:51:33 2017

@author: hopfenzapfen
"""

from sys import argv
from time import sleep
from subprocess import call, Popen
from shutil import rmtree
from os.path import join, exists, isdir
from os import mkdir, listdir, remove, devnull



scan_count = 1000
target_address = "127.0.0.1"
pcap_dir = "pcaps"
pcap_file_name = "nmap_os-detection.pcap"


def cleanDataDir(dataDir):
    """
    Removes the given directory and all its subfolders and contained files
    """

    # make sure data directory exists
    if not exists(dataDir) or not isdir(dataDir):
        mkdir(dataDir)

    # wipe content if it already exists
    else:
        for f in [join(dataDir, f) for f in listdir(dataDir)]:
            if (isdir(f)):
                rmtree(f)
            else:
                remove(f)

def perform_nmap_scans():

    for i in range(0, scan_count):

        # start nmap scan
        tcpdump = Popen(["tcpdump", "-i", "lo", "-w", join(pcap_dir, str(i) + pcap_file_name)])
        result = call(["nmap", "-sV", "-O", target_address], stdout=open(devnull, "w"))
        tcpdump.terminate()
        print tcpdump
        print result



if __name__ == "__main__":

    # TODO: get number of iterations from command line
    cleanDataDir(pcap_dir)
    perform_nmap_scans()

