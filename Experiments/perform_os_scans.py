# -*- coding: utf-8 -*-
"""
Project title: Repurposing defensive technologies for offensive Red Team operations
Authors:       Kristiyan Mladenov, Arne Zismer
Date:          February 12, 2017

Description:
               This script runs the specified number of Nmap service and OS-detection scans
               against a target, captures the entire communication with tcpdump and
               stores the captured data in pcap files for further inspection.
"""

from time import sleep
from subprocess import call, Popen
from shutil import rmtree
from os.path import join, exists, isdir
from os import mkdir, listdir, remove, devnull

scan_count = 1000
target_address = "10.0.0.220"
interface = "ens160"
pcap_dir = "pcaps"
pcap_file_name = "nmap_service-scan.pcap"


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
    """
    Run the actual Nmap scans and tcpdumps
    """

    for i in range(0, scan_count):

        # start nmap scan
        tcpdump = Popen(["tcpdump", "-i", interface, "-w", join(pcap_dir, str(i) + pcap_file_name)])
        result = call(["nmap", "-sV", "-O", target_address], stdout=open(devnull, "w"))
        tcpdump.terminate()

        # sleep a bit to make sure the iptable rules added by knockd are removed
        # before running the next scan
        sleep(2)


if __name__ == "__main__":

    cleanDataDir(pcap_dir)
    perform_nmap_scans()
