# -*- coding: utf-8 -*-
"""
Project title: Repurposing defensive technologies for offensive Red Team operations
Authors:       Kristiyan Mladenov, Arne Zismer
Date:          February 12, 2017

Description:
               This script processes the pcap files captured by the
               perform_os_scans.py script.
               For each pcap file it keeps track of which ports the Nmap scan
               contacted before reaching the target port.
               The results are presented in a bar chart.
"""

pcap_name = "test.pcap"
pcap_dir = "pcaps"
target_port = 80
label_font_size = 15

from dpkt import pcap, ethernet, tcp
from os import listdir
from os.path import isfile, join
from numpy import arange
import matplotlib.pyplot as plt

def get_pcap_files():
    """
    Returns a list of all files inside the pcap_dir
    """
    return [join(pcap_dir, f) for f in listdir(pcap_dir) if isfile(join(pcap_dir, f))]


def print_results(ports):
    """
    Prints the results in a simple table
    """


    print "port\tcount"
    print "----------------------"
    for port in ports:
        print ("%d\t%d" % (port[0], port[1]))

    print "----------------------"
    print ("%d ports scanned" % len(ports))


def plot_results(ports):
    """
    Draws the bar chart
    """

    # convert tuple list to two separate lists: the ports and its frequencies
    port_numbers, port_frequencies = [list(t) for t in zip(*ports)]
    y_pos = arange(len(port_numbers))

    plt.bar(y_pos, port_frequencies, width=0.8, alpha=0.8, align="center")
    plt.xticks(y_pos, port_numbers, rotation=45)
    plt.ylabel("Port hits", fontsize=label_font_size)
    plt.xlabel("Port number", fontsize=label_font_size)
    plt.xlim([-1, 27])
    plt.ylim([0, 550])
    plt.title("Number of times a port was scanned before port %d was reached" % target_port, fontsize=20)
    plt.show()


def parse_pcaps():
    """
    Iterates over all pcap files, registers all ports that are contacted before
    target port is reached, per file.
    """

    # get pcap files from directory
    ports = {}
    pcap_file_names = get_pcap_files()
    for pcap_file_name in pcap_file_names:
#        print("reading %s" % pcap_file_name)
        f = open(pcap_file_name)
        pcap_file = pcap.Reader(f)

        # iterate over all packets inside pcap
        for ts, buf in pcap_file:
            eth = ethernet.Ethernet(buf)
            ip = eth.data

            # only process TCP packets
            if (type(ip.data) is tcp.TCP and ip.data.flags == 2):
                tcp_packet = ip.data
                port = tcp_packet.dport

                # stop iteration if target port is found
                if (port in [80]):
                    break

                # otherwise, increment counter
                else:
                    if port in ports:
                        ports[port] += 1
                    else:
                        ports[port] = 1
        f.close()

    # convert dict to list of tuples so it can be sorted
    ports_list = []
    for port in ports:
        port_tuple = (port, ports[port])
        ports_list.append(port_tuple)

    # sort list
    return sorted(ports_list, key=lambda x: x[1], reverse=True)


if __name__ == "__main__":
    scanned_ports = parse_pcaps()
    print_results(scanned_ports)
    plot_results(scanned_ports)

    print "\ndone"