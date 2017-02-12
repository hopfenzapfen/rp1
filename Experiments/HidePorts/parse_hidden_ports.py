# -*- coding: utf-8 -*-
"""
Project title: Repurposing defensive technologies for offensive Red Team operations
Authors:       Kristiyan Mladenov, Arne Zismer
Date:          February 12, 2017

Description:
               This script processes the pcap files captured by the
               perform_os_scans.py script.
               For each pcap file it checks whether one of the target ports was
               found to be open. After processing all pcap files, the script visualises
               the ratio of times the port was opened or closed in  a pie chart.
"""

pcap_dir = "pcaps_80_open"
target_ports = [80]
label_font_size = 15

from dpkt import pcap, ethernet, tcp
from os import listdir
from os.path import isfile, join
import matplotlib.pyplot as plt

def get_pcap_files():
    """
    Returns a list of all files inside the pcap_dir
    """
    return [join(pcap_dir, f) for f in listdir(pcap_dir) if isfile(join(pcap_dir, f))]


def print_results(ports):
    print "Port %d was opened %d/%d times" % (target_ports[0], ports[1], ports[0])


def plot_results(ports):
    """
    Draw a pie chart
    """

    # The slices will be ordered and plotted counter-clockwise.
    open_frac = ports[1] / float(ports[0])
    closed_frac = (ports[0] - ports[1]) / float(ports[0])

    labels = 'open', 'closed'
    fracs = [open_frac, closed_frac]
    explode=(0.05, 0.05)

    plt.pie(fracs, explode=explode, labels=labels, colors=['green', 'red'],
                    autopct='%1.1f%%', shadow=True, startangle=170)
    plt.title('Reachability of port %d' % (target_ports[0]))
    plt.show()


def parse_pcaps():
    """
    Iterate over all pcap files and check whether target ports were opened or closed
    Returns a tuple of (<total_scans>, <open_ports_count>)
    """

    # get pcap files from directory
    pcap_file_names = get_pcap_files()
    total_scans = 0
    open_target_ports = 0

    # iterate over pcap file
    for pcap_file_name in pcap_file_names:
        f = open(pcap_file_name)
        pcap_file = pcap.Reader(f)
        total_scans += 1

        # iterate over all packets inside pcap
        for ts, buf in pcap_file:
            eth = ethernet.Ethernet(buf)
            ip = eth.data

            # only process TCP packets
            try:
                if (type(ip.data) is tcp.TCP and ip.data.sport in target_ports):

                    # SYN,ACK flag indicates that port is open
                    if (ip.data.flags == 18):
                        open_target_ports += 1
                        print ("Found open port %d with flag %d" % (ip.data.sport, ip.data.flags))
                    break
            except:
                pass
        f.close()

    return (total_scans, open_target_ports)


if __name__ == "__main__":
    open_ports = parse_pcaps()
    print_results(open_ports)
    plot_results(open_ports)

    print "\ndone"