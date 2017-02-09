# -*- coding: utf-8 -*-
"""
Created on Mon Jan 30 15:12:14 2017

@author: hopfenzapfen
"""

#pcap_name = "test.pcap"
pcap_dir = "pcaps_80_open"
target_ports = [80]
label_font_size = 15

from dpkt import pcap, ethernet, tcp
from os import listdir
from os.path import isfile, join
import matplotlib.pyplot as plt

def get_pcap_files():
    """
    returns a list of all files inside the pcap_dir
    """
    return [join(pcap_dir, f) for f in listdir(pcap_dir) if isfile(join(pcap_dir, f))]


def print_results(ports):
    print "Port %d was opened %d/%d times" % (target_ports[0], ports[1], ports[0])


def plot_results(ports):

    # make a square figure and axes
#    figure(1, figsize=(6,6))
#    ax =plt.axes([0.1, 0.1, 0.8, 0.8])

    # The slices will be ordered and plotted counter-clockwise.
    open_frac = ports[1] / float(ports[0])
    closed_frac = (ports[0] - ports[1]) / float(ports[0])

    labels = 'open', 'closed'
    fracs = [open_frac, closed_frac]
    explode=(0.05, 0.05)

    plt.pie(fracs, explode=explode, labels=labels, colors=['green', 'red'],
                    autopct='%1.1f%%', shadow=True, startangle=170)
                    # The default startangle is 0, which would start
                    # the Frogs slice on the x-axis.  With startangle=90,
                    # everything is rotated counter-clockwise by 90 degrees,
                    # so the plotting starts on the positive y-axis.

    plt.title('Reachability of port %d' % (target_ports[0]))

    plt.show()


def parse_pcaps():

    # get pcap files from directory
    pcap_file_names = get_pcap_files()
    total_scans = 0
    open_target_ports = 0

    # iterate over pcap file
    for pcap_file_name in pcap_file_names:
#        print("reading %s" % pcap_file_name)
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

                    if (ip.data.flags == 18):
                        open_target_ports += 1
                        print ("Found open port %d with flag %d" % (ip.data.sport, ip.data.flags))
                    break
            except:
                pass
        f.close()

#    return (1000, 205)
    return (total_scans, open_target_ports)


if __name__ == "__main__":
    open_ports = parse_pcaps()
    print_results(open_ports)
    plot_results(open_ports)

#    test()

    print "\n\ndone"