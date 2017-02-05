# -*- coding: utf-8 -*-
"""
Created on Wed Feb  1 09:53:32 2017
"""

from itertools import permutations
from os.path import join, exists, isdir
from os import mkdir

ports = [199, 3306, 554, 143, 22, 3389, 8888, 113, 1720, 135, 1723, 8080, 53, 111, 445, 1025, 5900, 21, 587, 995, 256, 25, 139, 993, 23, 110]
file_name = "knockd.conf"
dir_name = "knockd_configs"

seq_timeout = 1
start_command = "iptables -A INPUT -s %IP% -p tcp -m multiport --tcp-flags ALL SYN --dports 80,443 -j REJECT --reject-with tcp-reset"
tcpflags = "syn"
cmd_timeout = 2
stop_command = "iptables -D INPUT -s %IP% -p tcp -m multiport --tcp-flags ALL SYN --dports 80,443 -j REJECT --reject-with tcp-reset"


def generateSingleKnockdConf(ports):
    knockdConf = open(file_name, "w")
    port_pairs = list(permutations(ports, 2))


    knockdConf.write("[options]\n")
    knockdConf.write("\tlogfile = /var/log/knockd.log\n")
    knockdConf.write("\n")

    # write  rule for each pair
    for port_pair in port_pairs:

        knockdConf.write("[%s]\n" % ("TRIGGER" + str(port_pair)))
        knockdConf.write("\tsequence =\t%d,%d\n" % (port_pair[0], port_pair[1]))
        knockdConf.write("\tseq_timeout =\t%d\n" % seq_timeout)
        knockdConf.write("\tcommand =\t%s\n" % start_command)
        knockdConf.write("\ttcpflags =\t%s\n" % tcpflags)
        knockdConf.write("\tcmd_timeout =\t%d\n" % cmd_timeout)
        knockdConf.write("\tstop_command =\t%s\n" % stop_command)
        knockdConf.write("\n")
    knockdConf.close()
    print ("Wrote %d rules to %s" % (len(port_pairs), file_name))


def generateMultipleKnockdConfs(ports):

    # make sure data directory exists
    if not exists(dir_name) or not isdir(dir_name):
        mkdir(dir_name)

    for port1 in ports:
        conf_file = open(join(dir_name, str(port1) + file_name), "w")
        conf_file.write("[options]\n")
        conf_file.write("\tlogfile = /var/log/knockd.log\n")
        conf_file.write("\n")

        for port2 in ports:
            if port1 != port2:
                conf_file.write("[%s_%d,%d]\n" % ("TRIGGER", port2, port1 ))
                conf_file.write("\tsequence =\t%d,%d\n" % (port2, port1))
                conf_file.write("\tseq_timeout =\t%d\n" % seq_timeout)
                conf_file.write("\tcommand =\t%s\n" % start_command)
                conf_file.write("\ttcpflags =\t%s\n" % tcpflags)
                conf_file.write("\tcmd_timeout =\t%d\n" % cmd_timeout)
                conf_file.write("\tstop_command =\t%s\n" % stop_command)
                conf_file.write("\n")
        conf_file.close()


if __name__ == "__main__":

    # this approach didn't work
#    generateSingleKnockdConf(ports)

    # so we generate multiple config files
    generateMultipleKnockdConfs(ports)
