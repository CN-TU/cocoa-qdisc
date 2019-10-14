#!/usr/bin/env python3

import matplotlib.pyplot as plt
import sys
import os
import subprocess
plt.rcParams["font.family"] = "serif"

interval = 1
pcap_file = sys.argv[1]
assert pcap_file.startswith("sender_")

rtt_command = f"tshark -Y tcp.srcport!=60000&&tcp.analysis.ack_rtt!=0 -r pcaps/{pcap_file} -Tfields -e frame.time_relative -e tcp.analysis.ack_rtt"

receiver_pcap = 'receiver_'+('_'.join(pcap_file.split('_')[1:]))

packets_command = f"tshark -Y tcp.srcport==60000 -r pcaps/{receiver_pcap} -q -z io,stat,{interval},tcp.srcport==60000"

bytes_command = f"tshark -r pcaps/{receiver_pcap} -q -z io,stat,{interval},SUM(ip.len)ip.len&&tcp.srcport==60000"

rtt_out = subprocess.run(rtt_command.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
rtt_out = [item.split("\t") for item in rtt_out.stdout.decode("utf-8").split("\n") if item!=""]
rtt_results = [(float(item[0]), 1000*float(item[1])) for item in rtt_out]
# print("rtt_results", rtt_results[:100])

# packets_out = subprocess.run(packets_command.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
# packets_out = [item for item in packets_out.stdout.decode("utf-8").split("\n")[12:-3] if item!=""]
# packets_out = [[subitem for subitem in item.split("|") if subitem!=''] for item in packets_out]
# packets_out = [[item[0].split("<>"), *item[1:]] for item in packets_out]
# packets_results = [(float(item[0][0]), float(item[0][1]), float(item[1])) for item in packets_out]
# # print("packets_results", packets_results)

bytes_out = subprocess.run(bytes_command.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
bytes_out = [item for item in bytes_out.stdout.decode("utf-8").split("\n")[12:-3] if item!=""]
bytes_out = [[subitem for subitem in item.split("|") if subitem!=''] for item in bytes_out]
bytes_out = [[item[0].split("<>"), *item[1:]] for item in bytes_out]
bytes_results = [(float(item[0][0]), float(item[0][1]), float(item[1])) for item in bytes_out]
# print("bytes_results", bytes_results)

# assert len(packets_results) == len(bytes_results)

# divided = [(first[0], first[1], first[2]/second[2]) for first, second in zip(bytes_results, packets_results)]
# print("divided", divided)

with_correct_time = [((item[0] + item[1])/2, item[2]) for item in bytes_results]
os.makedirs("plots", exist_ok=True)

plt.figure(figsize=(5,2))
plt.xlabel("Time [s]")
plt.ylabel(f"Throughput ({interval}s window)")
plt.plot(*zip(*with_correct_time))

plt.tight_layout()

plt.savefig(f"plots/throughput_{interval}_{('_'.join(pcap_file.split('_')[1:]))}.pdf", bbox_inches = 'tight', pad_inches = 0)

plt.close()



plt.figure(figsize=(5,2))
plt.xlabel("Time [s]")
plt.ylabel(f"RTT [ms]")
plt.plot(*zip(*rtt_results))

plt.tight_layout()

plt.savefig(f"plots/rtt_{interval}_{('_'.join(pcap_file.split('_')[1:]))}.pdf", bbox_inches = 'tight', pad_inches = 0)

plt.close()