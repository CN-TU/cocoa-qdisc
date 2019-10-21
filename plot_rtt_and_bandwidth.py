#!/usr/bin/env python3

import matplotlib.pyplot as plt
import sys
import os
import subprocess
import statistics
import pandas as pd
plt.rcParams["font.family"] = "serif"
plt.rcParams['pdf.fonttype'] = 42

interval = 1
pcap_file = sys.argv[1]
assert pcap_file.startswith("sender_"), pcap_file

receiver_pcap = 'receiver_'+('_'.join(pcap_file.split('_')[1:]))

# rtt_command = f"tshark -r pcaps/{pcap_file} -Tfields -e frame.time_relative -e tcp.analysis.ack_rtt"
new_rtt_command = f"../pantheon/tools/wintracker pcaps/{pcap_file}"

retransmissions_command = f"tshark -Y tcp.srcport==60000&&tcp.analysis.retransmission -r pcaps/{pcap_file} -Tfields -e frame.time_relative"

packets_command = f"tshark -Y tcp.srcport==60000 -r pcaps/{receiver_pcap} -q -z io,stat,{interval},tcp.srcport==60000"

bytes_command = f"tshark -r pcaps/{receiver_pcap} -q -z io,stat,{interval},SUM(ip.len)ip.len&&tcp.srcport==60000"

bytes_command_total = f"tshark -r pcaps/{receiver_pcap} -q -z io,stat,0,SUM(ip.len)ip.len&&tcp.srcport==60000"

# rtt_out = subprocess.run(rtt_command.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
rtt_out = subprocess.run(new_rtt_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)

df = pd.read_csv(f"pcaps/{'.'.join(pcap_file.split('.')[:-1])}_full_1.csv")

ack_timestamps = df['ackTimestamp'].tolist()
rtts = [item*1000 for item in df['rtt'].tolist()]



# rtt_out = [item.split("\t") for item in rtt_out.stdout.decode("utf-8").split("\n") if item!=""]
# # print("rtt_out", rtt_out)
# rtt_results = [(float(item[0]), 1000*float(item[1])) for item in rtt_out if item[1] != ""]
# print("average rtt", statistics.mean(list(zip(*rtt_results))[1]))
print("average rtt", statistics.mean(rtts))
# print("rtt_results", rtt_results[:100])

retransmissions_out = subprocess.run(retransmissions_command.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
retransmissions_out = [item for item in retransmissions_out.stdout.decode("utf-8").split("\n") if item!=""]
retransmissions_results = [float(item) for item in retransmissions_out]
print("total retransmissions", len(retransmissions_results))

bytes_total_out = subprocess.run(bytes_command_total.split(), check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
bytes_total_out = bytes_total_out.stdout.decode("utf-8")
print("bytes_total_out", bytes_total_out)

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

with_correct_time = [((item[0] + item[1])/2, item[2]/1000000*8) for item in bytes_results]
os.makedirs("plots", exist_ok=True)

plt.figure(figsize=(5,2))
plt.xlabel("Time [s]")
plt.ylabel(f"Throughput [Mbit/s]")
plt.plot(*zip(*with_correct_time))

plt.tight_layout()

plt.savefig(f"plots/throughput_{interval}_{('_'.join(pcap_file.split('_')[1:]))}.pdf", bbox_inches = 'tight', pad_inches = 0)

plt.close()



plt.figure(figsize=(5,2))
plt.xlabel("Time [s]")
plt.ylabel(f"RTT [ms]")
# plt.plot(*zip(*rtt_results))
plt.plot(ack_timestamps, rtts)
# print("rtt_results", *zip(*rtt_results))
# plt.scatter(retransmissions_results, [0]*len(retransmissions_results), marker=".", linestyle="None", color="r", s=2, edgecolors="none")

plt.tight_layout()

plt.savefig(f"plots/rtt_{interval}_{('_'.join(pcap_file.split('_')[1:]))}.pdf", bbox_inches = 'tight', pad_inches = 0)
# plt.show()

plt.close()