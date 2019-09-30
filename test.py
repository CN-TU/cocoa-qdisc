"""Example file for testing

This creates a small testnet with ipaddresses from 192.168.0.0/24,
one switch, and three hosts.
"""

import sys, os
import io
import time
import math
import signal
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

import subprocess
# import matplotlib
# matplotlib.use("Agg")
# import matplotlib.pyplot as plt
import virtnet
import statistics

# import numpy as np
# from scipy.stats import norm


# DELAY = 10000
# SIGMA = 2000
# SAMPLES = 1000
# X = 10
# NUMPING = 1000

# Client port
bytes_to_capture = 100
cport = 60000
# milliseconds
delay_to_add = 10
# Mbit/s
rate = 100
# Bytes, obviously
MTU = 1514
TIME = 60
QDISC_NAME = "cn"
CC="reno"
#             Mbit/s       ms                bytes
BDP_packets = rate*1000000*delay_to_add/1000/(MTU*8)
print("BDP_packets", BDP_packets)
# Just for fun...
BDP_packets *= 0.2
# BDP_packets = 1
print("actual packets", BDP_packets)
# quit()

def run_commands(cmds, Popen=False):
	if type(cmds) is not list:
		cmds = [cmds]
	return_stuff = []
	for cmd in cmds:
		if type(cmd) is tuple:
			cmd, kwargs = cmd
		else:
			kwargs = {}
		try:
			print("cmd", cmd)#, "kwargs", kwargs)
			if not Popen:
				output = subprocess.run(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True, **kwargs)
				# print("output", output)
				return_stuff.append(output)
			else:
				popen = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
				return_stuff.append(popen)
		except subprocess.CalledProcessError as e:
			print(e.cmd, e.returncode, e.output)
			raise e
	return return_stuff


env_with_tc = os.environ.copy()
# Idiotic
# env_with_tc["TC_LIB_DIR"] = os.path.expanduser('~/repos/iproute2/tc')
env_with_tc["TC_LIB_DIR"] = "/home/max/repos/iproute2/tc"

# print("os.environ", os.environ)

def execute_popen_and_show_result(command, host=None):
	parent = host if host is not None else subprocess
	print(f"Executing{f' on host {host.name}' if host else ''}", command)
	with parent.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as cmd:
		out, err = cmd.stdout.read(), cmd.stderr.read()
		if out:
			print("out", out.decode("utf-8"))
		if err:
			print("err", err.decode("utf-8"))

def run(vnet):
		"Main functionality"

		# print("Calculating pdf...")

		# x = np.linspace(-X, X, SAMPLES)
		# y = norm.pdf(x, loc=-5)+norm.pdf(x, loc=5, scale=3)
		# area = np.trapz(y)*(2*X)/SAMPLES

		print("Building network...")
		network = vnet.Network("192.168.0.0/24")
		switch = vnet.Switch("sw")
		hosts = []
		for i in range(2):
			host = vnet.Host("host{}".format(i))
			host.connect(vnet.VirtualLink, switch, "eth0")
			# print("switch.interfaces", switch.interfaces)
			host["eth0"].add_ip(network)
			execute_popen_and_show_result("ethtool -K eth0 gro off", host)
			execute_popen_and_show_result("ethtool -K eth0 gso off", host)
			execute_popen_and_show_result("ethtool -K eth0 tso off", host)
			hosts.append(host)
			# print("host", host)
		# hosts[0]["eth0"].tc('add', 'netem', delay=DELAY, jitter=SIGMA, dist=y)

		# import pdb; pdb.set_trace()

		# print("switch.interfaces", switch.interfaces)
		for interface in switch.interfaces:
			print("interface", interface)
			# continue
			execute_popen_and_show_result(f"ethtool -K {interface} gro off")
			execute_popen_and_show_result(f"ethtool -K {interface} gso off")
			execute_popen_and_show_result(f"ethtool -K {interface} tso off")

			run_commands([f"tc qdisc add dev {interface} root handle 1: netem delay {delay_to_add/2}ms", f"tc qdisc add dev {interface} parent 1: handle 2: htb default 21", f"tc class add dev {interface} parent 2: classid 2:21 htb rate {rate}mbit", (f"tc qdisc add dev {interface} parent 2:21 handle 3: {QDISC_NAME if interface=='host10' else 'fq'} nopacing quantum 3028 initial_quantum 3028{f' flow_limit {int(math.ceil(BDP_packets))}' if interface=='host10' else ''}", {"env": env_with_tc})])
			# run_commands(["tc qdisc add dev {} root handle 1: netem delay {}ms".format(interface, delay_to_add/2), "tc qdisc add dev {} parent 1: handle 2: htb default 21".format(interface), "tc class add dev {} parent 2: classid 2:21 htb rate {}mbit ceil {}mbit".format(interface, rate, rate), ("tc qdisc add dev {} parent 2:21 handle 3: {}".format(interface, QDISC_NAME), {"env": env_with_tc})])
		#     # output = subprocess.run(f"tc qdisc replace dev {interface} root {QDISC_NAME}".split(" "), capture_output=True, env=env_with_tc)
		#     print("output", output)
		# quit()
		vnet.update_hosts()

		with hosts[0].Popen("ping -c 100 -i 0 host1".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as ping:
			ping_output = ping.stdout.read().decode("utf-8").split("\n")
			ping_output = [float(item.split()[-2][5:]) for item in ping_output if "time=" in item]
			print("mean rtt", statistics.mean(ping_output))

		server_popen = hosts[1].Popen("iperf3 -V -4 -s".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		tcpdump_sender_popen = hosts[0].Popen(f"/usr/sbin/tcpdump -s {bytes_to_capture} -i eth0 -w sender.pcap tcp port {cport} && port 5201".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		tcpdump_receiver_popen = hosts[1].Popen(f"/usr/sbin/tcpdump -s {bytes_to_capture} -i eth0 -w receiver.pcap tcp port {cport} && port 5201".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		# tcpdump_switch_popens = []
		# for interface_name in switch.interfaces.keys():
		# 	tcpdump_switch_popens.append(subprocess.Popen(f"/usr/sbin/tcpdump -s 96 -i {interface_name} -w switch_{interface_name}.pcap tcp port {cport} && port 5201".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE))

		# client_popen = hosts[0].Popen(f"iperf3 -w 10M -V -4 -t {TIME} -C {CC} --cport {cport} -c host1".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		client_popen = hosts[0].Popen(f"iperf3 -w 50M -V -4 -t {TIME} -C {CC} --cport {cport} -c host1".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		print("client pid", client_popen.pid)
		# time.sleep(0.1)

		# trace_popen = hosts[0].Popen(f"trace-cmd record -e tcp:tcp_probe -P {client_popen.pid}".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		# trace_popen = hosts[0].Popen(f"trace-cmd record -e tcp:tcp_probe".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		out, err = client_popen.communicate()
		if out:
			print("client out", out.decode("utf-8"))
		if err:
			print("client err", err.decode("utf-8"))

		server_popen.terminate()
		out, err = server_popen.stdout.read(), server_popen.stderr.read()
		if out:
			print("server out", out.decode("utf-8"))
		if err:
			print("server err", err.decode("utf-8"))

		# trace_popen.send_signal(signal.SIGINT)
		# out, err = trace_popen.stdout.read(), trace_popen.stderr.read()
		# if out:
		# 	print("trace out", out.decode("utf-8"))
		# if err:
		# 	print("trace err", err.decode("utf-8"))

		tcpdump_sender_popen.terminate()
		out, err = tcpdump_sender_popen.stdout.read(), tcpdump_sender_popen.stderr.read()
		if out:
			print("tcpdump out", out.decode("utf-8"))
		if err:
			print("tcpdump err", err.decode("utf-8"))

		tcpdump_receiver_popen.terminate()
		out, err = tcpdump_receiver_popen.stdout.read(), tcpdump_receiver_popen.stderr.read()
		if out:
			print("tcpdump out", out.decode("utf-8"))
		if err:
			print("tcpdump err", err.decode("utf-8"))

		# for index, interface_name in enumerate(switch.interfaces.keys()):
		# 	tcpdump_switch_popens[index].terminate()
		# 	out, err = tcpdump_switch_popens[index].stdout.read(), tcpdump_switch_popens[index].stderr.read()
		# 	if out:
		# 		print(f"{interface_name} out", out.decode("utf-8"))
		# 	if err:
		# 		print(f"{interface_name} err", err.decode("utf-8"))

		# if out:
		# 	print("server out", out)
		# if err:
		# 	print("server err", err)

		# output = subprocess.run("ip a".split(" "), capture_output=True, env=env_with_tc)
		# print("output", output)

		# print("Doing ping...")

		# with hosts[0].Popen(["ping", "-q", "-c", "1", "host1"], stdout=subprocess.DEVNULL):
		#     pass

		# res = []
		# pings = 0
		# print(' '*40+'|'+'\b'*41, end='', flush=True)
		# with hosts[0].Popen(["ping", "-c", str(NUMPING), "-i", "0", "host1"], stdout=subprocess.PIPE) as ping:
		#     for line in ping.stdout:
		#         line = line.rsplit(b'time=', 1)
		#         if len(line) != 2:
		#             continue
		#         pings += 1
		#         if not pings%(NUMPING/40):
		#             print('.', end='', flush=True)
		#         res.append(float(line[1][:-4]))
		# plt.plot(x/X*4*SIGMA/1000+DELAY/1000, y/area, label='pdf of setting')

		# print("Done")
		# print()

		# print("min={} max={}".format(min(res),max(res)))
		# print("mean={} std={}".format(np.mean(res), np.std(res, ddof=1)))
		# plt.hist(res, density=True, label='result histogram')
		# plt.ylabel('fraction of packets')
		# plt.xlabel('time [ms]')
		# plt.legend()
		# plt.savefig("netem_output.pdf")

with virtnet.Manager() as context:
		run(context)
