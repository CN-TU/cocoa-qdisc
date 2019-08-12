"""Example file for testing

This creates a small testnet with ipaddresses from 192.168.0.0/24,
one switch, and three hosts.
"""

import sys, os
import io
import time
import math
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

import subprocess
# import matplotlib
# matplotlib.use("Agg")
# import matplotlib.pyplot as plt
import virtnet

# import numpy as np
# from scipy.stats import norm


# DELAY = 10000
# SIGMA = 2000
# SAMPLES = 1000
# X = 10
# NUMPING = 1000

# milliseconds
delay_to_add = 100
# Mbit/s
rate = 10
MTU = 1514

# BDP_packets = rate*1000000*delay_to_add/1000/(MTU*8)
BDP_packets = 1
print("BDP_packets", BDP_packets)
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
			print("cmd", cmd)
			if not Popen:
				output = subprocess.run(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
				return_stuff.append(output)
			else:
				popen = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
				return_stuff.append(popen)
		except subprocess.CalledProcessError as e:
			print(e.cmd, e.returncode, e.output)
			raise e
	return return_stuff


env_with_tc = os.environ.copy()
env_with_tc["TC_LIB_DIR"] = os.path.expanduser('~/repos/iproute2/tc')

# print("os.environ", os.environ)

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
				host["eth0"].add_ip(network)
				hosts.append(host)
				# print("host", host)
		# hosts[0]["eth0"].tc('add', 'netem', delay=DELAY, jitter=SIGMA, dist=y)

		# import pdb; pdb.set_trace()

		for interface in switch.interfaces:
			run_commands(["tc qdisc add dev {} root handle 1: netem delay {}ms".format(interface, delay_to_add/2), "tc qdisc add dev {} parent 1: handle 2: htb default 21".format(interface), "tc class add dev {} parent 2: classid 2:21 htb rate {}mbit".format(interface, rate,), ("tc qdisc add dev {} parent 2:21 handle 3: cn nopacing spam flow_limit {}".format(interface, int(math.ceil(BDP_packets))), {"env": env_with_tc})])
			# run_commands(["tc qdisc add dev {} root handle 1: netem delay {}ms".format(interface, delay_to_add/2), "tc qdisc add dev {} parent 1: handle 2: htb default 21".format(interface), "tc class add dev {} parent 2: classid 2:21 htb rate {}mbit ceil {}mbit".format(interface, rate, rate), ("tc qdisc add dev {} parent 2:21 handle 3: cn".format(interface), {"env": env_with_tc})])
		#     # output = subprocess.run(f"tc qdisc replace dev {interface} root cn".split(" "), capture_output=True, env=env_with_tc)
		#     print("output", output)
		vnet.update_hosts()
		server_popen = hosts[1].Popen("iperf3 -s".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		time.sleep(0.1)
		client_popen = hosts[0].Popen(f"iperf3 -Z reno -i {delay_to_add/1000} -c host1".split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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
