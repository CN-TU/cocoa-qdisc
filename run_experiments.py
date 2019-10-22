#!/usr/bin/env python3

import subprocess
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--number', type=int, default=10)
parser.add_argument('--time', type=float, default=240)
parser.add_argument('--cc', type=str, default="cubic")
parser.add_argument('--qdisc', type=str, default="cn")

opt = parser.parse_args()
print(opt)

cmd = f'''sudo bash -c 'echo > /sys/kernel/debug/tracing/trace' && sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on' && sudo python3 test.py --rate 100 --delay_to_add 50 --time {opt.time} --qdisc {opt.qdisc} --change 1 --cc {opt.cc}'''

for i in range(opt.number):
	try:
		output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True, shell=True, timeout=opt.time+100)
	except subprocess.CalledProcessError as e:
		print(e.cmd, e.returncode, e.output)
		raise e
	except subprocess.TimeoutExpired as e:
		pass