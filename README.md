# cocoa-qdisc
CN contact: Maximilian Bachl

Cocoa is a qdisc which maximizes throughput for each flow while keeping the buffer minimal. For a more detailed description check out the [upcoming paper](https://arxiv.org/abs/1910.10604).
## Building
To compile the kernel module run 

    make

to install it and load it into the kernel run

    sudo make install
    
Next, change into the iproute2 folder ```cd iproute2``` and run

    make
    sudo make install

## Deploying
To make the configuration for the module visible to the ```tc``` utility we have to set

    export TC_LIB_DIR=<path to the repository>/cocoa-qdisc/iproute2/tc

Finally, you can use the qdisc on an interface: 

    sudo -E tc qdisc replace dev <interface> root cocoa
    
```tc``` also allows you to specify options like this: 

    sudo -E tc qdisc replace dev <interface> root cocoa initial_quantum 3028 quantum 3028
    
## Experimenting
To run experiments, make sure you have [```py-virtnet```](https://pypi.org/project/py-virtnet/) ([GitHub repository](https://github.com/CN-TU/py-virtnet)) installed and then run

    sudo bash -c 'echo > /sys/kernel/debug/tracing/trace' && sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on' && sudo python3 test.py --path_to_tc_module <path to the repository>/cocoa-qdisc/iproute2/tc --rate 20 --delay_to_add 1 --time 30 --qdisc cocoa --change 1 --cc cubic
    
After running experiments with cocoa, you can look at detailed output in the kernel tracing file at ```/sys/kernel/debug/tracing/trace```.

## Analyzing
To create plots of a run and show further statistics, first compile ```wintracker```:

    go build -o wintracker wintracker.go
    
Then, if you have a file called ```sender_fq_codel_cubic_1_20_120_1.0_bw_1571822805075.pcap``` in the ```pcaps``` directory you can run the plotting script:

    ./plot_rtt_and_bandwidth.py sender_fq_codel_cubic_1_20_120_1.0_bw_1571822805075.pcap

All tests were performed on kernel ```4.19.0-6-amd64``` on Debian Buster. We use Python 3.7.2. Our go version is ```go1.10.2 linux/amd64```.
