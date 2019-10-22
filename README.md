# cocoa-qdisc
CN contact: Maximilian Bachl

## Building
To compile the kernel module run 

    make

to install it and load it into the kernel run

    sudo make install
    
Next, change into the iproute2 folder ```cd iproute2``` and run

    make

## Deploying
To make the configuration for the module visible to the ```tc``` utility we have to set

    export TC_LIB_DIR=<path to the repository>/cocoa-qdisc/iproute2/tc

Finally, you can use the qdisc on an interface: 

    sudo -E tc qdisc replace dev <interface> root cocoa
    
```tc``` also allows you to specify options like this: 

    sudo -E tc qdisc replace dev <interface> root cocoa initial_quantum 3028 quantum 3028
    
## Experimenting
To run experiments, make sure you have [```py-virtnet```](https://github.com/CN-TU/py-virtnet) installed and then run

    sudo bash -c 'echo > /sys/kernel/debug/tracing/trace' && sudo bash -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on' && sudo python3 test.py --rate 20 --delay_to_add 1 --time 30 --qdisc cocoa --change 1 --cc cubic
    
After running experiments with our qdisc, you can look at detailed output in the kernel tracing file at ```/sys/kernel/debug/tracing/trace```.

All tests were performed on kernel ```4.19.0-6-amd64``` on Debian Buster. We use python 3.7.2.
