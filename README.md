# cocoa-qdisc
CN contact: Maximilian Bachl

To compile the kernel module run 

    make

to install it and load it into the kernel run

    sudo make install
    
Next, change into the iproute2 folder ```cd iproute2``` and run

    make

To make the configuration for the module visible to the ```tc``` utility we have to set

    export TC_LIB_DIR=<path to the repository>/traq/iproute2/tc
    
Finally, you can use the qdisc on an interface: 

    sudo -E tc qdisc replace dev <interface> root cn
    
```tc``` also allows you to specify options like this: 

    sudo -E tc qdisc replace dev <interface> root cn initial_quantum 3028 quantum 3028
    
