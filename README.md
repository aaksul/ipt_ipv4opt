# xt_ipv4opt

## Overview
`xt_ipv4opt` is a Linux kernel module and user-space library for matching IPv4 options in network packets. It provides functionality to inspect and filter packets based on specific IPv4 options.

## Files
- **xt_ipv4opt.c**: The main source file containing the implementation of the IPv4 options matching logic.
- **libipt_ipv4opt.c**: The user-space library file that provides the interface for `iptables` to use the `xt_ipv4opt` match.
- **Makefile**: The build script for compiling the kernel module and the user-space library.

## Building the Module
To build the kernel module and the user-space library, you need to have the Linux kernel headers and `iptables` development files installed. Follow these steps:

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd xt_ipv4opt
    ```

2. Build the module and the user-space library:
    ```sh
    make
    ```

3. Load the module:
    ```sh
    sudo insmod xt_ipv4opt.ko
    ```

4. Verify that the module is loaded:
    ```sh
    lsmod | grep xt_ipv4opt
    ```

## Building and Installing the iptables Shared Library
To use the `ipv4opt` match in `iptables`, you need to build and install the shared library:

1. Clone the `iptables` source code:
    ```sh
    git clone git://git.netfilter.org/iptables
    cd iptables
    ```

2. Copy the `libipt_ipv4opt.c` file to the `iptables/extensions` directory:
    ```sh
    cp /path/to/xt_ipv4opt/libipt_ipv4opt.c extensions/
    ```

3. Build and install `iptables` with the new extension:
    ```sh
    ./autogen.sh
    ./configure
    make
    sudo make install
    ```

4. Verify that the library is installed:
    ```sh
    iptables -m ipv4opt --help
    ```

## Usage
To use the module, you need to add rules to `iptables` that utilize the `xt_ipv4opt` match. Here is an example:

```sh
sudo iptables -A INPUT -m ipv4opt --opttype <option-type> -j ACCEPT