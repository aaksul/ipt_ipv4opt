# xt_ipv4opt

## Overview
`xt_ipv4opt` is a Linux kernel module and user-space library for matching IPv4 options in network packets. It provides functionality to inspect and filter packets based on specific IPv4 options.

## Files
- **xt_ipv4opt.c**: The main source file containing the implementation of the IPv4 options matching logic and it registers the match function via the Netfilter API.
- **libipt_ipv4opt.c**: The user-space library file that provides the interface for `iptables` to use the `xt_ipv4opt` match.
- **ipv4opt_iptables/Makefile**: The build script for copying source file into iptables/extensions and compiling it with the Makefile presented in that file.
- **kernel/Makefile**: The build script for compiling the kernel module and the user-space library.

## Dependency Notice
This project **depends on the iptables source tree**, as it integrates directly with its `extensions/` build system.  
**The iptables source directory must be stored in the same parent directory as this repository.**

Example directory structure:
```
parent-directory/
├── iptables/
└── xt_ipv4opt/
```
## Build And Install
To utilize the `ipv4opt` match in iptables, you need to build and install the iptables binary with the  extensions. Then register the match function via Netfilter API.

### 1. Build and Install Iptables
1. Clone the `ipt_ipv4opt` repository:
    ```sh
    git clone <repository-url>
    ```

2. Make sure that iptables is not already installed. Then, clone the iptables source code: 
    ```sh
    git clone git://git.netfilter.org/iptables
    ```

3. Build and install `iptables`:
    ```sh
    cd iptables
    ./autogen.sh
    ./configure
    make
    sudo make install
    ```

### 2. Build and dynamically load extensions to Iptables binary
4. Run make command:
    ```sh
    cd ipt_ipv4opt/ipv4opt_iptables
    sudo make all
    sudo make install
    ```
5. Verify that the library is installed:
    ```sh
    iptables -m ipv4opt --help
    ```

### 3. Build And Register match function
To build the kernel module and the user-space library, you need to have the Linux kernel headers and `iptables` development files installed. Follow these steps:

6. Build the kernel module and the user-space library:
    ```sh
    cd ipt_ipv4opt/ipv4opt_iptables
    sudo make
    ```

7. Load the built kernel module:
    ```sh
    sudo insmod xt_ipv4opt.ko
    ```

8. Verify that the module is loaded:
    ```sh
    lsmod | grep xt_ipv4opt
    ```


## Usage
To use the module, you need to add rules to `iptables` that utilize the `xt_ipv4opt` match. Here is an example:

```sh
sudo iptables -A INPUT -m ipv4opt  [--soft] --opttype <option-type> -j ACCEPT
```
example:
```sh
sudo iptables -A INPUT -m ipv4opt --opttype 68,148 -j ACCEPT
sudo iptables -A INPUT -m ipv4opt --soft --opttype 68,148 -j DROP
 