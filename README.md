ndndump - packet capture and analysis tool for NDN
==================================================

ndndump was created to provide a tcpdump-like tool for Named Data Networking (NDN).

For more information about NDN, refer to [NDN Project homepage](http://www.named-data.net/).

## Prerequisites

- ndn-cxx library (https://github.com/named-data/ndn-cxx)

    For detailed installation instructions refer to
    [ndn-cxx getting started instructions](https://github.com/named-data/ndn-cxx)

## Source installation

The following commands will configure, build, and install ndndump:

    ./waf configure
    ./waf
    sudo ./waf install

## Command line options

    Usage:
      ./build/ndndump [-i interface] [-p name-filter] [tcpdump-expression]

    Default tcpdump-expression:
      '(ether proto 0x8624) || (tcp port 6363) || (udp port 6363)'

      -h [ --help ]          Produce this help message
      -i [ --interface ] arg Interface from which to dump packets
      -r [ --read ] arg      Read  packets  from file
      -v [ --verbose ]       When  parsing  and  printing, produce verbose output
      -f [ --filter ] arg    Regular expression to filter out Interest and Data
                             packets
