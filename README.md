# smc-llc

smc-llc is a command line tool for capturing SMC LLC traffic from a network
interface or reading it from a pcap file and parsing the SMC LLC messages. The
LLC messages are part of the
[SMC protocol](https://www.rfc-editor.org/info/rfc7609) and are used to
establish SMC connections between communication partners over RoCE devices.
Although LLC messages are the main focus of this tool, it also captures and
parses RoCEv1 and RoCEv2 GRHs and BTHs as well as SMC CDC messages.

## Installation

You can download and install smc-llc with its dependencies to your GOPATH or
GOBIN with the go tool:

```console
$ go get github.com/hwipl/smc-llc/cmd/smc-llc
```

## Usage

You can run smc-llc with the `smc-llc` command. Make sure your user has the
permission to capture traffic on the network interface.

You can specify the network interface with the option `-i`. For example, you
can specify the interface `eth0` with:

```console
$ smc-llc -i eth0
```

Alternatively, you can read packets from a pcap file with the option `-f`.

Hint: For example, you can capture packets directly from a local Mellanox
infiniband device with the tool [ibdump](https://github.com/Mellanox/ibdump)
and load the resulting pcap file, e.g., `sniffer.pcap`, in smc-llc with the
following command:

```console
$ smc-llc -f sniffer.pcap
```

Options of the `smc-llc` command:

```
  -f file
        read packets from a pcap file and set it to file
  -http address
        use http server output and listen on address (e.g.: :8000 or
        127.0.0.1:8080)
  -i interface
        read packets from a network interface (default) and set it to interface
  -pcap-filter filter
        set pcap packet filter to filter (e.g.: "not port 22")
  -pcap-maxpkts number
        set maximum packets to capture to number (may require pcap-timeout
        argument)
  -pcap-maxtime seconds
        set maximum capturing time to seconds (may require pcap-timeout
        argument)
  -pcap-promisc
        set network interface to promiscuous mode (default true)
  -pcap-snaplen milliseconds
        set pcap timeout to milliseconds (default 2048)
  -pcap-timeout milliseconds
        set pcap timeout to milliseconds
  -show-bth
        show BTH of messages
  -show-grh
        show GRH of messages
  -show-hex
        show hex dumps of messages
  -show-other
        show non-LLC/CDC messages
  -show-reserved
        show reserved message fields
  -show-timestamps
        show timestamps of messages (default true)
```
