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
$ go get github.com/hwipl/smc-llc
```

## Usage

You can run smc-llc with the `smc-llc` command. Make sure your user has the
permission to capture traffic on the network interface.

You can specify the network interface with the option `-i`. For example, you
can specify the interface `eth0` with:

```console
$ smc-llc -i eth0
```

Options of the `smc-llc` command:

```
  -f string
        the pcap file to read
  -http string
        use http server and set listen address (e.g.: :8000)
  -i string
        the interface to listen on (default "eth0")
  -promisc
        promiscuous mode (default true)
  -snaplen int
        pcap snaplen (default 2048)
  -with-bth
        show BTH
  -with-grh
        show GRH
  -with-hex
        show hex dumps
  -with-other
        show other messages
  -with-reserved
        show reserved message fields
```
