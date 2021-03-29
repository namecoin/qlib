package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/namecoin/qlib"
)

var (
	short        = flag.Bool("short", false, "abbreviate long DNSSEC records")
	dnssec       = flag.Bool("dnssec", false, "request DNSSEC records")
	query        = flag.Bool("question", false, "show question")
	check        = flag.Bool("check", false, "check internal DNSSEC consistency")
	six          = flag.Bool("6", false, "use IPv6 only")
	four         = flag.Bool("4", false, "use IPv4 only")
	anchor       = flag.String("anchor", "", "use the DNSKEY in this file as trust anchor")
	tsig         = flag.String("tsig", "", "request tsig with key: [hmac:]name:key")
	port         = flag.Int("port", 53, "port number to use")
	laddr        = flag.String("laddr", "", "local address to use")
	aa           = flag.Bool("aa", false, "set AA flag in query")
	ad           = flag.Bool("ad", false, "set AD flag in query")
	cd           = flag.Bool("cd", false, "set CD flag in query")
	rd           = flag.Bool("rd", true, "set RD flag in query")
	fallback     = flag.Bool("fallback", false, "fallback to 4096 bytes bufsize and after that TCP")
	tcp          = flag.Bool("tcp", false, "TCP mode, multiple queries are asked over the same connection")
	timeoutDial  = flag.Duration("timeout-dial", 2*time.Second, "Dial timeout")
	timeoutRead  = flag.Duration("timeout-read", 2*time.Second, "Read timeout")
	timeoutWrite = flag.Duration("timeout-write", 2*time.Second, "Write timeout")
	nsid         = flag.Bool("nsid", false, "set edns nsid option")
	client       = flag.String("client", "", "set edns client-subnet option")
	opcode       = flag.String("opcode", "query", "set opcode to query|update|notify")
	rcode        = flag.String("rcode", "success", "set rcode to noerror|formerr|nxdomain|servfail|...")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [@server] [qtype...] [qclass...] [name ...]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	params := &qlib.Params {
		Short: *short,
		Dnssec: *dnssec,
		Query: *query,
		Check: *check,
		Six: *six,
		Four: *four,
		Anchor: *anchor,
		Tsig: *tsig,
		Port: *port,
		LAddr: *laddr,
		Aa: *aa,
		Ad: *ad,
		Cd: *cd,
		Rd: *rd,
		Fallback: *fallback,
		Tcp: *tcp,
		TimeoutDial: *timeoutDial,
		TimeoutRead: *timeoutRead,
		TimeoutWrite: *timeoutWrite,
		Nsid: *nsid,
		Client: *client,
		Opcode: *opcode,
		Rcode: *rcode,
	}

	result, err := params.Do(flag.Args())
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	fmt.Println("Success")
	fmt.Println()

	if params.Query {
		fmt.Println("Query Message:")
		fmt.Printf("%v\n", result.QueryMsg)
		fmt.Println()
	}

	fmt.Printf("%v\n", result.ResponseMsg)
	fmt.Println()

	fmt.Printf("RTT: %v\n", result.Rtt)
	fmt.Printf("Nameserver: %v\n", result.Nameserver)
	fmt.Printf("Network: %v\n", result.Net)
	fmt.Printf("XFR Envelope: %v\n", result.XfrEnvelope)
	fmt.Printf("Fallback to 4096 bytes bufsize: %v\n", result.FallbackBufSize)
	fmt.Printf("Fallback to TCP: %v\n", result.FallbackTcp)
}
