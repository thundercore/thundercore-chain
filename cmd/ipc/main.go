package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
)

var (
	prettify = flag.Bool("pretty", false, "Prettify response.")
)

type rpcRequest struct {
	Version string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	Id      uint32        `json:"id"`
}

func readSocket(conn io.Reader, errCh chan error) {
	resp, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		errCh <- err
		return
	}

	if *prettify {
		var output bytes.Buffer
		json.Indent(&output, resp, "", "\t")
		output.WriteTo(os.Stdout)
	} else {
		fmt.Printf("%v", string(resp[:]))
	}

	errCh <- nil
}

func parseArgs(args []string) (method string, params []interface{}) {
	method = args[0]

	if len(args) > 1 {
		for _, arg := range args[1:] {
			// int
			if val, err := strconv.ParseUint(arg, 10, 64); err == nil {
				params = append(params, val)
				continue
			}
			// bool
			if val, err := strconv.ParseBool(arg); err == nil {
				params = append(params, val)
				continue
			}
			// float
			if val, err := strconv.ParseFloat(arg, 64); err == nil {
				params = append(params, val)
				continue
			}
			// string
			params = append(params, arg)
		}
	}
	return
}

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s method [arg1 arg2 ...]\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.Usage = Usage
	path := flag.String("p", "/datadir/thunder2.ipc", "Unix domain socket path used by pala")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		return
	}

	method, params := parseArgs(args)
	if err := sendSocketRpc(*path, method, params); err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
}

func sendSocketRpc(ipcPath, method string, params []interface{}) error {
	errCh := make(chan error)

	conn, err := net.Dial("unix", ipcPath)
	if err != nil {
		return err
	}
	defer conn.Close()

	go readSocket(conn, errCh)

	req := rpcRequest{
		Version: "2.0",
		Method:  method,
		Params:  params,
		Id:      1,
	}
	if b, err := json.Marshal(req); err == nil {
		conn.Write(b)
	} else {
		return err
	}

	if err := <-errCh; err != nil {
		return err
	}
	return nil
}
