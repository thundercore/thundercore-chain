# The fntool tool

fntool is designed to stress fullnodes by sending large numbers of requests to them

## The command line
A simple command line is (as a single line, wrapped to multiple lines here for clarity):

	bin/fntool --target ws://localhost:8536 randblock

(use port 8546 to connect to the Thunder accelerator's fullnode in a local chain)

### args:
* --target - the url to the destination fullnode
* -v - print verbose information.  Optional.
* -h - get command help
* --txDelay - wait time between requests.  
* --numSockets - number of sockets/goroutines to use for sending requests
* --duration - amount of time to send requests.  Default = 24hours. Use "30s" for 30 seconds, etc

### The commands are:
* chainid - send lots of chainid requests
* block - send lots of requests for block 1
* randblock - send lots of requests for random blocks with block numbers between 0 and the current 
block when fntool was started
* seqblock - send requests for sequential blocks from 1 to the current block number
