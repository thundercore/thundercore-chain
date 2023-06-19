Exampe of usages:

1. Understand the maximum RPC/s using HTTP::

  $ go run src/thunder2/cmd/tb/main.go -b
  > Connect to http://127.0.0.1:8545
  10097.7

2. Understand the maximum RPC/s using Unix domain socket::

  $ go run src/thunder2/cmd/tb/main.go -u ./pala-dev/dataDir/single/thunder2.ipc -b
  > Connect to ./pala-dev/dataDir/single/thunder2.ipc
  22053.0

3. Run 10 accounts with 3000 txs in a round::

  $ go run src/thunder2/cmd/tb/main.go -a 10 -t 3000

4. Fill up the txpool::

  $ go run src/thunder2/cmd/tb/main.go -u ./pala-dev/dataDir/single/thunder2.ipc -a 100 -t 100

Note that HTTP request is slower. We need to use UNIX domain socket to fill up txpool.

Besides watching the TPS, observe the txpool status in resource.json. You'll see tx_pending_count growths as well::

  $ tail -f resource.json  | jq .
