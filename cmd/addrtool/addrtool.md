# The addrtool tool

addrtool can generate ECDSA (Ethereum wallet) and BLS keys.  It can also print data about keys.

For ECDSA keys, given a private key it will print the corresponding public key and address.  For BLS 
keys, given a private key it will print the public key (there are no addresses corresponding to
BLS keys).

## The command line
The command lines:

        $ bin/addrtool
        priv key is b34ff57b97c3619791d24badd3c19ada526af6e137eb6eb7dfbea2586128d41f
        pub  key is 043a7089b1dcc0bfc31debcf22e5879f994c152e69c68c6012d8e9bee0beb8521e599483cc423c282d074019e2ac8df309d90af203ddf1de90bf2d36b77b4949d5
        addr     is 0xD6394FD7264bf6a8CFCcd7a1B28E39D8df92c6B5

        bin/addrtool --bls
        bls signing key is 047977fb046b98e657a4e922bf8bd598fd4c5d61374f5575a8f060ec6d3dff29
        bls public  key is 499aea03bd44db06ce94efdc02a918de8461bc1dbd20bb955916b7dc97d7b7c067c00d019f7cf214d7be803ac02b2f14fb5856bf1438a1f517319986ae24816c73c78be750004201c20316ac732e5f3421f067c781bb8b5f27dd02ce069b59098928cf30e10f8f9e7ad4e17549dae44c288f9c0c988a1050eb87ddf8a082f782

        bin/addrtool --print b34ff57b97c3619791d24badd3c19ada526af6e137eb6eb7dfbea2586128d41f
        priv key is b34ff57b97c3619791d24badd3c19ada526af6e137eb6eb7dfbea2586128d41f
        pub  key is 043a7089b1dcc0bfc31debcf22e5879f994c152e69c68c6012d8e9bee0beb8521e599483cc423c282d074019e2ac8df309d90af203ddf1de90bf2d36b77b4949d5
        addr     is 0xD6394FD7264bf6a8CFCcd7a1B28E39D8df92c6B5

        bin/addrtool --print 043a7089b1dcc0bfc31debcf22e5879f994c152e69c68c6012d8e9bee0beb8521e599483cc423c282d074019e2ac8df309d90af203ddf1de90bf2d36b77b4949d5
        pub  key is 043a7089b1dcc0bfc31debcf22e5879f994c152e69c68c6012d8e9bee0beb8521e599483cc423c282d074019e2ac8df309d90af203ddf1de90bf2d36b77b4949d5
        addr     is 0xD6394FD7264bf6a8CFCcd7a1B28E39D8df92c6B5

        bin/addrtool --bls --print 047977fb046b98e657a4e922bf8bd598fd4c5d61374f5575a8f060ec6d3dff29
        bls signing key is 047977fb046b98e657a4e922bf8bd598fd4c5d61374f5575a8f060ec6d3dff29
        bls public  key is 499aea03bd44db06ce94efdc02a918de8461bc1dbd20bb955916b7dc97d7b7c067c00d019f7cf214d7be803ac02b2f14fb5856bf1438a1f517319986ae24816c73c78be750004201c20316ac732e5f3421f067c781bb8b5f27dd02ce069b59098928cf30e10f8f9e7ad4e17549dae44c288f9c0c988a1050eb87ddf8a082f782

### The args are:
* --print \<hex\> - detect if this is a public or private key, and print the derived values
* --bls - print or generate a BLS key instead of a ECDSA key 
* -h - get command help
