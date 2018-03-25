# AEZ implementation for node

This is an implementation of the [AEZ](http://web.cs.ucdavis.edu/~rogaway/aez/) authenticated-encryption scheme in JavaScript for node.

The code is based upon [Yawning's implementation in Go](https://github.com/Yawning/aez) and the
[reference implementation in C](http://web.cs.ucdavis.edu/~rogaway/aez/code/v5/aez5_software.zip). 

I am by no means an expert in high performance JavaScript or the underlying cryptography. So this library might be really slow.

The current version passes all test vectors generated [with this hacked version of aez](https://github.com/nmathewson/aez_test_vectors).
**But the author does not give any guarantee that the algorithm is implemented correctly at the moment!**