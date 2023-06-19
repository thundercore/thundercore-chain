package bls

// Interface to get data signed securely.
// Over time, we will build objects & libraries with functionalities which may need to get some
// data signed by private key. But we also don't want copies of private key everywhere for security
// purpose (more copies => more risk of loosing via api, or write to file by mistake, etc)
// This simple abstraction to interface gives 'node' object only ownership of signing key while
// giving other libraries (like multisig) ability to get data signed.
type BlsSigner interface {
	Sign(data []byte) *Signature
	GetPublicKey() *PublicKey
}
