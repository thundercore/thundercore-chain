package commitsha1

// CommitSha1 is the version string from the revision control system,
// e.g. the output of `git rev-parse HEAD`.
// Its value is set from the Makefile via
// -ldflags "-X commitsha1.CommitSHA1=..."
var CommitSha1 = "000000v000000000000000000000000000000000"
var CommitTag = ""
