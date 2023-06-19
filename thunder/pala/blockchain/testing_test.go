package blockchain

// TODO(thunder): when we want to test byzantine behavior, fix this test.
/*
func TestVerifierFakeBad(t *testing.T) {
	req := require.New(t)

	// prepare VerifierFake for testing
	pid := ConsensusId("p1")
	vid := ConsensusId("v1")
	proposerList := NewElectionResultFake([]ConsensusId{pid}, Session(1), Session(2))
	voterList := NewElectionResultFake([]ConsensusId{vid}, Session(1), Session(2))
	verifier := NewVerifierFakeBad(pid, vid, proposerList, voterList,
		"p100", "v100", false)

	// no longer proposer/voter at session 2
	verifier.AddElectionResult(
		NewElectionResultFake([]ConsensusId{"p2"}, Session(3), Session(4)),
		NewElectionResultFake([]ConsensusId{"v2"}, Session(3), Session(4)))

	makeBlock := func(e Epoch) Block {
		return NewBlockFake(
			BlockSn{e, uint32(2)},
			BlockSn{e, uint32(1)},
			0, []Notarization{}, nil, "")
	}

	// propose when it is our turn, expect no error
	proposal, err := verifier.Propose(makeBlock(NewEpoch(1, 1)))
	req.NoError(err, "expected nil err for Propose")

	// verify, expect no error
	err = verifier.VerifyProposal(proposal)
	req.NoError(err, "expected nil for VerifyProposal")

	// vote when it is our turn
	vote, err := verifier.Vote(proposal)
	req.NoError(err, "expected nil err for Vote")

	// verify, expect no error
	err = verifier.VerifyVote(vote, nil)
	req.NoError(err, "expected nil err for VerifyVote")

	// make a bad proposal, expect no error
	proposal, err = verifier.Propose(makeBlock(NewEpoch(3, 1)))
	req.NoError(err, "expected nil err for Propose")

	// verify bad proposal, expect error
	err = verifier.VerifyProposal(proposal)
	req.Error(err, "expected err for VerifyProposal")

	// vote on bad proposal, expect no error
	vote, err = verifier.Vote(proposal)
	req.NoError(err, "expected nil err for Vote")

	// verify bad vote, expect error
	err = verifier.VerifyVote(vote, nil)
	req.Error(err, "expected err for VerifyVote")

	// a good clock message, expect no error
	cm, err := verifier.NewClockMsg(NewEpoch(1, 2))
	req.NoError(err, "expected nil err for NewClockMsg")

	// verify, expect no error
	err = verifier.VerifyClockMsg(cm)
	req.NoError(err, "expected nil err for VerifyClockMsg")

	// make a bad clock message, expect no error
	cm, err = verifier.NewClockMsg(NewEpoch(4, 1))
	req.NoError(err, "expected nil err for NewClockMsg")

	// verify bad vote, expect error
	err = verifier.VerifyClockMsg(cm)
	req.Error(err, "expected err for VerifyClockMsg")
}
*/
