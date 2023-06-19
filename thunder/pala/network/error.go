package network

type TLSVerifyError struct {
	message string
}

func (err TLSVerifyError) Error() string {
	return err.message
}

type HandShakeError struct {
	message string
}

func (err HandShakeError) Error() string {
	return err.message
}

type ClientPuzzleError struct {
	message string
}

func (err ClientPuzzleError) Error() string {
	return err.message
}
