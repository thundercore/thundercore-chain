package rmonitor

type Resource interface {
	ID() string
	Equal(Resource) bool
	Dump()
}
