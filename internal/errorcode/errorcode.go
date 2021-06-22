// Package Errors provides an implementation of error with an error code
package errorcode

type Error struct {
	Err  error
	Code string
}

func New(c string, e error) *Error {
	return &Error{
		Err:  e,
		Code: c,
	}
}

func (e Error) Error() string {
	return e.Err.Error()
}
