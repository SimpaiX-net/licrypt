package aesctr

import "errors"

var (
	ErrAuthFailure = errors.New("authenticity & integrity failure")
)
