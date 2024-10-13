package aesgcm

import "errors"

var (
	ErrNonceSizeToSmall = errors.New("given nonce size is smaller than the requirement")
)
