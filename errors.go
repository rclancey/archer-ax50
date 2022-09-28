package ax50

import (
	"errors"
)

var ErrLoginFailed = errors.New("Login failed, wrong password")
var ErrExceededMaxAttempts = errors.New("Login failed, maximum login attempts exceeded. Please wait for 60-120 minutes")
var ErrUserConflict = errors.New("Login conflict. Someone else is logged in.")
var ErrLoginError = errors.New("Login error")
