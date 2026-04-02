package centralserver

import "time"

type EnrollmentContext struct {
	Identity   IdentityType
	Enrollment Enrollment
	Method     string
	At         time.Time
}

type IdentifyContext struct {
	Identity   IdentityType
	Enrollment Enrollment
	Found      bool
	Method     string
	At         time.Time
}

func (p *Process) SetEnrollCallback(fn func(EnrollmentContext)) {
	if fn != nil {
		p.onEnroll = fn
	}
}

func (p *Process) SetIdentifyCallback(fn func(IdentifyContext)) {
	if fn != nil {
		p.onIdentify = fn
	}
}
