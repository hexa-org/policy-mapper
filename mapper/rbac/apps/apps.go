package apps

import (
	"github.com/hexa-org/policy-mapper/api/idp"
)

type Idp interface {
	Provider() (idp.AppInfoSvc, error)
}
