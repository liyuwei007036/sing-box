//go:build !linux

package dialer

import "github.com/sagernet/sing/common/control"

func setInitialTTL(int) control.Func {
	return nil
}
