//go:build !linux

package diale

import "github.com/sagernet/sing/common/control"

func setInitialTTL(int) control.Func {
	return nil
}
