//go:build !linux

package v5

func bindDevice(fd uintptr, ifceName string) error {
	return nil
}

func setMark(fd uintptr, mark int) error {
	return nil
}
