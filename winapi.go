package sshsso

import (
	"fmt"
	"syscall"
	"unsafe"
)

var advapi32DLL *syscall.DLL
var procGetUserNameW *syscall.Proc

// get the user for this OS thread
// unlike user.Current(), this does not cache the result
func getCurrentUser() (string, error) {
	if advapi32DLL == nil {
		var err error
		advapi32DLL, err = syscall.LoadDLL("advapi32.dll")
		if err != nil {
			err := fmt.Errorf(`syscall.LoadDLL("advapi32.dll"): %w`, err)
			return "", err
		}
	}
	if procGetUserNameW == nil {
		var err error
		procGetUserNameW, err = advapi32DLL.FindProc("GetUserNameW")
		if err != nil {
			err := fmt.Errorf("advapi32DLL.FindProc(GetUserNameW): %w", err)
			return "", err
		}
	}

	var buf [256]uint16
	var n uint32 = uint32(len(buf))
	r1, _, err := procGetUserNameW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&n)),
	)
	if r1 == 0 {
		err := fmt.Errorf("WinAPI GetUserNameW: %d %w", r1, err)
		return "", err
	}
	return syscall.UTF16ToString(buf[:]), nil
}
