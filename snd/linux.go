package snd

import "syscall"

type syscallStatfs = syscall.Statfs_t

func syscallStatfsCall(path string, stat *syscall.Statfs_t) error {
	return syscall.Statfs(path, stat)
}
