package agent

import (
	"os/exec"
	"syscall"
)

// setParentDeathSignal stops journalctl when the agent dies, so a restart never leaves one behind.
func setParentDeathSignal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
