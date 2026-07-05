package main

// Thin wrappers around golang.org/x/crypto/ssh/agent + net.Dial so we don't
// have to add extra module-level dependencies. Keeps main.go focused.

import (
	"net"

	"golang.org/x/crypto/ssh/agent"
)

func netDial(network, addr string) (net.Conn, error) { return net.Dial(network, addr) }

func newAgentClient(c net.Conn) agent.Agent { return agent.NewClient(c) }
