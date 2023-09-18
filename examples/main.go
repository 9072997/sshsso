package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/9072997/sshsso"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// AllowLogin decides weather or not a user should be allowed to connect.
// conn.User() will return the username supplied by the client. You should
// regard that as untrusted. srcName will be in the format user@domain.com
// and is what you should actually check to see if you want to allow the
// connection. If you return a nil error the connection will be allowed.
// The ssh.Permissions doesn't really do much.
func AllowLogin(
	conn ssh.ConnMetadata, srcName string,
) (
	*ssh.Permissions, error,
) {
	fmt.Printf("AllowLogin(__, \"%s\")\n", srcName)
	fmt.Printf("%+v\n", conn)

	// in this example we will allow anyone who's true username matches
	// their claimed username (case insensitive) ignoring domain.
	trueUsername := strings.Split(srcName, "@")[0]
	claimedUsername := conn.User()
	if strings.Contains(claimedUsername, `\`) {
		claimedUsername = strings.Split(claimedUsername, `\`)[1]
	}
	fmt.Printf(
		"TrueUsername: \"%s\"\tClaimedUsername: \"%s\"\n",
		trueUsername,
		claimedUsername,
	)
	if !strings.EqualFold(trueUsername, claimedUsername) {
		return nil, fmt.Errorf(
			"user \"%s\" claimed to be \"%s\"",
			trueUsername, claimedUsername)
	}

	// a nil error will allow the user to log in
	return nil, nil
}

func server() {
	sshConfig := &ssh.ServerConfig{
		GSSAPIWithMICConfig: &ssh.GSSAPIWithMICConfig{
			// AllowLogin() decides if a user is allowed to connect once
			// we know who they are
			AllowLogin: AllowLogin,
			Server:     sshsso.NewServer(),
		},
	}

	// the SSH server requires a host key, but we don't really need to care
	// what it is since kerberos takes care of proving to the client that we
	// are the host we claim to be
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	hostKey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		panic(err)
	}
	sshConfig.AddHostKey(hostKey)

	// start a TCP server on the IP and port from the config
	tcpListener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		panic(err)
	}

	// accept connection
	tcpConn, err := tcpListener.Accept()
	if err != nil {
		panic(err)
	}

	// upgrade the tcp connection to an ssh connection
	sshConn, sessionReqs, globalOOBReqs, err :=
		ssh.NewServerConn(tcpConn, sshConfig)
	if err != nil {
		panic(err)
	}
	log.Printf(
		"SERVER: New connection from \"%s\"",
		sshConn.RemoteAddr(),
	)

	// all the normal stuff you have to seal with to set up SSH
	go ssh.DiscardRequests(globalOOBReqs)
	sessionReq := <-sessionReqs
	session, sessionOOBReqs, err := sessionReq.Accept()
	if err != nil {
		panic(err)
	}
	go ssh.DiscardRequests(sessionOOBReqs)

	// greet the user based on their username, wait 10 seconds, then exit
	t := term.NewTerminal(session, "> ")
	fmt.Fprintln(t, "Hello", sshConn.User())
	time.Sleep(10 * time.Second)
	session.Close()
	sshConn.Close()
}

func client(username, hostname string) {
	sshConn, err := ssh.Dial(
		"tcp",
		// the host you specify here is what you will actually connect to
		hostname+":2222",
		&ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				// the host you specify here is the one we will ask for a
				// kerberos ticket to (the remote computer will have to
				// prove that it is this computer).
				ssh.GSSAPIWithMICAuthMethod(
					sshsso.NewClient(),
					hostname,
				),
			},
			// Don't do this in prod
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
	)
	if err != nil {
		panic(err)
	}

	// use the ssh connection normally
	session, sessionOOBReqs, err := sshConn.OpenChannel("sessionType", nil)
	if err != nil {
		panic(err)
	}
	go ssh.DiscardRequests(sessionOOBReqs)

	// copy from ssh to stdout
	go io.Copy(os.Stdout, session)
	time.Sleep(time.Second * 5)
	sshConn.Close()
}

func main() {
	sshsso.Debug = true

	var action string
	if len(os.Args) > 1 {
		action = os.Args[1]
	}

	var username string
	if len(os.Args) > 2 {
		username = os.Args[2]
	} else {
		u, err := user.Current()
		if err != nil {
			panic(err)
		}
		username = u.Username
	}

	var hostname string
	if len(os.Args) > 3 {
		hostname = os.Args[3]
	} else {
		// we have to use our proper hostname, since we can't prove we are
		// "localhost" using Kerberos.
		hostname, _ = os.Hostname()
	}

	switch action {
	case "server":
		server()
	case "client":
		client(username, hostname)
	case "both":
		go server()
		time.Sleep(time.Second)
		client(username, hostname)
	default:
		basename := filepath.Base(os.Args[0])
		fmt.Println("Usage (this prints unconditionally):")
		fmt.Println("   ", basename, "server")
		fmt.Println("   ", basename, "client myusername [remote host]")
		fmt.Println("   ", basename, "both myusername")
	}
}
