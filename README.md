[![Go Reference](https://pkg.go.dev/badge/github.com/9072997/sshsso.svg)](https://pkg.go.dev/github.com/9072997/sshsso)

A `GSSAPIServer` and `GSSAPIClient` for crypto/ssh based on Kerberos and the Windows Security Support Provider Interface (so it only works on Windows). My only intention was that client implementation to be able to authenticate with this server implementation, so if it works with any other GSSAPI or Kerberos implementation it is just a happy accident. This makes it possible to do "Windows Single Sign On" without prompting the user for credentials, or to have AD computers authenticate using their computer account. You can also take advantage of the fact that kerberos does mutual authentication to eliminate the need for host key checking **IF** you use the `GSSAPIClient.Success` variable.

Check out the [example program](examples/main.go)

Thanks to [Alex Brainman's excellent SSPI library](https://github.com/alexbrainman/sspi)

# Quick Start
## Client
```golang
var usedKerberosAuth bool
sshConn, _ := ssh.Dial(
	// the host you specify here is what you will actually connect to
	"tcp", "localhost:2222",
	&ssh.ClientConfig{
		User: "MyUsername",
		Auth: []ssh.AuthMethod{
			// the host you specify here is the one we will ask for a
			// kerberos ticket to (the remote computer will have to
			// prove that it is this computer).
			ssh.GSSAPIWithMICAuthMethod(
				&sshsso.GSSAPIClient{Success: &usedKerberosAuth},
				"NetBIOSName",
			),
		},
		// we can safely ignore host key, since kerberos already forces
		// the remote computer to prove who it is **IF** we check that
		// we actually used Kerberos for authentication using the
		// usedKerberosAuth variable
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	},
)

// if this is false, it means the server accepted "none" auth and might
// not be who we think it is
if !usedKerberosAuth {
	sshConn.Close()
	panic("server accepted none auth")
}
```

## Server
```golang
sshConfig := &ssh.ServerConfig{
	GSSAPIWithMICConfig: &ssh.GSSAPIWithMICConfig{
		// AllowLogin() decides if a user is allowed to
		// connect once we know who they are
		AllowLogin: func(_ ssh.ConnMetadata, user string) (*ssh.Permissions, error) {
			if user == "kidswatter@WAYSIDESCHOOL.LOCAL" {
				return nil, nil
			} else {
				return nil, errors.New("Not Authorized")
			}
		},
		Server: &sshsso.GSSAPIServer{},
	},
}
```

# Gotchas
* The server needs to have permission to validate tickets for the service principal name (SPN) "HOST/myhostname", which means you probably have to run as "SYSTEM" ("Network Service" might work too, I haven't tested)
* If you are doing machine to machine authentication remember that AD computer accounts end with a "$"
* I'm dumb and this is dangerously close to the classic blunder of "rolling your own key exchange". If it breaks, you get to keep both halves.
* Thread safety: `GSSAPIServer` and `GSSAPIClient` are not thread safe. If you want to handle multiple authentication attempts at once (for example in a normal server) you will need to create a new copy for each connection which will be passed in via a new `ssh.ServerConfig` or `ssh.ClientConfig`
* Neither the API nor the protocol should be considered stable
