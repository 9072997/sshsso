package sshsso

import (
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/thanhpk/randstr"
	"golang.org/x/crypto/ssh"
)

type gssapiServer struct {
	sspi      *negotiate.ServerContext
	creds     *sspi.Credentials
	sessionID string
}

// NewServer returns a GSSAPIServer from crypto/ssh. It will authenticate as
// the SPN "HOST/foo" where foo is the hostname (not fqdn) of the current
// computer. This may necessitate running as "SYSTEM" or "Network Service".
// This is not thread safe. If you want to handle multiple authentication
// attempts at once (for example in a normal server) you will need to create
// a new copy for each connection, and pass that in via a new
// `ssh.ServerConfig`.
func NewServer() ssh.GSSAPIServer {
	return new(gssapiServer)
}

// AcceptSecContext allows a remotely initiated security context between the application
// and a remote peer to be established by the ssh client. The routine may return a
// outputToken which should be transferred to the ssh client,
// where the ssh client will present it to InitSecContext.
// If no token need be sent, AcceptSecContext will indicate this
// by setting the needContinue to false. To
// complete the context establishment, one or more reply tokens may be
// required from the ssh client. if so, AcceptSecContext
// will return a needContinue which is true, in which case it
// should be called again when the reply token is received from the ssh
// client, passing the token to AcceptSecContext via the
// token parameters.
// The srcName return value is the authenticated username.
// See RFC 2743 section 2.2.2 and RFC 4462 section 3.4.
func (g *gssapiServer) AcceptSecContext(
	token []byte,
) (
	outputToken []byte, srcName string, needContinue bool, err error,
) {
	outputToken, srcName, needContinue, err = g.acceptSecContext(token)
	if Debug {
		log.Printf(
			"SERVER %s: AcceptSecContext([%d]): [%d] \"%s\" %t %v",
			g.sessionID,
			len(token), len(outputToken), srcName, needContinue, err,
		)
	}
	return
}
func (g *gssapiServer) acceptSecContext(
	token []byte,
) (
	outputToken []byte, srcName string, needContinue bool, err error,
) {
	if g.sessionID == "" {
		g.sessionID = randstr.String(4)
		if Debug {
			log.Printf("SERVER %s: New Session", g.sessionID)
		}
	}

	if g.creds == nil {
		hostname, err := os.Hostname()
		if err != nil {
			err := fmt.Errorf("os.Hostname: %w", err)
			return nil, "", false, err
		}
		spn := "HOST/" + hostname
		if Debug {
			log.Printf("SERVER %s: SPN: \"%s\"", g.sessionID, spn)
		}

		g.creds, err = negotiate.AcquireServerCredentials("")
		if err != nil {
			err := fmt.Errorf("negotiate.AcquireServerCredentials: %w", err)
			return nil, "", false, err
		}
	}

	var authCompleted bool
	if g.sspi == nil {
		g.sspi, authCompleted, outputToken, err =
			negotiate.NewServerContext(g.creds, token)
		if err != nil {
			err := fmt.Errorf("negotiate.NewServerContext: %w", err)
			return nil, "", false, err
		}
	} else {
		authCompleted, outputToken, err = g.sspi.Update(token)
		if err != nil {
			err := fmt.Errorf("negotiate.ServerContext.Update: %w", err)
			return nil, "", false, err
		}
	}

	if authCompleted {
		srcName, err = g.Username()
		if err != nil {
			return nil, "", false, err
		}
	}

	return outputToken, srcName, !authCompleted, nil
}

// VerifyMIC verifies that a cryptographic MIC, contained in the token parameter,
// fits the supplied message is received from the ssh client.
// See RFC 2743 section 2.3.2.
func (g *gssapiServer) VerifyMIC(micField []byte, micToken []byte) error {
	err := g.verifyMIC(micField, micToken)
	if Debug {
		log.Printf(
			"SERVER %s: VerifyMIC([%d], [%d]): %v",
			g.sessionID, len(micField), len(micToken), err,
		)
	}
	return err
}
func (g *gssapiServer) verifyMIC(micField []byte, micToken []byte) error {
	_, err := g.sspi.VerifySignature(micField, micToken, 0)
	return err
}

// Whenever possible, it should be possible for
// DeleteSecContext() calls to be successfully processed even
// if other calls cannot succeed, thereby enabling context-related
// resources to be released.
// In addition to deleting established security contexts,
// gss_delete_sec_context must also be able to delete "half-built"
// security contexts resulting from an incomplete sequence of
// InitSecContext()/AcceptSecContext() calls.
// See RFC 2743 section 2.2.3.
func (g *gssapiServer) DeleteSecContext() error {
	sessionID := g.sessionID
	err := g.deleteSecContext()
	if Debug {
		log.Printf("SERVER %s: DeleteSecContext(): %v", sessionID, err)
	}
	return err
}
func (g *gssapiServer) deleteSecContext() error {
	err1 := g.creds.Release()
	g.creds = nil
	err2 := g.sspi.Release()
	g.sspi = nil
	g.sessionID = ""
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}

// return the username of the connected client
func (g *gssapiServer) Username() (string, error) {
	username, err := g.username()
	if Debug {
		log.Printf(
			"SERVER %s: Username(): \"%s\" %v",
			g.sessionID, username, err,
		)
	}
	return username, err
}
func (g *gssapiServer) username() (string, error) {
	// try to get the username the normal way
	username, err := g.sspi.GetUsername()
	if err == nil {
		return username, nil
	}
	if Debug {
		err := fmt.Errorf("negotiate.ServerContext.GetUsername: %w", err)
		log.Printf("SERVER %s: GetUsername Error: %v", g.sessionID, err)
		log.Printf("SERVER %s: Falling back to ImpersonateUser", g.sessionID)
	}

	// if that fails, impersonate the user
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err = g.sspi.ImpersonateUser()
	if err != nil {
		err := fmt.Errorf("negotiate.ServerContext.ImpersonateUser: %w", err)
		return "", err
	}
	defer g.sspi.RevertToSelf()

	// and see who we are
	username, err = getCurrentUser()
	if err != nil {
		return "", err
	}
	return username, nil
}
