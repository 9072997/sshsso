package sshsso

import (
	"fmt"
	"log"
	"regexp"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/thanhpk/randstr"
	"golang.org/x/crypto/ssh"
)

type gssapiClient struct {
	sspi      *negotiate.ClientContext
	creds     *sspi.Credentials
	sessionID string
}

// NewClient returns a GSSAPIClient from crypto/ssh. It will always attempt
// to authenticate as the current Windows user. This is not thread safe. In
// normal client scenarios this is fine, but if you want to handle multiple
// authentication attempts at once you will need to create a new copy for
// each connection and pass that in via a new `ssh.ClientConfig`.
func NewClient() ssh.GSSAPIClient {
	return new(gssapiClient)
}

// InitSecContext initiates the establishment of a security context for GSS-API between the
// ssh client and ssh server. Initially the token parameter should be specified as nil.
// The routine may return a outputToken which should be transferred to
// the ssh server, where the ssh server will present it to
// AcceptSecContext. If no token need be sent, InitSecContext will indicate this by setting
// needContinue to false. To complete the context
// establishment, one or more reply tokens may be required from the ssh
// server;if so, InitSecContext will return a needContinue which is true.
// In this case, InitSecContext should be called again when the
// reply token is received from the ssh server, passing the reply
// token to InitSecContext via the token parameters.
// See RFC 2743 section 2.2.1 and RFC 4462 section 3.4.
func (g *gssapiClient) InitSecContext(
	target string, token []byte, isGSSDelegCreds bool,
) (
	outputToken []byte, needContinue bool, err error,
) {
	outputToken, needContinue, err =
		g.initSecContext(target, token, isGSSDelegCreds)
	if Debug {
		log.Printf(
			"CLIENT %s: InitSecContext(\"%s\", [%d], %t): [%d] %t %v",
			g.sessionID,
			target, len(token), isGSSDelegCreds,
			len(outputToken), needContinue, err,
		)
	}
	return
}
func (g *gssapiClient) initSecContext(
	target string, token []byte, isGSSDelegCreds bool,
) (
	outputToken []byte, needContinue bool, err error,
) {
	if g.sessionID == "" {
		g.sessionID = randstr.String(4)
		if Debug {
			log.Printf("CLIENT %s: New Session", g.sessionID)
		}
	}

	if g.creds == nil {
		g.creds, err = negotiate.AcquireCurrentUserCredentials()
		if err != nil {
			err := fmt.Errorf("negotiate.AcquireCurrentUserCredentials: %w", err)
			return nil, false, err
		}
	}

	var authCompleted bool
	if g.sspi == nil {
		spn := regexp.MustCompile("^host@").
			ReplaceAllLiteralString(target, "HOST/")
		if Debug {
			log.Printf("CLIENT: SPN: \"%s\"", spn)
		}

		g.sspi, outputToken, err =
			negotiate.NewClientContextWithFlags(
				g.creds, spn, sspi.ISC_REQ_MUTUAL_AUTH,
			)
		if err != nil {
			err := fmt.Errorf("negotiate.NewClientContextWithFlags: %w", err)
			return outputToken, true, err
		}

		return outputToken, true, nil
	}

	authCompleted, outputToken, err = g.sspi.Update(token)
	if err != nil {
		err := fmt.Errorf("negotiate.ClientContext.Update: %w", err)
		return nil, false, err
	}

	err = g.sspi.VerifyFlags()
	if err != nil {
		err := fmt.Errorf("negotiate.ClientContext.VerifyFlags: %w", err)
		return nil, false, err
	}

	return outputToken, !authCompleted, nil
}

// GetMIC generates a cryptographic MIC for the SSH2 message, and places
// the MIC in a token for transfer to the ssh server.
// The contents of the MIC field are obtained by calling GSS_GetMIC()
// over the following, using the GSS-API context that was just
// established:
//
//	string    session identifier
//	byte      SSH_MSG_USERAUTH_REQUEST
//	string    user name
//	string    service
//	string    "gssapi-with-mic"
//
// See RFC 2743 section 2.3.1 and RFC 4462 3.5.
func (g *gssapiClient) GetMIC(micField []byte) ([]byte, error) {
	micToken, err := g.getMIC(micField)
	if Debug {
		log.Printf(
			"CLIENT %s: GetMIC([%d]): [%d] %v",
			g.sessionID, len(micField), len(micToken), err,
		)
	}
	return micToken, err
}
func (g *gssapiClient) getMIC(micField []byte) ([]byte, error) {
	mic, err := g.sspi.MakeSignature(micField, 0, 0)
	if err != nil {
		err := fmt.Errorf("negotiate.ClientContext.MakeSignature: %w", err)
		return mic, err
	}
	return mic, nil
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
func (g *gssapiClient) DeleteSecContext() error {
	sessionID := g.sessionID
	err := g.deleteSecContext()
	if Debug {
		log.Printf(
			"CLIENT %s: DeleteSecContext(): %v",
			sessionID, err,
		)
	}
	return err
}
func (g *gssapiClient) deleteSecContext() error {
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
