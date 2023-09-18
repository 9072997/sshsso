// Package sshsso implements gssapiServer and gssapiClient from crypto/ssh
// based on the Windows Security Support Provider Interface "negotiate"
// implimentation. This makes it possible to do authentication without
// prompting the user for credentials using AD. This package makes no
// attempt to be compatible with any other ssh server or client other than
// itself.
package sshsso

// Debug will cause each GAASPI call to be logged using the default logger
var Debug = false
