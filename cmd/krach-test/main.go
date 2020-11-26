package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	smolcert "github.com/smolcert/smolcert"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(certCmd)
	rootCmd.PersistentFlags().StringVar(&listenAddr, "listen", ":9095", "IP and host to listen on. Example: :9095 to listen on all interfaces on port 9095")
}

var (
	defaultClientBasename = "client"
	defaultRootBasename   = "root"
	defaultServerBasename = "server"
)

var (
	listenAddr = ":9095"
)
var (
	rootCmd = &cobra.Command{
		Use:   "krach-tester",
		Short: "Tool to test implementations of krach against the go implementation",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("This should start the server")
		},
	}

	certCmd = &cobra.Command{
		Use:   "certs",
		Short: "Writes the test certs and keys to the given location",
		Run: func(cmd *cobra.Command, args []string) {
			rootCert, rootKey, err := smolcert.SelfSignedCertificate("root", time.Time{}, time.Time{},
				[]smolcert.Extension{})
			if err != nil {
				er(err)
			}
			writePair(rootCert, rootKey, defaultRootBasename)

			clientCert, clientKey, err := smolcert.ClientCertificate("client", 1, time.Time{}, time.Time{},
				[]smolcert.Extension{}, rootKey, rootCert.Subject)
			if err != nil {
				er(err)
			}
			writePair(clientCert, clientKey, defaultClientBasename)

			serverCert, serverKey, err := smolcert.ServerCertificate("server", 2, time.Time{}, time.Time{},
				nil, rootKey, rootCert.Subject)
			if err != nil {
				er(err)
			}
			writePair(serverCert, serverKey, defaultServerBasename)

			fmt.Printf(`
			Root smolcert written to: root.smolcert
			Root key written to: root.key
			Server smolcert written to: server.smolcert
			Server key written to: server.key
			Client smolcert written to: client.smolcert
			Client key written to: client.key
			
			Please use client.smolcert and client.key to connect to this server
`)
		},
	}
)

func writePair(cert *smolcert.Certificate, key ed25519.PrivateKey, baseName string) {
	certBytes, err := cert.Bytes()
	if err != nil {
		er(err)
	}
	writeFile(certBytes, baseName+".smolcert")
	writeFile([]byte(key), baseName+".key")
}

func writeFile(buf []byte, filePath string) {
	outFile, err := os.Create(filePath)
	if err != nil {
		er(err)
	}
	defer outFile.Close()
	n, err := outFile.Write(buf)
	if err != nil {
		er(err)
	}
	if n != len(buf) {
		er(fmt.Errorf("Expected to write %d bytes to file %s, but only %d got written", len(buf), filePath, n))
	}
}

func er(err error) {
	fmt.Printf("Error: %s\n", err)
	os.Exit(1)
}

func main() {
	rootCmd.Execute()
}
