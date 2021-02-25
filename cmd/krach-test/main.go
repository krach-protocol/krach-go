package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/connctd/krach/v2"
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
		Short: "Tool to test implementations of krach against the go implementation. Will expect data on stream 1",
		Run: func(cmd *cobra.Command, args []string) {
			ctx, mainCancel := context.WithCancel(context.Background())
			serverCert, serverKey := loadPair("server")
			serverIdentity := krach.NewPrivateIdentity(serverCert, serverKey)

			serverConf := krach.DefaultConnectionConfig()
			serverConf.IsClient = false
			serverConf.LocalIdentity = serverIdentity

			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
			var tcpListener net.Listener
			go func() {
				var err error
				tcpListener, err = net.Listen("tcp", listenAddr)
				if err != nil {
					er(err)
				}
				log.Printf("Waiting for connections on: %s", tcpListener.Addr().String())
				for {
					select {
					case <-ctx.Done():
						tcpListener.Close()
						return
					default:
						conn, err := tcpListener.Accept()
						if err != nil {
							er(err)
						}
						clientCtx, clientCancel := context.WithCancel(ctx)
						defer clientCancel()
						go func(ctx context.Context, conn net.Conn) {
							defer conn.Close()
							log.Printf("Opened socket for %s, running handshake", conn.RemoteAddr().String())
							serverConn, err := krach.NewConn(serverConf, conn)
							if err != nil {
								log.Printf("Failed to create krach server handler: %s", err)
								return
							}
							if err := serverConn.Handshake(); err != nil {
								log.Printf("Handshake failed for %s: %s", conn.RemoteAddr().String(), err)
								return
							}
							log.Printf("Handshake succeeded for client %s, creating stream with ID 1", conn.RemoteAddr().String())
							stream, err := serverConn.NewStream(uint8(1))
							if err != nil {
								log.Printf("Failed to create stream 1 with client %s", conn.RemoteAddr().String())
								return
							}
							readBuf := make([]byte, 4096)
							for {
								select {
								case <-ctx.Done():
									return
								default:
									n, err := stream.Read(readBuf)
									if err != nil {
										log.Printf("Failed to read data from stream: %s", err)
										return
									}
									log.Printf("Received %d bytes from %s", n, conn.RemoteAddr().String())
									printBuf(readBuf[:n])
								}
							}
						}(clientCtx, conn)
					}
				}
			}()

			<-sigs
			log.Printf("Exiting server")
			tcpListener.Close()
			mainCancel()
			os.Exit(0)
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

func loadPair(baseName string) (*smolcert.Certificate, ed25519.PrivateKey) {
	certFile, err := os.Open(baseName + ".smolcert")
	if err != nil {
		er(err)
	}
	defer certFile.Close()

	keyFile, err := os.Open(baseName + ".key")
	if err != nil {
		er(err)
	}
	defer keyFile.Close()

	cert, err := smolcert.Parse(certFile)
	if err != nil {
		er(err)
	}

	keyBytes, err := ioutil.ReadAll(keyFile)
	return cert, ed25519.PrivateKey(keyBytes)
}

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

var bytesPerLine = 16

func printBuf(buf []byte) {
	for i, b := range buf {
		fmt.Printf("0x%X ", b)
		if i%bytesPerLine == 0 {
			fmt.Printf("\n")
		}
	}
	fmt.Printf("\n")
}
