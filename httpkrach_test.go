package krach

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/connctd/noise"
	"github.com/smolcert/smolcert"
)

func ExampleHTTPServer() {
	serverAddr := "127.0.0.1:8099"
	rootCert, rootKey, err := smolcert.SelfSignedCertificate("example root CA",
		time.Time{}, time.Time{}, nil)
	if err != nil {
		panic(err)
	}

	serverCert, serverKey, err := smolcert.SignedCertificate("example server cert",
		2, time.Time{}, time.Time{}, nil, rootKey, rootCert.Subject)
	if err != nil {
		panic(err)
	}

	l, err := Listen(serverAddr, &ConnectionConfig{
		StaticKey: noise.NewPrivateSmolIdentity(serverCert, serverKey),
	}, smolcert.NewCertPool(rootCert))
	if err != nil {
		panic(err)
	}

	doneChan := make(chan struct{}, 1)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello Krach"))
		}))

		http.Serve(l, mux)
		<-doneChan
	}()

	clientCert, clientKey, err := smolcert.SignedCertificate("example client", 3, time.Time{},
		time.Time{}, nil, rootKey, rootCert.Subject)
	if err != nil {
		panic(err)
	}

	krachTransport := http.Transport{}
	krachTransport.Dial = func(network, addr string) (net.Conn, error) {
		return Dial(addr, &ConnectionConfig{
			StaticKey: noise.NewPrivateSmolIdentity(clientCert, clientKey),
		}, smolcert.NewCertPool(rootCert))
	}
	client := &http.Client{
		Transport: &krachTransport,
	}

	resp, err := client.Get(fmt.Sprintf("http://%s/", serverAddr))
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	doneChan <- struct{}{}
	fmt.Println(string(body))
	// Output: Hello Krach
}
