package main

import (
	"context"
	"fmt"
	utls "github.com/refraction-networking/utls"
	"rushClient/net/proxy"
	"rushClient/rush/net/http"
	"rushClient/rush/task"
)

func main() {
	rt := task.NewRoundTripper(context.Background(), proxy.Direct.DialContext, "tcp", utls.HelloChrome_Auto, func(_ uint8, _ uint) {})

	client := http.Client{Transport: rt}
	resp, err := client.Get("https://localhost")
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	fmt.Println(resp.Status)
}
