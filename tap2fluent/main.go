/*
 * Copyright (c) 2018 Manabu Sonoda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/mimuret/tap2fluent"
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

var (
	flagReadSock    = flag.String("u", "/var/run/unbound/dnstap.sock", "read dnstap payloads from unix socket")
	flagFluentdHost = flag.String("h", "localhost", "fluentd host")
	flagFluentdPort = flag.Int("p", 24224, "fluentd port")
	flagFluentdTag  = flag.String("t", "dnstap.%i", "fluentd tag")
	flagLogLevel    = flag.String("d", "info", "log level(debug,info,warn,error,fatal)")
	flagIPv4Mask    = flag.Int("4", 24, "IPv4 mask")
	flagIPv6Mask    = flag.Int("6", 48, "IPv6 mask")
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]...\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var err error
	var i dnstap.Input

	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Usage = usage

	flag.Parse()
	// set log level
	switch *flagLogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	default:
		usage()
		os.Exit(1)
	}
	if *flagIPv4Mask > 32 {
		log.Fatal("IPv4 mask range 0 to 32")
	}
	if *flagIPv6Mask > 128 {
		log.Fatal("IPv4 mask range 0 to 128")
	}

	output := make(chan []byte, 10000)
	ctx, cancel := context.WithCancel(context.Background())
	o, err := tap2fluent.NewDnstapFluentdOutput(*flagFluentdHost, *flagFluentdTag, *flagFluentdPort, *flagIPv4Mask, *flagIPv6Mask)
	if err != nil {
		log.Fatal(err)
	}
	go o.Start(ctx, output)

	if *flagReadSock != "" {
		i, err = dnstap.NewFrameStreamSockInputFromPath(*flagReadSock)
		if err != nil {
			log.Fatalf("dnstap: Failed to open input socket: %s\n", err)
		}
		log.Infof("dnstap: opened input socket %s\n", *flagReadSock)
	}
	i.ReadInto(output)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	select {
	case <-sigCh:
		cancel()
	}
	// Wait for input loop to finish.
	close(output)
}
