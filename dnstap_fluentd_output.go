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

package tap2fluent

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/farsightsec/golang-framestream"
	"github.com/fluent/fluent-logger-golang/fluent"
	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
)

var hostname, nodename string
var names = map[int]string{
	2: "tld",
	3: "2ld",
	4: "3ld",
	5: "4ld",
}

func init() {
	hostname, _ = os.Hostname()
	nodename = strings.Split(hostname, ".")[0]
	if nodename == "" {
		nodename = "localhost"
	}
}

type DnstapFluentdOutput struct {
	wait     chan bool
	enc      *framestream.Encoder
	config   fluent.Config
	logger   *fluent.Fluent
	ipv4Mask net.IPMask
	ipv6Mask net.IPMask
	tag      string
}

func NewDnstapFluentdOutput(host, tag string, port, v4mask, v6mask int) (o *DnstapFluentdOutput, err error) {
	o = new(DnstapFluentdOutput)
	o.tag = tag
	o.ipv4Mask = net.CIDRMask(v4mask, 32)
	o.ipv6Mask = net.CIDRMask(v6mask, 128)
	o.config = fluent.Config{
		FluentHost: host,
		FluentPort: port,
		Async:      false,
	}
	o.logger, err = fluent.New(o.config)
	if err != nil {
		return
	}
	o.wait = make(chan bool)
	return
}

func (o *DnstapFluentdOutput) Start(ctx context.Context, output chan []byte) {
	log.Info("DnstapFluentdOutput: start fluentd output\n")
	for {
		select {
		case frame := <-output:
			o.output(frame)
		case <-ctx.Done():
			break
		}
	}
	close(o.wait)
}

func (o *DnstapFluentdOutput) output(frame []byte) {
	var dnsMessage []byte
	dt := &dnstap.Dnstap{}
	if err := proto.Unmarshal(frame, dt); err != nil {
		log.Debugf("DnstapFluentdOutput: proto.Unmarshal() failed: %s len=%d\n", err, len(frame))
		return
	}
	msg := dt.GetMessage()
	dnsMsg := dns.Msg{}
	if msg.GetQueryMessage != nil {
		dnsMessage = msg.GetQueryMessage()
	} else {
		dnsMessage = msg.GetResponseMessage()
	}
	if err := dnsMsg.Unpack(dnsMessage); err != nil {
		log.Debugf("DnstapFluentdOutput: can't parse dns message() failed: %s len: %d\n", err, len(frame))
		return
	}

	var data = map[string]interface{}{}
	switch msg.GetType() {
	case dnstap.Message_AUTH_QUERY, dnstap.Message_RESOLVER_QUERY,
		dnstap.Message_CLIENT_QUERY, dnstap.Message_FORWARDER_QUERY,
		dnstap.Message_STUB_QUERY, dnstap.Message_TOOL_QUERY:
		data["@timestamp"] = time.Unix(int64(msg.GetQueryTimeSec()), int64(msg.GetQueryTimeNsec())).Format(time.RFC3339Nano)
		data["identity"] = dt.GetIdentity()
		if len(msg.GetQueryAddress()) == 4 {
			data["query_address"] = net.IP(msg.GetQueryAddress()).Mask(o.ipv4Mask).String()
		} else {
			data["query_address"] = net.IP(msg.GetQueryAddress()).Mask(o.ipv6Mask).String()
		}
		data["query_port"] = msg.GetQueryPort()
	case dnstap.Message_AUTH_RESPONSE, dnstap.Message_RESOLVER_RESPONSE,
		dnstap.Message_CLIENT_RESPONSE, dnstap.Message_FORWARDER_RESPONSE,
		dnstap.Message_STUB_RESPONSE, dnstap.Message_TOOL_RESPONSE:
		data["@timestamp"] = time.Unix(int64(msg.GetResponseTimeSec()), int64(msg.GetResponseTimeNsec())).Format(time.RFC3339Nano)
		data["identity"] = dt.GetIdentity()
		if len(msg.GetResponseAddress()) == 4 {
			data["response_address"] = net.IP(msg.GetResponseAddress()).Mask(o.ipv4Mask).String()
		} else {
			data["response_address"] = net.IP(msg.GetResponseAddress()).Mask(o.ipv6Mask).String()
		}
		data["response_port"] = msg.GetResponsePort()
		data["response_zone"] = msg.GetQueryZone()
	}
	data["type"] = msg.GetType().String()
	data["socket_family"] = msg.GetSocketFamily().String()
	data["socket_protocol"] = msg.GetSocketProtocol().String()
	data["version"] = dt.GetVersion()
	data["extra"] = dt.GetExtra()
	data["qname"] = dnsMsg.Question[0].Name
	data["qclass"] = dns.ClassToString[dnsMsg.Question[0].Qclass]
	data["qtype"] = dns.TypeToString[dnsMsg.Question[0].Qtype]
	data["rcode"] = dns.RcodeToString[dnsMsg.Rcode]
	data["aa"] = dnsMsg.Authoritative
	data["tc"] = dnsMsg.Truncated
	data["rd"] = dnsMsg.RecursionDesired
	data["ra"] = dnsMsg.RecursionAvailable
	data["ad"] = dnsMsg.AuthenticatedData
	data["cd"] = dnsMsg.CheckingDisabled

	labels := strings.Split(dnsMsg.Question[0].Name, ".")
	labelsLen := len(labels)
	for i, n := range names {
		if labelsLen-i >= 0 {
			data[n] = strings.Join(labels[labelsLen-i:labelsLen-1], ".")
		} else {
			data[n] = dnsMsg.Question[0].Name
		}
	}
	tag := o.Tag(dt)
	if err := o.logger.Post(tag, data); err != nil {
		log.Warn("DnstapFluentdOutput: logger.Post() failed: %s %s\n", tag, err)
	}
}
func (o *DnstapFluentdOutput) Tag(dt *dnstap.Dnstap) string {
	identity := string(dt.Identity)
	if identity == "" {
		identity = nodename
	} else {
		identity = strings.Split(identity, ".")[0]
	}
	tag := strings.Replace(o.tag, "%i", identity, -1)
	tag = strings.Replace(tag, "%t", dt.GetType().String(), -1)

	return tag
}

func (o *DnstapFluentdOutput) Close() {
	o.logger.Close()
	<-o.wait
}
