tap2fleunt is experimental implementation.
if you use production, see [dtap](https://github.com/mimuret/dtap)


# tap2fluent
Throw DNS Message into Elasticsearch via Fluentd.

## install tap2fluent
```
go get -u github.com/mimuret/tap2fluent/tap2fluent
```

## install elasticsearch template
```
curl -H "content-type: application/json" -XPOST http://localhost:9200/_template/dnstap -d "@misc/template.json"
```

## Enable forward your fluentd and throw into Elasticsearch.
```
<source>
  @type forward
  port 24224
  bind 0.0.0.0
</source>

<match dnstap.**>
  @type elasticsearch
  host localhost
  port 9200
  type_name dnstap
  request_timeout 15s
  include_tag_key true
  logstash_format true
  template_name dnstap
  logstash_prefix dnstap
  buffer_type file
  buffer_type file
  buffer_path /var/log/td-agent/tmp/out_elasticsearch.dnstap.buffer
  buffer_chunk_limit 8m
  reconnect_on_error true
</match>
```

## Unbound.conf
enable dnstap
```
dnstap:
	dnstap-enable: yes
	dnstap-socket-path: "/var/run/unbound/dnstap.sock"
	dnstap-send-identity: yes
	dnstap-send-version: yes
	dnstap-log-resolver-query-messages: yes
	dnstap-log-resolver-response-messages: yes
	dnstap-log-client-query-messages: yes
	dnstap-log-client-response-messages: yes
	dnstap-log-forwarder-query-messages: yes
	dnstap-log-forwarder-query-messages: yes
```

## run tap2fluent
```
sudo -u unbound tap2fluent -u /var/run/unbound/dnstap.sock -h your.fluentd.host.IP
```

