## ""Suspicious Base64 Pattern in HTTP Request""

**SID:** 1000004

**Revision:** 1

**Class Type:** web-application-attack

**Metadata:** 

**Reference:** 


**Protocol:** tcp

**Source Network:** $EXTERNAL_NET

**Source Port:** any

**Destination Network:** $HTTP_SERVERS

**Destination Port:** $HTTP_PORTS

**Flow:** established,to_server

**Contents:**


**Within:** 

**PCRE:** "/[a-zA-Z0-9\/\+=]{20,}/"

**Special Options:**


- http_client_body



[*source*](https://github.com/magicsword-io/Magic-SigExplorer/tree/main/yaml/custom/custom_rule_1000004.yaml)