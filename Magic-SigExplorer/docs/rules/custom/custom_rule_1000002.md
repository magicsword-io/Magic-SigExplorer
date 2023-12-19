## ""Suspicious SharePoint API Endpoint Access""

**SID:** 1000002

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


- Value: "/_api/web/"
  
  



**Within:** 

**PCRE:** 

**Special Options:**


- http_uri



[*source*](https://github.com/magicsword-io/Magic-SigExplorer/tree/main/yaml/custom/custom_rule_1000002.yaml)