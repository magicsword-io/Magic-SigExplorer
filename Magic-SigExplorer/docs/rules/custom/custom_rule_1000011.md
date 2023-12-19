## ""Access to SharePoint Current User API""

**SID:** 1000011

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


- Value: "/_api/web/currentuser"
  
  



**Within:** 

**PCRE:** 

**Special Options:**


- http_uri



[*source*](https://github.com/magicsword-io/Magic-SigExplorer/tree/main/yaml/custom/custom_rule_1000011.yaml)