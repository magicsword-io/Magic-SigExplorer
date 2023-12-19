## ""Potential SharePoint JWT Token Bypass Attempt (CVE-2023-29357)""

**SID:** 1000010

**Revision:** 1

**Class Type:** web-application-attack

**Metadata:** 

**Reference:** 


- [Link](https://github.com/Chocapikk/CVE-2023-29357)



**Protocol:** tcp

**Source Network:** $EXTERNAL_NET

**Source Port:** any

**Destination Network:** $HTTP_SERVERS

**Destination Port:** $HTTP_PORTS

**Flow:** established,to_server

**Contents:**


- Value: "/_api/web/siteusers"
  
  

- Value: "Authorization: Bearer "
  
  

- Value: "alg=none"
  
  



**Within:** 

**PCRE:** 

**Special Options:**


- http_uri

- http_header

- http_header



[*source*](https://github.com/magicsword-io/Magic-SigExplorer/tree/main/yaml/custom/custom_rule_1000010.yaml)