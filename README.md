# AWSCurlBurpExtension
Burp Extension to create AWS Curl commands from an API

Simple right-click functionality to bring up the extensioj contenxt menu and select the extension. The awscurl command will be copied to clipboard.

![awscurlextension](https://github.com/user-attachments/assets/c007916d-3dcc-4edd-8002-8278026fa4f2)


```
awscurl --service <service> --region us-east-1 \
-X GET \
-H 'Host: <host>' \
-H 'Accept-Encoding: gzip, deflate, br' \
-H 'User-Agent: <User-Agent>' \
-H 'X-Amz-Date: 20250331T152635Z' \
-H 'X-Amz-Security-Token: <Token>' \
'<Endpoint-URL>'
```
