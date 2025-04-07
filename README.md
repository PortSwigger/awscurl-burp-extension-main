# AWSCurl/Curl With SigV4 BurpExtension
Burp Extension to create AWS Curl commands or cURL with SigV4 from an API

Simple right-click functionality to bring up the extension contenxt menu and select the extension. The awscurl command or curl with sigv4 will be copied to clipboard.


![2025-04-07_09-35](https://github.com/user-attachments/assets/09e9b3d2-2a3b-4edd-a08e-d82ce338060a)

AWS cURL
```
awscurl --service <service> --region us-east-1 \
    -X GET \
    -H 'Host: <host>' \
    -H 'Accept-Encoding: gzip, deflate, br' \
    -H 'User-Agent: <User-Agent>' \
    -H 'X-Amz-Date: <date>' \
    -H 'X-Amz-Security-Token: <Token>' \
    -d '{<data>}' \
    '<Endpoint-URL>'
```

cURL with SigV4
```
curl "https://endpoint" \
    --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
    -H "x-amz-security-token: $AWS_SESSION_TOKEN" \
    --aws-sigv4 "aws:amz:<region>:<service>" \
    -H 'User-Agent: <User-Agent>' \
    -H 'Accept: application/json,' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    -H 'Accept-Encoding: gzip, deflate, br' \
    -H 'Content-Type: application/json' \
    -H 'Origin: *' \
    -H 'Content-Length: 457' \
    --data '{"<data>"}'
```
