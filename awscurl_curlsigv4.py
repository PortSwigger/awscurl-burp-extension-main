from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from javax.swing import JMenuItem, JOptionPane
from java.util import ArrayList
from java.awt.event import ActionListener
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import json
import xml.etree.ElementTree as ET
import re

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # Set a combined extension name
        callbacks.setExtensionName("AWS Curl Commands")
        callbacks.registerContextMenuFactory(self)
        # For logging purposes (used in the SigV4 functionality)
        self._stdout = callbacks.getStdout()
        self._stdout.write("Loaded: AWS Curl Commands\n")
        return

    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        # Add menu item for awscurl command
        menu_items.add(JMenuItem("Copy as AWSCurl", 
                                  actionPerformed=lambda x: self.generate_awscurl_command(invocation)))
        # Add menu item for AWS SigV4 curl command
        menu_item_sigv4 = JMenuItem("Copy as cURL with AWS SigV4")
        menu_item_sigv4.addActionListener(CurlActionListener(self, invocation))
        menu_items.add(menu_item_sigv4)
        return menu_items

    def generate_awscurl_command(self, invocation):
        try:
            selected_messages = invocation.getSelectedMessages()
            if selected_messages and len(selected_messages) > 0:
                request_response = selected_messages[0]
                request_info = self._helpers.analyzeRequest(request_response)

                method = request_info.getMethod()
                url = str(request_info.getUrl())
                headers = request_info.getHeaders()
                body = self._helpers.bytesToString(request_response.getRequest()[request_info.getBodyOffset():])

                aws_service, aws_region = self.extract_aws_info(headers)
                content_type = self.get_content_type(headers)

                # Process body based on content type (JSON, XML, GraphQL, or raw)
                processed_body = self.process_body(body, content_type)

                awscurl_command = ["awscurl --service {} --region {}".format(aws_service, aws_region)]
                awscurl_command.append("-X {}".format(method))

                for header in headers[1:]:
                    if not header.lower().startswith("authorization"):
                        awscurl_command.append("-H '{}'".format(header))

                if processed_body:
                    escaped_body = processed_body.replace("'", "'\\''")
                    awscurl_command.append("-d '{}'".format(escaped_body))

                awscurl_command.append("'{}'".format(url))

                final_command = " \\\n".join(awscurl_command)

                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(StringSelection(final_command), None)

                self._callbacks.printOutput("awscurl command copied to clipboard:\n" + final_command)
            else:
                self._callbacks.printError("No request selected")
        except Exception as e:
            self._callbacks.printError("Error generating awscurl command: " + str(e))

    def extract_aws_info(self, headers):
        for header in headers:
            if header.lower().startswith("authorization:"):
                auth_parts = header.split()
                for part in auth_parts:
                    if part.startswith("Credential="):
                        credential_parts = part.split('/')
                        if len(credential_parts) >= 5:
                            return credential_parts[3], credential_parts[2]  # Service and Region
        return "unknown", "unknown"

    def get_content_type(self, headers):
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":", 1)[1].strip().lower()
        return "unknown"

    def process_body(self, body, content_type):
        try:
            if "application/json" in content_type:
                json_obj = json.loads(body)
                return json.dumps(json_obj, indent=4)
            elif "application/xml" in content_type or "text/xml" in content_type:
                root = ET.fromstring(body)
                return ET.tostring(root, encoding="unicode", method="xml")
            elif "application/graphql" in content_type or "graphql" in content_type:
                return body.strip()
            else:
                return body.strip()
        except Exception as e:
            self._callbacks.printError("Error processing body: " + str(e))
            return body.strip()

class CurlActionListener(ActionListener):
    def __init__(self, extender, invocation):
        self._extender = extender
        self._invocation = invocation

    def actionPerformed(self, event):
        messages = self._invocation.getSelectedMessages()
        if not messages or len(messages) == 0:
            self._log("No message selected.")
            return

        messageInfo = messages[0]
        request = messageInfo.getRequest()
        httpService = messageInfo.getHttpService()
        analyzedRequest = self._extender._helpers.analyzeRequest(httpService, request)
        headers = analyzedRequest.getHeaders()

        # 1. URL as captured
        url = analyzedRequest.getUrl().toString()

        # 2. Determine region and service from the host
        host = httpService.getHost()
        region = "us-east-1"
        service = ""
        if "execute-api" in host:
            service = "execute-api"
            m = re.search(r"\.execute-api\.([^.]+)\.amazonaws\.com", host)
            if m:
                region = m.group(1)
        else:
            m = re.search(r"^([^-\.]+)(?:-[^\.]+)?\.([^.]+)\.amazonaws\.com$", host)
            if m:
                service = m.group(1)
                region = m.group(2)
            else:
                service = "execute-api"

        # 3. Build the curl command lines
        lines = []
        lines.append('curl "' + url + '"')
        lines.append('    --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY"')
        lines.append('    -H "x-amz-security-token: $AWS_SESSION_TOKEN"')
        lines.append('    --aws-sigv4 "aws:amz:' + region + ':' + service + '"')

        # Append remaining headers (skip host, authorization, x-amz-date, and x-amz-security-token)
        for header in headers[1:]:
            lower = header.lower()
            if (lower.startswith("host:") or lower.startswith("authorization:") or 
                lower.startswith("x-amz-date:") or lower.startswith("x-amz-security-token:")):
                continue
            lines.append("    -H '" + header + "'")

        # 4. Append request body if present
        body_offset = analyzedRequest.getBodyOffset()
        request_bytes = request
        if len(request_bytes) > body_offset:
            body = self._extender._helpers.bytesToString(request_bytes[body_offset:])
            if body:
                body = body.replace("'", "'\\''")
                lines.append("    --data '" + body + "'")

        # Format command with backslashes on every line except the last
        final_lines = []
        for i, line in enumerate(lines):
            if i < len(lines) - 1:
                final_lines.append(line + " \\")
            else:
                final_lines.append(line)
        curlCommand = "\n".join(final_lines)
        self.copyToClipboard(curlCommand)

    def copyToClipboard(self, text):
        try:
            selection = StringSelection(text)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(selection, None)
            self._log("Curl command copied to clipboard.")
        except Exception as e:
            self._log("Error copying to clipboard: " + str(e))
            JOptionPane.showMessageDialog(None, text, "Curl Command", JOptionPane.INFORMATION_MESSAGE)

    def _log(self, message):
        try:
            self._extender._stdout.write(message + "\n")
        except Exception:
            pass
