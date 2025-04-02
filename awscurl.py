from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.util import ArrayList
import json
import xml.etree.ElementTree as ET

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Create awscurl Command")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        menu_items.add(JMenuItem("Create awscurl Command", 
                                 actionPerformed=lambda x: self.generate_awscurl_command(invocation)))
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

                # Process body based on content type
                processed_body = self.process_body(body, content_type)

                awscurl_command = ["awscurl --service {} --region {}".format(aws_service, aws_region)]
                awscurl_command.append("-X {}".format(method))

                for header in headers[1:]:  # Skip the first header (HTTP method)
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
        return "unknown", "unknown"  # Return "unknown" if info can't be determined

    def get_content_type(self, headers):
        for header in headers:
            if header.lower().startswith("content-type:"):
                return header.split(":")[1].strip().lower()
        return "unknown"

    def process_body(self, body, content_type):
        try:
            if "application/json" in content_type:
                # Pretty-print JSON body
                json_obj = json.loads(body)
                return json.dumps(json_obj, indent=4)
            elif "application/xml" in content_type or "text/xml" in content_type:
                # Pretty-print XML body
                root = ET.fromstring(body)
                return ET.tostring(root, encoding="unicode", method="xml")
            elif "application/graphql" in content_type or "graphql" in content_type:
                # Format GraphQL queries (if needed)
                return body.strip()  # GraphQL queries are typically already formatted
            else:
                # Return raw body for unsupported types
                return body.strip()
        except Exception as e:
            self._callbacks.printError("Error processing body: " + str(e))
            return body.strip()
