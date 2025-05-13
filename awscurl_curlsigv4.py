# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JOptionPane
from java.util import ArrayList
from java.awt.event import ActionListener
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import json
import xml.etree.ElementTree as ET
import re

def getBurpFrame():
    from javax.swing import JFrame
    for frame in JFrame.getFrames():
        if "Burp Suite" in frame.getTitle():
            return frame
    return None

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("AWS Curl Commands")
        callbacks.registerContextMenuFactory(self)
        self._stdout = callbacks.getStdout()
        self._stdout.write("Loaded: AWS Curl Commands\n")

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages or len(messages) != 1:
            return None

        msg = messages[0]
        svc = msg.getHttpService()
        req = msg.getRequest()
        if svc is None or req is None or len(req) == 0:
            return None

        menu_items = ArrayList()
        awscurl_item = JMenuItem("Copy as awscURL Command")
        awscurl_item.addActionListener(AwscurlActionListener(self, invocation))
        menu_items.add(awscurl_item)

        sigv4_item = JMenuItem("Copy as cURL Command with AWS SigV4")
        sigv4_item.addActionListener(CurlActionListener(self, invocation))
        menu_items.add(sigv4_item)

        return menu_items

    def generate_awscurl_command(self, invocation):
        try:
            rr   = invocation.getSelectedMessages()[0]
            info = self._helpers.analyzeRequest(rr)
            method  = info.getMethod()
            url     = str(info.getUrl())
            headers = info.getHeaders()
            body    = self._helpers.bytesToString(rr.getRequest()[info.getBodyOffset():])

            svc, region = self._extract_aws_info(headers)
            ctype       = self._get_content_type(headers)
            payload     = self._process_body(body, ctype)

            parts = [
                "awscurl --service {} --region {}".format(svc, region),
                "-X {}".format(method)
            ]
            for h in headers[1:]:
                if not h.lower().startswith("authorization"):
                    parts.append("-H '{}'".format(h))

            if payload:
                escaped = payload.replace("'", "'\\''")
                parts.append("-d '{}'".format(escaped))

            parts.append("'{}'".format(url))
            cmd = " \\\n".join(parts)

            Toolkit.getDefaultToolkit().getSystemClipboard()\
                   .setContents(StringSelection(cmd), None)
            self._callbacks.printOutput("awscurl command copied:\n" + cmd)

        except Exception as e:
            self._callbacks.printError("Error generating awscurl: " + str(e))

    def _extract_aws_info(self, headers):
        for h in headers:
            if h.lower().startswith("authorization:"):
                for part in h.split():
                    if part.startswith("Credential="):
                        segs = part.split('/')
                        if len(segs) >= 5:
                            return segs[3], segs[2]
        return "unknown", "unknown"

    def _get_content_type(self, headers):
        for h in headers:
            if h.lower().startswith("content-type:"):
                return h.split(":",1)[1].strip().lower()
        return ""

    def _process_body(self, body, ctype):
        try:
            if "application/json" in ctype:
                obj = json.loads(body)
                return json.dumps(obj, indent=4)
            if "xml" in ctype:
                root = ET.fromstring(body)
                return ET.tostring(root, encoding="unicode", method="xml")
            return body.strip()
        except:
            return body.strip()

class AwscurlActionListener(ActionListener):
    def __init__(self, extender, invocation):
        self._ext = extender
        self._inv = invocation

    def actionPerformed(self, event):
        self._ext.generate_awscurl_command(self._inv)

class CurlActionListener(ActionListener):
    def __init__(self, extender, invocation):
        self._ext = extender
        self._inv = invocation

    def actionPerformed(self, event):
        msg = self._inv.getSelectedMessages()[0]
        req = msg.getRequest()
        svc = msg.getHttpService()
        info = self._ext._helpers.analyzeRequest(svc, req)
        headers = info.getHeaders()
        url = info.getUrl().toString()

        host = svc.getHost()
        region = "us-east-1"
        service = ""
        if "execute-api" in host:
            service = "execute-api"
            m = re.search(r"\.execute-api\.([^.]+)\.amazonaws\.com", host)
            if m: region = m.group(1)
        else:
            m2 = re.match(r"^([^-\.]+)(?:-[^\.]+)?\.([^.]+)\.amazonaws\.com$", host)
            if m2:
                service, region = m2.group(1), m2.group(2)
            else:
                service = "execute-api"

        lines = [
            'curl "{}"'.format(url),
            '    --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY"',
            '    -H "x-amz-security-token: $AWS_SESSION_TOKEN"',
            '    --aws-sigv4 "aws:amz:{}:{}"'.format(region, service)
        ]
        for h in headers[1:]:
            low = h.lower()
            if low.startswith(("host:", "authorization:", "x-amz-date:", "x-amz-security-token:")):
                continue
            lines.append("    -H '{}'".format(h))

        body_offset = info.getBodyOffset()
        req_bytes = req
        if len(req_bytes) > body_offset:
            b = self._ext._helpers.bytesToString(req_bytes[body_offset:])
            if b:
                lines.append("    --data '{}'".format(b.replace("'", "'\\''")))

        cmd = "\n".join(l + " \\" for l in lines[:-1]) + "\n" + lines[-1]
        try:
            Toolkit.getDefaultToolkit().getSystemClipboard()\
                   .setContents(StringSelection(cmd), None)
            self._ext._stdout.write("SigV4 curl command copied\n")
        except Exception:
            parent = getBurpFrame()
            JOptionPane.showMessageDialog(parent, cmd, "Curl Command", JOptionPane.INFORMATION_MESSAGE)
