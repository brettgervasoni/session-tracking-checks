# Checks for the presence of known session tracking sites
# Brett Gervasoni, NCC Group

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array

# sources from: https://gist.github.com/gunesacar/0c67b94ad415841cf3be6761714147ca
sources = [ 
"mc.yandex.ru",
"fullstory.com",
"d2oh4tlt9mrke9.cloudfront.net",
"ws.sessioncam.com",
"userreplay.net",
"script.hotjar.com",
"insights.hotjar.com",
"static.hotjar.com",
"clicktale.net",
"smartlook.com",
"decibelinsight.net",
"quantummetric.com",
"inspectlet.com",
"mouseflow.com",
"logrocket.com",
"salemove.com",
"d10lpsik1i8c69.cloudfront.net" ]

class BurpExtender(IBurpExtender, IScannerCheck):

    # implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Session Tracking Checks")

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)

    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets
    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    # IScannerCheck
    def doPassiveScan(self, baseRequestResponse):
        issues = []

        # check for matches
        matches = []
        for source in sources:
            matches = self._get_matches(baseRequestResponse.getResponse(), self._helpers.stringToBytes(source))

            if len(matches) > 0:
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                    "Session tracking include",
                    "Scripts were included from the following domain: " + source,
                    "The included scripts could be used to perform session replay attacks, and leak sensitive data.",
                    "Avoid using third party session replay analytic scripts.",
                    "Low", 
                    "Firm"))

        if (len(issues) == 0):
            return None

        #print("Found - "+str(self._helpers.analyzeRequest(baseRequestResponse).getUrl()))

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, background, remediationBackground, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._background = background
        self._remediationBackground = remediationBackground
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return self._background

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediationBackground

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService