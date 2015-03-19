/*
 * BurpExtender.java
 *
 * Copyright (c) 2014 Mauro Gentile, Luca Carettoni
 *
 * A custom scanner check for Burp Suite Pro to identify Flex applications vulnerable to CVE-2011-2461 (APSB11-25)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version. This program is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY.
 *
 */
package burp;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.nibblesec.tools.ParrotNG.swfDump;
import static org.nibblesec.tools.ParrotNG.isVulnerable;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {

        this.callbacks = ibec;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("ParrotNG for Burp Suite Pro");
        callbacks.registerScannerCheck(this);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse ihrr) {

        // Look for .SWF files
        if (ihrr.getUrl().getPath().toLowerCase().endsWith(".swf")) {

            // Download the file in Burp's temporary directory
            byte[] swfFile = getBody(ihrr.getResponse());
            Path tmpFile = null;

            try {
                //Save the SWF file as a temporary file
                tmpFile = Files.createTempFile("parrotNG_", ".swf");
                tmpFile.toFile().deleteOnExit();
                FileOutputStream fileOutStream = new FileOutputStream(tmpFile.toFile());
                fileOutStream.write(swfFile);
                fileOutStream.close();
            } catch (IOException ex) {
                System.out.println("[!] ParrotNG Exception: TmpFile IOException");
                ex.printStackTrace();
            }

            // Scan using ParrotNG
            callbacks.issueAlert("Analyzing '" + ihrr.getUrl() + "'");
            System.out.println("[*] Analyzing '" + ihrr.getUrl() + "'");
            if (tmpFile != null) { 
                String logDump = swfDump(tmpFile.toFile());
                if (isVulnerable(logDump)) {

                    // If vulnerable, report the vulnerability
                    List<IScanIssue> issues = new ArrayList<>(1);
                    issues.add(new CVE20112461Issue(ihrr));
                    return issues;
                }
            }
        } else {
            return null;
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse ihrr, IScannerInsertionPoint isip) {

        return null; //Passive scanner check only
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {

        if (existingIssue.getUrl().equals(newIssue.getUrl())) {
            return -1;
        } else {
            return 0;
        }
    }

    /*
     * Retrieve the HTTP message body from a request/response
     */
    public static byte[] getBody(byte[] request) {

        int offset = 0;
        byte[] body = null;

        for (int i = 0; i < request.length; i++) {
            if (i + 3 <= request.length) {
                if (request[i] == 13 && request[i + 1] == 10 && request[i + 2] == 13 && request[i + 3] == 10) {
                    offset = i + 4; //Got a \r\n\r\n
                }
            }
        }

        if (offset != 0 && offset < request.length) {
            body = new byte[request.length - offset];
            int cont = 0;
            for (int i = offset; i < request.length; i++) {
                body[cont] = request[i];
                cont++;
            }
        }
        return body;
    }
}

class CVE20112461Issue implements IScanIssue {

    private IHttpRequestResponse reqres;

    public CVE20112461Issue(IHttpRequestResponse reqres) {
        this.reqres = reqres;
    }

    @Override
    public String getHost() {
        return reqres.getHost();
    }

    @Override
    public int getPort() {
        return reqres.getPort();
    }

    @Override
    public String getProtocol() {
        return reqres.getProtocol();
    }

    @Override
    public URL getUrl() {
        return reqres.getUrl();
    }

    @Override
    public String getIssueName() {
        return "Adobe Flex resourceModuleURLs SOP Bypass (CVE-2011-2461)";
    }

    @Override
    public int getIssueType() {
        return 134217728; //See http://portswigger.net/burp/help/scanner_issuetypes.html
    }

    @Override
    public String getSeverity() {
        return "High";
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return "Starting from Flex version 3, Adobe introduced runtime localizations. A new component in the "
                + "Flex framework (ResourceManager) allows access to localized resources at runtime. "
                + "Any components that extend UIComponent, Formatter, or Validator have a ResourceManager"
                + "property, which lets the SWF file to access the singleton instance of the resource manager. "
                + "By using this new functionality, users can pass localization resources via a "
                + "resourceModuleURLs FlashVar, instead of embedding all resources within the main SWF.<br>"
                + "In Adobe Flex SDK between 3.x and 4.5.1, compiled SWF files do NOT properly validate the "
                + "security domain of the resource module, leading to same-origin requests and potentially Flash "
                + "XSS (in older versions of the Flash player). This vulnerability is tracked as CVE-2011-2461.";
    }

    @Override
    public String getRemediationBackground() {
        return "A few workarounds are possible:<b><ul>"
                + "<li> Recompile the vulnerable SWF file with the latest Apache Flex SDK, including static libraries</li>"
                + "<li> Patch the vulnerable SWF file with the official Adobe patch tool, as illustrated in the <a href=\"http://kb2.adobe.com/cps/915/cpsid_91544.html\">Adobe Tech Advisory<a/></li>"
                + "<li> If not used, delete the vulnerable SWF file</li></ul>";
    }

    @Override
    public String getIssueDetail() {
        return "Burp Scanner (ParrotNG extension) has identified the following vulnerable SWF file: <b>"
                + (reqres.getUrl().getPath().substring(reqres.getUrl().getPath().lastIndexOf("/")+1, reqres.getUrl().getPath().lastIndexOf(".")+4)).replace("<","&lt;").replace(">","&gt;") + "</b><br><br>"
                + "This Flex application is vulnerable to CVE-2011-2461. Hosting vulnerable "
                + "SWF files leads to an \"indirect\" SOP bypass in fully patched web browsers and plugins. "
                + "An attacker can inject a malicious localization resource using Flex's resourceModuleURLs FlashVar. "
                + "Since the malicious SWF inherits the security domain of the vulnerable SWF, it can "
                + "access HTTP responses from the victim's domain.";
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return null;
    }

    @Override
    public IHttpService getHttpService() {
        return reqres.getHttpService();
    }
}
