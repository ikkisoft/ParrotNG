--------------------------------------------------
         	  ParrotNG         
--------------------------------------------------
         	Version 0.2
--------------------------------------------------

Copyright (c) 2014 Mauro Gentile, Luca Carettoni

--------------------------------------------------
1.  INTRODUCTION
--------------------------------------------------

ParrotNG is a tool capable of identifying Adobe Flex 
applications (SWF) vulnerable to CVE-2011-2461. 

https://www.adobe.com/support/security/bulletins/apsb11-25.html
http://helpx.adobe.com/flash-builder/kb/flex-security-issue-apsb11-25.html

ParrotNG comes in two flavors:
- A command line tool
- A custom scanner check for Burp Suite Professional

--------------------------------------------------
2.  USAGE
--------------------------------------------------

To run ParrotNG from command line, use the following command:

java -jar parrotng.jar <SWF File | Directory>

To use ParrotNG, load the extension in Burp Suite (Professional Edition only)
and simply perform a Passive Scan.

--------------------------------------------------
3.  DEPENDENCIES
--------------------------------------------------

(a). Adobe ActionScript Compiler - asc.jar

(b). Apache Flex SDK (SWF Dump) - swfdump.jar

(c). Apache Flex SDK (SWF Kit) - swfutils.jar

These libraries have been included as provided.


