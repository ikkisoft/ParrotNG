# ParrotNG ![ParrotNG Logo](http://i.imgur.com/Ek8SGIit.png "ParrotNG Logo")

ParrotNG is a tool capable of identifying Adobe Flex applications (SWF) vulnerable to [CVE-2011-2461](https://www.adobe.com/support/security/bulletins/apsb11-25.html). For more details, please refer to the slides of our [Troopers 2015 talk](http://www.slideshare.net/ikkisoft/the-old-is-new-again-cve20112461-is-back).

Download the latest release from [HERE](https://github.com/ikkisoft/ParrotNG/releases).

##Features

* Written in Java, based on [swfdump](http://www.swftools.org/swfdump.html)
* One JAR, two flavors: command line utility and [Burp Pro](http://portswigger.net/burp/editions.html) Passive Scanner plugin 
* Detection of SWF files compiled with either a vulnerable Flex SDK version, patched by [Adobe's tool](http://helpx.adobe.com/flash-builder/kb/flex-security-issue-apsb11-25.html) or not affected

##How To Use - Command Line

1. Download the latest ParrotNG from the release page
2. Simply use the following command:
```
$ java -jar parrotng_v0.2.jar <SWF File | Directory>
```

![ParrotNG CmdLine](http://i.imgur.com/1JT4CtH.png "ParrotNGCmdLine")

##How To Use - Burp Pro Passive Scanner Plugin

1. Download the latest ParrotNG from the release page
2. Load Burp Suite Professional
3. From the _Extender_ tab in Burp Suite,  add [parrotng_v0.2.jar](https://github.com/ikkisoft/ParrotNG/releases) as a standard Java-based Burp Extension
4. Enable [Burp Scanner Passive Scanning](http://portswigger.net/burp/help/scanner_scanmodes.html)
5. Browse your target web application. All SWF files passing through Burp Suite are automatically analyzed  

![ParrotNG Burp](http://i.imgur.com/thAkkMB.png "ParrotNGBurp")


