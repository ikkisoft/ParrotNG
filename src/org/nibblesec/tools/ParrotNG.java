/*
 * ParrotNG.java
 *
 * Copyright (c) 2014 Mauro Gentile, Luca Carettoni
 *
 * A command-line tool to identify Flex applications vulnerable to CVE-2011-2461 (APSB11-25)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version. This program is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY.
 *
 */
package org.nibblesec.tools;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

public class ParrotNG {

    private static File swfInput;
    private static ArrayList samples;

    public static void main(String[] args) {

        System.out.println(":: ParrotNG v0.2 ::");

        if (args.length < 1) {
            printHelp();
        }

        swfInput = new File(args[0]);

        if (swfInput.isDirectory()) {
            //Create samples File collection
            File[] matchingFiles = swfInput.listFiles(new FilenameFilter() {
                public boolean accept(File dir, String name) {
                    return name.endsWith(".swf");
                }
            });
            samples = new ArrayList(Arrays.asList(matchingFiles));
        } else {
            //Single file only
            samples = new ArrayList();
            samples.add((File) swfInput);
        }

        Iterator samplesIte = samples.iterator();
        while (samplesIte.hasNext()) {
            File singleSample = (File) samplesIte.next();
            if (!singleSample.exists()) {
                System.out.println("[!] SWF file does not exist: " + args[0]);
                System.exit(-1);
            }
            System.out.println("\n[*] Analyzing " + singleSample.getAbsolutePath());
            String logDump = swfDump(singleSample);
            isVulnerable(logDump);
        }
    }

    private static void printHelp() {

        System.out.println("\nParrotNG is a command-line tool capable of identifying\n"
                + "Flex applications (SWF) vulnerable to CVE-2011-2461\n");
        System.out.println("Usage: java -jar parrotng.jar <SWF File | Directory>");
        System.exit(0);
    }

    public static String swfDump(File swfSample) {

        //Redirect StdOut to String
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        //Execute swfdump -abc <swf file> using instrumentation
        try {
            Class<?> cls = Class.forName("flash.swf.tools.SwfxPrinter");
            Method meth = cls.getMethod("main", String[].class);
            String[] args = {"-abc", swfSample.getAbsolutePath()};
            meth.invoke(null, (Object) args);
        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException ex) {
            System.out.println("[!] SWFDump Exception: " + ex.getMessage());
        }

        //Revert StdOut redirection
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));

        return baos.toString();
    }

    public static boolean isVulnerable(String logDump) {

        if (isFlex(logDump)) {
            System.out.println("[*] Flex application detected");

            if (containsMload(logDump)) {
                System.out.println("[*] It contains ModuleInfo::load");
                String block = getMIlcontent(logDump);

                if (block != null && containsVuln(block)) {
                    return true;
                } else {
                    System.out.println("[*]=> NOT vulnerable");
                    return false;
                }
            } else {
                System.out.println("[!] It does NOT contain ModuleInfo::load");
                if (vulnSdkV(logDump)) {
                    return true;
                } else {
                    return false;
                }
            }
        } else {
            System.out.println("[!] NOT a Flex application");
            return false;
        }
    }

    private static boolean vulnSdkV(String logDump) {

        String version = null;

        try {
            BufferedReader br = new BufferedReader(new StringReader(logDump));
            String line = br.readLine();

            while (line != null) {
                if (line.contains("<ProductInfo ")) {
                    int j = line.indexOf("version='");

                    if (j != -1) {
                        int y = line.substring(j + 9).indexOf("'");

                        if (y != -1) {
                            version = line.substring(j + 9, j + 9 + y);
                            System.out.println("[*] It is was compiled with Flex SDK " + version);

                            if (vulnerableSDKVersion(version.replace(".", ""))) {
                                System.out.println("[*]=> LIKELY vulnerable. Proceeding with testing...");
                                return true;
                            } else {
                                System.out.println("[*]=> Code pattern NOT found. Not vulnerable");
                                return false;
                            }
                        } else {
                            return errSDK();
                        }
                    } else {
                        return errSDK();
                    }
                }
                line = br.readLine();
            }
            br.close();
        } catch (IOException ex) {
            System.out.println("[!] SDK Version Check IOException:" + ex.getMessage());
        }
        return errSDK();
    }

    private static boolean errSDK() {
        System.out.println("[!] Unable to identify the SDK version");
        return false;
    }

    private static boolean vulnerableSDKVersion(String version) {

        int[] ver = new int[3];

        for (int i = 0; i < 3; i++) {
            try {
                ver[i] = (version.length() <= i) ? 0 : Integer.parseInt("" + version.charAt(i));
            } catch (NumberFormatException e) {
                return errSDK();
            }
        }

        // 3.X and 4.X (till 4.5.1) versions should be vulnerable
        if (ver[0] < 3) {
            return false;
        } else if (ver[0] == 3) {
            return true;
        } else if (ver[0] == 4) {
            if (ver[1] < 4) {
                return true;
            } else if (ver[1] == 5 && ver[2] <= 1) {
                return true;
            }
        }
        // versions >= 5
        return false;
    }

    private static boolean containsVuln(String block) {

        if (block.contains("        getproperty   	:currentDomain" + System.lineSeparator()
                + "        setproperty   	:securityDomain")) {
            System.out.println("[*] It was compiled with an old SDK version");

            if (!block.contains("        pushfalse     	" + System.lineSeparator()
                    + "        pushtrue")) {
                System.out.println("[*] It was not patched");
                System.out.println("[*]=> VULNERABLE!");
                return true;
            } else {
                System.out.println("[*]=> It was PATCHED");
                return false;
            }
        } else {
            System.out.println("[*] It was compiled with a 'recent' Flex SDK");
            return false;
        }
    }

    private static String getMIlcontent(String logDump) {

        StringBuilder sb = null;
        try {
            BufferedReader br = new BufferedReader(new StringReader(logDump));
            String line = br.readLine();
            sb = new StringBuilder();
            boolean inBlock = false;

            while (line != null) {
                if (line.contains("ModuleInfo:::load(")) {
                    inBlock = true;
                    sb.append(line);
                    sb.append(System.lineSeparator());
                } else if (line.contains("0 Traits Entries") && inBlock) {
                    sb.append(line);
                    sb.append(System.lineSeparator());
                    break;
                } else if (inBlock) {
                    sb.append(line);
                    sb.append(System.lineSeparator());
                }

                line = br.readLine();
            }

            br.close();
        } catch (IOException ex) {
            System.out.println("[!] getMIlcontent Exception:" + ex.getMessage());
        }
        return (sb == null) ? null : sb.toString();
    }

    private static boolean containsMload(String logDump) {
        return logDump.contains("ModuleInfo:::load(");
    }

    private static boolean isFlex(String logDump) {
        return logDump.contains("resourceModuleURLs");
    }
}