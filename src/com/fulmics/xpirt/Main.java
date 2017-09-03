/*
 * Copyright (C) 2017, Andrei Conache <conache.and@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.fulmics.xpirt;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {
    private static final boolean DEBUG = false;

    private static final String VERSION = "1.0";
    private static final String ANDROID_MANIFEST_FILENAME = "AndroidManifest.xml";

    public static void main(String[] args) {
        System.out.println("GetApkSignInfo v" + VERSION + " - get useful signature information out of apk/jar files");
        System.out.println("Copyright(c) 2017, Andrei Conache <conache.and@gmail.com>\n");

        if (args.length < 1 || args.length > 1) {
            System.out.println("Usage: java -jar GetApkSignInfo.jar <apk|jar>");
            System.exit(-1);
        }

        // First argument is apk path
        final String apkPath = args[0];

        // Check if file exists
        File apkFile = new File(apkPath);
        if (!apkFile.exists()) {
            System.out.println("File " + apkFile.getAbsolutePath() + " does not exist; ignoring!");
            System.exit(-1);
        }

        System.out.println("File: " + apkPath);

        // Verify certificates
        Certificate[] certs = null;
        try {
            JarFile jarFile = new JarFile(apkPath);

            // Always verify manifest, regardless of source
            final JarEntry manifestEntry = jarFile.getJarEntry(ANDROID_MANIFEST_FILENAME);
            if (manifestEntry == null) {
                System.err.println("Package " + apkPath + " has no manifest");
                System.exit(-1);
            }

            final List<JarEntry> toVerify = new ArrayList<>();
            toVerify.add(manifestEntry);

            // Verify all content
            Enumeration entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry jarEntry = (JarEntry) entries.nextElement();

                if (jarEntry.isDirectory()) continue;
                if (jarEntry.getName().startsWith("META-INF/")) continue;
                if (jarEntry.getName().equals(ANDROID_MANIFEST_FILENAME)) continue;

                toVerify.add(jarEntry);
            }

            // Verify that entries are signed consistently with the first entry
            // we encountered. Note that for splits, certificates may have
            // already been populated during an earlier parse of a base APK.
            for (JarEntry jarEntry : toVerify) {
                final Certificate[] entryCerts = loadCertificates(jarFile, jarEntry);
                if (entryCerts == null) {
                    System.err.println("Failed to collect certificates from " + apkPath + ", entryCerts is null");
                    jarFile.close();
                    return;
                }
                if (entryCerts.length == 0) {
                    System.err.println("Package " + apkPath + " has no certificates at entry " + jarEntry.getName());
                    jarFile.close();
                    return;
                }

                if (certs == null) {
                    certs = entryCerts;
                } else {
                    // Ensure all certificates match
                    for (Certificate cert : certs) {
                        boolean found = false;
                        for (Certificate localCert : entryCerts) {
                            if (cert != null && cert.equals(localCert)) {
                                found = true;
                                break;
                            }
                        }
                        if (!found || certs.length != entryCerts.length) {
                            System.err.println("Package has mismatched certificates at entry "
                                    + jarEntry.getName() + "; ignoring!");
                            jarFile.close();
                            return;
                        }
                    }
                }
            }

            // Close file
            jarFile.close();

            if (certs == null) {
                System.err.println("Package has no certificates; ignoring!");
                System.exit(-1);
            }

            // Get signature information
            int certsSize = certs.length;
            if (certsSize > 0) {
                for (int i = 0; i < certsSize; i++) {
                    X509Certificate x509cert = (X509Certificate) certs[i];

                    String certType = x509cert.getType();
                    String version = String.valueOf(x509cert.getVersion());
                    String serialNumber = String.valueOf(x509cert.getSerialNumber());
                    String certOwner = x509cert.getSubjectDN().getName();
                    String certIssuer = x509cert.getIssuerDN().getName();
                    if (certIssuer.equals(certOwner)) certIssuer = "Self-signed by Certificate Owner";
                    String validity = x509cert.getNotBefore().toString() + " -> " + x509cert.getNotAfter().toString();
                    String signatureAlgorithm = x509cert.getSigAlgName();
                    String hashCode = "0x" + Integer.toHexString(x509cert.hashCode()) + " ("
                            + String.valueOf(x509cert.hashCode()) + ")";
                    String charSignature = "\n" + new String(convertToChars(x509cert.getEncoded()));

                    System.out.println("\n"
                            + "CERT #" + i + "\n"
                            + "Cert Type: " + certType + "\n"
                            + "Version: " + version + "\n"
                            + "Serial Number: " + serialNumber + "\n"
                            + "Cert Owner: " + certOwner + "\n"
                            + "Issuer: " + certIssuer + "\n"
                            + "Validity: " + validity + "\n"
                            + "Signature Algorithm: " + signatureAlgorithm + "\n"
                            + "Hash Code: " + hashCode + "\n"
                            + "Signature Bits: " + charSignature);
                }
            } else {
                System.err.println("Package has no certificates; ignoring!");
            }
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | RuntimeException ex) {
            System.err.println("Exception reading " + apkPath);

            if (DEBUG) {
                System.err.println("Exception: " + ex.getMessage());
            }
        }
    }

    private static Certificate[] loadCertificates(JarFile jarFile, JarEntry jarEntry) {
        InputStream is;
        try {
            // We must read the stream for the JarEntry to retrieve
            // its certificates.
            is = jarFile.getInputStream(jarEntry);
            readFullyIgnoringContents(is);

            return jarEntry.getCertificates();
        } catch (IOException | RuntimeException e) {
            System.err.println("Failed reading " + jarEntry.getName() + " in " + jarFile);
            System.exit(-1);
        }
        return null;
    }

    private static AtomicReference<byte[]> sBuffer = new AtomicReference<>();
    private static long readFullyIgnoringContents(InputStream in) throws IOException {
        byte[] buffer = sBuffer.getAndSet(null);
        if (buffer == null) {
            buffer = new byte[4096];
        }

        int n;
        int count = 0;
        while ((n = in.read(buffer, 0, buffer.length)) != -1) {
            count += n;
        }

        sBuffer.set(buffer);
        return count;
    }

    private static char[] convertToChars(byte[] signature) {
        final int N = signature.length;
        final int N2 = N * 2;
        char[] text = new char[N2];

        for (int j = 0; j < N; j++) {
            byte v = signature[j];
            int d = (v >> 4) & 0xf;
            text[j * 2] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
            d = v & 0xf;
            text[j * 2 + 1] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
        }

        return text;
    }
}
