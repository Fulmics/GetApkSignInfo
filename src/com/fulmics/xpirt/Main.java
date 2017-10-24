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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
    private static final String VERSION = "2.0";
    private static final String ANDROID_MANIFEST_FILENAME = "AndroidManifest.xml";

    private static final boolean DEBUG = false;

    public static void main(String[] args) {
        // Print main information
        System.out.println("GetApkSignInfo v" + VERSION + " - get useful signature information out of apk/jar files");
        System.out.println("Copyright(c) 2017, Andrei Conache <conache.and@gmail.com>\n");

        String apkPath = null;
        if (args.length == 1) {
            // Accept first argument only
            apkPath = args[0];

            // Check if file exists
            File apkFile = new File(apkPath);
            if (!apkFile.exists() || !apkFile.canRead()) {
                System.err.println("Error: " + apkFile + " does not exists or cannot be read!");
                System.exit(1);
            }
        } else {
            System.out.println("Usage: java -jar GetApkSignInfo.jar <apk|jar>\r\n");
            System.exit(-1);
        }

        System.out.print("Analyzing " + apkPath + ", please wait...");

        // Verify certificates
        Certificate[] certs = null;
        try {
            JarFile jarFile = new JarFile(apkPath);

            // Always verify manifest, regardless of source
            final JarEntry manifestEntry = jarFile.getJarEntry(ANDROID_MANIFEST_FILENAME);
            if (manifestEntry == null) {
                System.err.println("Package " + apkPath + " has no manifest");
                System.exit(1);
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
                    System.exit(1);
                }
                if (entryCerts.length == 0) {
                    System.err.println("Package " + apkPath + " has no certificates at entry " + jarEntry.getName());
                    jarFile.close();
                    System.exit(1);
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
                            System.exit(1);
                        }
                    }
                }
            }

            // Close file
            jarFile.close();

            System.out.println(" verified successfully!\n");

            // Get signature information
            if (certs != null && certs.length > 0) {
                for (int i = 0; i < certs.length; i++) {
                    Certificate cert = certs[i];
                    String certType = cert.getType();

                    // Get certificate information
                    System.out.println("CERT #" + (i + 1));
                    System.out.println("Cert Type: " + certType);

                    if (certType.equals("X.509")) {
                        X509Certificate x509cert = (X509Certificate) cert;

                        System.out.println("Version: " + String.valueOf(x509cert.getVersion()));
                        System.out.println("Serial Number: " + String.valueOf(x509cert.getSerialNumber()));

                        String certOwner = x509cert.getSubjectDN().getName();
                        String certIssuer = x509cert.getIssuerDN().getName();
                        System.out.println("Cert Owner: " + x509cert.getSubjectDN().getName());
                        if (certIssuer.equals(certOwner)) certIssuer = "Self-signed by Certificate Owner";
                        System.out.println("Cert Issuer: " + certIssuer);

                        System.out.println("Validity: " + x509cert.getNotBefore().toString() + " -> "
                                + x509cert.getNotAfter().toString());
                        System.out.println("Signature Algorithm: " + x509cert.getSigAlgName());
                    }

                    System.out.println("Hash Code: 0x" + Integer.toHexString(cert.hashCode()) + " ("
                            + String.valueOf(cert.hashCode()) + ")\n");

                    // Get signature information
                    byte[] certEncoded = cert.getEncoded();
                    String md5Signature = calculateDigest(certEncoded,"MD5");
                    String sha1Signature = calculateDigest(certEncoded, "SHA1");
                    String charSignature = new String(bytesToChars(certEncoded));

                    System.out.println("Signature MD5: " + md5Signature);
                    System.out.println("Signature SHA1: " + sha1Signature);
                    System.out.println("Signature Bits: " + charSignature);

                    System.out.println("\nPublic Key: " + cert.getPublicKey().toString());
                }
            } else {
                System.err.println("Package has no certificates; ignoring!");
                System.exit(1);
            }
        } catch (CertificateEncodingException e) {
            System.err.println("Encoding exception " + e.getMessage());

            if (DEBUG) Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, e);
        } catch (IOException | RuntimeException e) {
            System.err.println("Exception reading " + apkPath);

            if (DEBUG) e.printStackTrace();
        }
    }

    private static Certificate[] loadCertificates(JarFile jarFile, JarEntry jarEntry) {
        InputStream is;
        try {
            // We must read the stream for the JarEntry to retrieve its certificates
            is = jarFile.getInputStream(jarEntry);
            readFullyIgnoringContents(is);

            return jarEntry.getCertificates();
        } catch (IOException | RuntimeException e) {
            System.err.println("Failed reading " + jarEntry.getName() + " in " + jarFile);

            if (DEBUG) e.printStackTrace();
            System.exit(1);
        }
        return null;
    }

    private static AtomicReference<byte[]> sBuffer = new AtomicReference<>();
    private static long readFullyIgnoringContents(InputStream in) throws IOException {
        byte[] buffer = sBuffer.getAndSet(null);
        if (buffer == null) buffer = new byte[4096];

        int n;
        int count = 0;
        while ((n = in.read(buffer, 0, buffer.length)) != -1) {
            count += n;
        }

        sBuffer.set(buffer);
        return count;
    }

    // Convert bytes to chars
    private static char[] bytesToChars(byte[] signature) {
        final int i = signature.length;
        final int j = i * 2;
        char[] text = new char[j];

        for (int k = 0; k < i; k++) {
            byte v = signature[k];
            int d = (v >> 4) & 0xf;
            text[k * 2] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
            d = v & 0xf;
            text[k * 2 + 1] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
        }
        return text;
    }

    // Calculate digest given algorithm
    private static String calculateDigest(byte[] signature, String algorithm) {
        String digest = "unknown";
        try
        {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            messageDigest.update(signature);
            digest = new String(bytesToChars(messageDigest.digest()));
        } catch (NoSuchAlgorithmException e) {
            if (DEBUG) e.printStackTrace();
        }
        return digest;
    }
}
