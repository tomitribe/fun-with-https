/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.superbiz.tomcatssl;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

@WebServlet("/*")
public class CertInfoServlet extends HttpServlet {

    private static final String CERTS_CODE = "(X509Certificate[]) request.getAttribute(\"jakarta.servlet.request.X509Certificate\")";
    private static final String CERT = "certs[0]";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/plain");
        PrintWriter out = response.getWriter();

        // --- SSL/TLS Connection Properties ---
        out.println("=== SSL/TLS Connection Properties ===");
        out.println();

        print(out, "SSL_PROTOCOL",
                request.getAttribute("org.apache.tomcat.util.net.secure_protocol_version"),
                "(String) request.getAttribute(\"org.apache.tomcat.util.net.secure_protocol_version\")");

        print(out, "SSL_CIPHER",
                request.getAttribute("jakarta.servlet.request.cipher_suite"),
                "(String) request.getAttribute(\"jakarta.servlet.request.cipher_suite\")");

        print(out, "SSL_SESSION_ID",
                request.getAttribute("jakarta.servlet.request.ssl_session_id"),
                "(String) request.getAttribute(\"jakarta.servlet.request.ssl_session_id\")");

        print(out, "SSL_CIPHER_USEKEYSIZE",
                request.getAttribute("jakarta.servlet.request.key_size"),
                "(Integer) request.getAttribute(\"jakarta.servlet.request.key_size\")");

        // --- Client Certificate ---
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");

        out.println();
        out.println("=== Client Certificate ===");
        out.println();

        print(out, "X509Certificate[] certs",
                (certs == null ? "null" : certs.length + " certificate(s)"),
                CERTS_CODE);

        if (certs == null || certs.length == 0) {
            print(out, "SSL_CLIENT_VERIFY", "NONE",
                    "certs == null || certs.length == 0 ? \"NONE\" : \"SUCCESS\"");
            printRequestProperties(out, request);
            return;
        }

        print(out, "SSL_CLIENT_VERIFY", "SUCCESS",
                "certs != null && certs.length > 0 ? \"SUCCESS\" : \"NONE\"");

        X509Certificate clientCert = certs[0];

        // --- Subject DN ---
        out.println();
        out.println("=== Client Certificate - Subject ===");
        out.println();

        print(out, "SSL_CLIENT_S_DN",
                clientCert.getSubjectX500Principal().getName(),
                CERT + ".getSubjectX500Principal().getName()");

        printDNComponents(out, "SSL_CLIENT_S_DN",
                clientCert.getSubjectX500Principal().getName(),
                CERT + ".getSubjectX500Principal().getName()");

        // --- Issuer DN ---
        out.println();
        out.println("=== Client Certificate - Issuer ===");
        out.println();

        print(out, "SSL_CLIENT_I_DN",
                clientCert.getIssuerX500Principal().getName(),
                CERT + ".getIssuerX500Principal().getName()");

        printDNComponents(out, "SSL_CLIENT_I_DN",
                clientCert.getIssuerX500Principal().getName(),
                CERT + ".getIssuerX500Principal().getName()");

        // --- Validity ---
        out.println();
        out.println("=== Client Certificate - Validity ===");
        out.println();

        print(out, "SSL_CLIENT_V_START",
                clientCert.getNotBefore(),
                CERT + ".getNotBefore()");

        print(out, "SSL_CLIENT_V_END",
                clientCert.getNotAfter(),
                CERT + ".getNotAfter()");

        long remainMs = clientCert.getNotAfter().getTime() - System.currentTimeMillis();
        long remainDays = remainMs / (1000 * 60 * 60 * 24);
        print(out, "SSL_CLIENT_V_REMAIN",
                remainDays + "d",
                "(" + CERT + ".getNotAfter().getTime() - System.currentTimeMillis()) / 86400000");

        // --- Certificate Details ---
        out.println();
        out.println("=== Client Certificate - Details ===");
        out.println();

        print(out, "SSL_CLIENT_M_VERSION",
                clientCert.getVersion(),
                CERT + ".getVersion()");

        print(out, "SSL_CLIENT_M_SERIAL",
                clientCert.getSerialNumber().toString(16).toUpperCase(),
                CERT + ".getSerialNumber().toString(16).toUpperCase()");

        print(out, "SSL_CLIENT_A_SIG",
                clientCert.getSigAlgName(),
                CERT + ".getSigAlgName()");

        print(out, "SSL_CLIENT_A_KEY",
                clientCert.getPublicKey().getAlgorithm(),
                CERT + ".getPublicKey().getAlgorithm()");

        if (clientCert.getPublicKey() instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) clientCert.getPublicKey();
            print(out, "SSL_CLIENT_A_KEY_SIZE",
                    rsaKey.getModulus().bitLength(),
                    "((RSAPublicKey) " + CERT + ".getPublicKey()).getModulus().bitLength()");
        }

        // --- Fingerprints ---
        try {
            byte[] encoded = clientCert.getEncoded();
            out.println();
            out.println("=== Client Certificate - Fingerprints ===");
            out.println();

            print(out, "SSL_CLIENT_CERT_SHA1",
                    fingerprint(encoded, "SHA-1"),
                    "MessageDigest.getInstance(\"SHA-1\").digest(" + CERT + ".getEncoded())");

            print(out, "SSL_CLIENT_CERT_SHA256",
                    fingerprint(encoded, "SHA-256"),
                    "MessageDigest.getInstance(\"SHA-256\").digest(" + CERT + ".getEncoded())");

            print(out, "SSL_CLIENT_CERT_MD5",
                    fingerprint(encoded, "MD5"),
                    "MessageDigest.getInstance(\"MD5\").digest(" + CERT + ".getEncoded())");
        } catch (Exception e) {
            // skip fingerprints on error
        }

        // --- Subject Alternative Names ---
        try {
            Collection<List<?>> sans = clientCert.getSubjectAlternativeNames();
            if (sans != null && !sans.isEmpty()) {
                out.println();
                out.println("=== Client Certificate - Subject Alternative Names ===");
                out.println();
                for (List<?> san : sans) {
                    int type = (Integer) san.get(0);
                    print(out, "SSL_CLIENT_SAN_" + sanTypeName(type),
                            san.get(1),
                            CERT + ".getSubjectAlternativeNames() // type=" + type);
                }
            }
        } catch (Exception e) {
            // skip SANs on error
        }

        // --- PEM-encoded certificate ---
        try {
            out.println();
            out.println("=== Client Certificate - PEM ===");
            out.println();
            String pem = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(clientCert.getEncoded());
            print(out, "SSL_CLIENT_CERT", "\n-----BEGIN CERTIFICATE-----\n" + pem + "\n-----END CERTIFICATE-----",
                    "Base64.getMimeEncoder(64, \"\\n\".getBytes()).encodeToString(" + CERT + ".getEncoded())");
        } catch (CertificateEncodingException e) {
            print(out, "SSL_CLIENT_CERT", "<encoding error>",
                    CERT + ".getEncoded()");
        }

        // --- Certificate Chain ---
        if (certs.length > 1) {
            out.println();
            out.println("=== Certificate Chain ===");
            out.println();
            print(out, "SSL_CLIENT_CHAIN_SIZE", certs.length, "certs.length");
            for (int i = 1; i < certs.length; i++) {
                print(out, "SSL_CLIENT_CHAIN_" + i + "_S_DN",
                        certs[i].getSubjectX500Principal().getName(),
                        "certs[" + i + "].getSubjectX500Principal().getName()");
                print(out, "SSL_CLIENT_CHAIN_" + i + "_I_DN",
                        certs[i].getIssuerX500Principal().getName(),
                        "certs[" + i + "].getIssuerX500Principal().getName()");
            }
        }

        printRequestProperties(out, request);
    }

    private void print(PrintWriter out, String key, Object value, String code) {
        out.println(key + "=" + value);
        out.println("  code: " + code);
        out.println();
    }

    private void printRequestProperties(PrintWriter out, HttpServletRequest request) {
        out.println();
        out.println("=== Request Properties ===");
        out.println();
        print(out, "request.scheme", request.getScheme(), "request.getScheme()");
        print(out, "request.secure", request.isSecure(), "request.isSecure()");
        print(out, "request.remoteAddr", request.getRemoteAddr(), "request.getRemoteAddr()");
        print(out, "request.remoteHost", request.getRemoteHost(), "request.getRemoteHost()");
        print(out, "request.remotePort", request.getRemotePort(), "request.getRemotePort()");
        print(out, "request.serverName", request.getServerName(), "request.getServerName()");
        print(out, "request.serverPort", request.getServerPort(), "request.getServerPort()");
        print(out, "request.requestURI", request.getRequestURI(), "request.getRequestURI()");
        print(out, "request.protocol", request.getProtocol(), "request.getProtocol()");
    }

    private void printDNComponents(PrintWriter out, String prefix, String dn, String dnCode) {
        try {
            LdapName ldapName = new LdapName(dn);
            for (Rdn rdn : ldapName.getRdns()) {
                String type = rdn.getType().toUpperCase();
                String value = rdn.getValue().toString();
                String suffix;
                switch (type) {
                    case "CN": suffix = "_CN"; break;
                    case "OU": suffix = "_OU"; break;
                    case "O": suffix = "_O"; break;
                    case "L": suffix = "_L"; break;
                    case "ST": suffix = "_ST"; break;
                    case "C": suffix = "_C"; break;
                    case "E":
                    case "EMAILADDRESS": suffix = "_Email"; break;
                    default: suffix = "_" + type; break;
                }
                print(out, prefix + suffix, value,
                        "new LdapName(" + dnCode + ").getRdns() // filter type=\"" + type + "\"");
            }
        } catch (Exception e) {
            print(out, prefix + "_parse_error", e.getMessage(), "new LdapName(" + dnCode + ").getRdns()");
        }
    }

    private String fingerprint(byte[] encoded, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digest = md.digest(encoded);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < digest.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02X", digest[i]));
        }
        return sb.toString();
    }

    private String sanTypeName(int type) {
        switch (type) {
            case 0: return "otherName";
            case 1: return "rfc822Name";
            case 2: return "dNSName";
            case 3: return "x400Address";
            case 4: return "directoryName";
            case 5: return "ediPartyName";
            case 6: return "URI";
            case 7: return "iPAddress";
            case 8: return "registeredID";
            default: return "type_" + type;
        }
    }
}
