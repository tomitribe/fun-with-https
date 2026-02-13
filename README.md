# Tomcat SSL — Mutual TLS (Client Certificate Authentication)

This example demonstrates mutual TLS (mTLS) on Apache TomEE and Apache Tomcat,
where both the server and the client present certificates during the TLS handshake.
A servlet displays every available SSL/TLS property, along with the Java code 
needed to obtain each value.

## How It Works

In standard HTTPS the server proves its identity to the client. With mutual TLS
the server also requires the **client** to present a certificate. Tomcat
validates the client certificate against a truststore and, if successful, makes
the full `X509Certificate` chain available to the application through a servlet
request attribute.

## Building and Running

All certificates are generated automatically during the Maven build — there are
no manual `keytool` steps.

```bash
mvn clean install tomee:run
```

### Generated Artifacts

| File | Format | Purpose |
|------|--------|---------|
| `target/conf/keystore.jks` | JKS | Server key pair (`CN=localhost`) |
| `target/conf/client.p12` | PKCS12 | Client key pair (`CN=Test Client`) |
| `target/conf/client.cer` | PEM | Exported client public certificate |
| `target/conf/truststore.jks` | JKS | Truststore containing the client cert |

## Testing with curl

**With client certificate** (should return SSL property output):

```bash
curl -k --cert-type P12 --cert target/conf/client.p12:changeit \
     https://localhost:8443/tomcat-ssl/
```

**Without client certificate** (should fail — handshake error or HTTP 400):

```bash
curl -k https://localhost:8443/tomcat-ssl/
```

## server.xml Configuration

Two things are required beyond a standard HTTPS connector:

1. `certificateVerification="required"` on `<SSLHostConfig>` — tells Tomcat to
   demand a client certificate.
2. A truststore containing the CA (or individual client certificates) that
   Tomcat will accept.

```xml
<Connector port="8443" protocol="HTTP/1.1"
           SSLEnabled="true"
           maxThreads="150"
           scheme="https"
           secure="true">
  <SSLHostConfig certificateVerification="required"
                 truststoreFile="${catalina.base}/conf/truststore.jks"
                 truststorePassword="changeit">
    <Certificate certificateKeystoreFile="${catalina.base}/conf/keystore.jks"
                 certificateKeystorePassword="changeit"
                 certificateKeyAlias="server"
                 type="RSA"/>
  </SSLHostConfig>
</Connector>
```

### SSLHostConfig Attributes

| Attribute | Value | Description |
|-----------|-------|-------------|
| `certificateVerification` | `required` | Client must present a valid certificate. Other options: `optional`, `optionalNoCA`, `none`. |
| `truststoreFile` | path | Truststore containing accepted client/CA certificates. |
| `truststorePassword` | string | Password for the truststore. |

## Servlet Request Attributes

Tomcat exposes SSL/TLS information through `request.getAttribute()`. These are
the key attributes:

| Attribute Name | Type | Description |
|----------------|------|-------------|
| `jakarta.servlet.request.X509Certificate` | `X509Certificate[]` | Client certificate chain. Index `[0]` is the client cert. |
| `jakarta.servlet.request.cipher_suite` | `String` | Negotiated SSL/TLS cipher suite. |
| `jakarta.servlet.request.key_size` | `Integer` | Effective key size of the cipher. |
| `jakarta.servlet.request.ssl_session_id` | `String` | SSL session identifier. |
| `org.apache.tomcat.util.net.secure_protocol_version` | `String` | TLS protocol version (Tomcat-specific). |

### Retrieving the Client Certificate

```java
X509Certificate[] certs = (X509Certificate[])
    request.getAttribute("jakarta.servlet.request.X509Certificate");

if (certs != null && certs.length > 0) {
    X509Certificate clientCert = certs[0];
    String subjectDN = clientCert.getSubjectX500Principal().getName();
    // ...
}
```

### Parsing DN Components

Individual RDN values (CN, OU, O, etc.) can be extracted from the
Distinguished Name using `javax.naming.ldap.LdapName`:

```java
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

LdapName ldapName = new LdapName(clientCert.getSubjectX500Principal().getName());
for (Rdn rdn : ldapName.getRdns()) {
    System.out.println(rdn.getType() + "=" + rdn.getValue());
}
```

## Apache HTTPD mod_ssl to Java/Tomcat Mapping

The table below maps Apache HTTPD `mod_ssl` environment variables to their
Java/Tomcat equivalents. In every case, the certificate object is obtained
first:

```java
X509Certificate[] certs = (X509Certificate[])
    request.getAttribute("jakarta.servlet.request.X509Certificate");
X509Certificate cert = certs[0];
```

### SSL Connection Variables

| mod_ssl Variable | Java / Tomcat Equivalent |
|------------------|--------------------------|
| `SSL_PROTOCOL` | `(String) request.getAttribute("org.apache.tomcat.util.net.secure_protocol_version")` |
| `SSL_CIPHER` | `(String) request.getAttribute("jakarta.servlet.request.cipher_suite")` |
| `SSL_CIPHER_USEKEYSIZE` | `(Integer) request.getAttribute("jakarta.servlet.request.key_size")` |
| `SSL_SESSION_ID` | `(String) request.getAttribute("jakarta.servlet.request.ssl_session_id")` |

### Client Certificate — Subject DN

| mod_ssl Variable | Java / Tomcat Equivalent |
|------------------|--------------------------|
| `SSL_CLIENT_S_DN` | `cert.getSubjectX500Principal().getName()` |
| `SSL_CLIENT_S_DN_CN` | `new LdapName(cert.getSubjectX500Principal().getName()).getRdns()` — filter `type="CN"` |
| `SSL_CLIENT_S_DN_OU` | Same as above — filter `type="OU"` |
| `SSL_CLIENT_S_DN_O` | Same as above — filter `type="O"` |
| `SSL_CLIENT_S_DN_L` | Same as above — filter `type="L"` |
| `SSL_CLIENT_S_DN_ST` | Same as above — filter `type="ST"` |
| `SSL_CLIENT_S_DN_C` | Same as above — filter `type="C"` |
| `SSL_CLIENT_S_DN_Email` | Same as above — filter `type="EMAILADDRESS"` |

### Client Certificate — Issuer DN

| mod_ssl Variable | Java / Tomcat Equivalent |
|------------------|--------------------------|
| `SSL_CLIENT_I_DN` | `cert.getIssuerX500Principal().getName()` |
| `SSL_CLIENT_I_DN_CN` | `new LdapName(cert.getIssuerX500Principal().getName()).getRdns()` — filter `type="CN"` |
| `SSL_CLIENT_I_DN_OU` | Same as above — filter `type="OU"` |
| `SSL_CLIENT_I_DN_O` | Same as above — filter `type="O"` |
| `SSL_CLIENT_I_DN_L` | Same as above — filter `type="L"` |
| `SSL_CLIENT_I_DN_ST` | Same as above — filter `type="ST"` |
| `SSL_CLIENT_I_DN_C` | Same as above — filter `type="C"` |
| `SSL_CLIENT_I_DN_Email` | Same as above — filter `type="EMAILADDRESS"` |

### Client Certificate — Validity

| mod_ssl Variable | Java / Tomcat Equivalent |
|------------------|--------------------------|
| `SSL_CLIENT_V_START` | `cert.getNotBefore()` |
| `SSL_CLIENT_V_END` | `cert.getNotAfter()` |
| `SSL_CLIENT_V_REMAIN` | `(cert.getNotAfter().getTime() - System.currentTimeMillis()) / 86400000` |

### Client Certificate — Details

| mod_ssl Variable | Java / Tomcat Equivalent |
|------------------|--------------------------|
| `SSL_CLIENT_M_VERSION` | `cert.getVersion()` |
| `SSL_CLIENT_M_SERIAL` | `cert.getSerialNumber().toString(16).toUpperCase()` |
| `SSL_CLIENT_A_SIG` | `cert.getSigAlgName()` |
| `SSL_CLIENT_A_KEY` | `cert.getPublicKey().getAlgorithm()` |
| — | `((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength()` |
| `SSL_CLIENT_CERT` | `Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())` |
| `SSL_CLIENT_VERIFY` | `certs != null && certs.length > 0 ? "SUCCESS" : "NONE"` |

### Client Certificate — Fingerprints

These do not have direct `mod_ssl` equivalents but are commonly needed:

| Variable | Java / Tomcat Equivalent |
|----------|--------------------------|
| SHA-1 fingerprint | `MessageDigest.getInstance("SHA-1").digest(cert.getEncoded())` |
| SHA-256 fingerprint | `MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())` |
| MD5 fingerprint | `MessageDigest.getInstance("MD5").digest(cert.getEncoded())` |

### Subject Alternative Names

| mod_ssl Variable | Java / Tomcat Equivalent |
|------------------|--------------------------|
| `SSL_CLIENT_SAN_DNS_n` | `cert.getSubjectAlternativeNames()` — filter general name type `2` (dNSName) |
| `SSL_CLIENT_SAN_Email_n` | Same as above — filter type `1` (rfc822Name) |

### Certificate Chain

| mod_ssl Variable | Java / Tomcat Equivalent |
|------------------|--------------------------|
| `SSL_CLIENT_CERT_CHAIN_n` | `certs[n]` (index 1+ in the `X509Certificate[]` array) |

## Project Structure

```
tomcat-ssl/
├── pom.xml                                         # Maven build with keytool + TomEE plugins
├── README.md
├── src/
│   ├── main/
│   │   ├── java/org/superbiz/tomcatssl/
│   │   │   └── CertInfoServlet.java                # Servlet displaying all SSL properties
│   │   └── webapp/
│   │       ├── WEB-INF/web.xml
│   │       └── index.jsp
│   └── test/
│       └── conf/
│           └── server.xml                           # Tomcat config with mTLS enabled
└── target/conf/                                     # Generated at build time
    ├── keystore.jks
    ├── client.p12
    ├── client.cer
    └── truststore.jks
```
