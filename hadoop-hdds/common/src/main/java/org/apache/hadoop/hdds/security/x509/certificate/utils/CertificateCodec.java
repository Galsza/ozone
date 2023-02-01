/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.apache.hadoop.hdds.security.x509.certificate.utils;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.LineIterator;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hdds.security.exception.SCMSecurityException;
import org.apache.hadoop.hdds.security.x509.SecurityConfig;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;
import static org.apache.hadoop.hdds.security.exception.SCMSecurityException.ErrorCode.PEM_ENCODE_FAILED;

/**
 * A class used to read and write X.509 certificates  PEM encoded Streams.
 */
public class CertificateCodec {
  public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
  public static final String END_CERT = "-----END CERTIFICATE-----";
  public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

  private static final Logger LOG =
      LoggerFactory.getLogger(CertificateCodec.class);
  private static final JcaX509CertificateConverter CERTIFICATE_CONVERTER
      = new JcaX509CertificateConverter();
  private final SecurityConfig securityConfig;
  private final Path location;
  private Set<PosixFilePermission> permissionSet =
      Stream.of(OWNER_READ, OWNER_WRITE, OWNER_EXECUTE)
          .collect(Collectors.toSet());
  /**
   * Creates a CertificateCodec with component name.
   *
   * @param config - Security Config.
   * @param component - Component String.
   */
  public CertificateCodec(SecurityConfig config, String component) {
    this.securityConfig = config;
    this.location = securityConfig.getCertificateLocation(component);
  }

  public CertificateCodec(SecurityConfig config, Path certPath) {
    this.securityConfig = config;
    this.location = certPath;
  }

  /**
   * Returns a X509 Certificate from the Certificate Holder.
   *
   * @param holder - Holder
   * @return X509Certificate.
   * @throws CertificateException - on Error.
   */
  public static X509Certificate getX509Certificate(X509CertificateHolder holder)
      throws CertificateException {
    return CERTIFICATE_CONVERTER.getCertificate(holder);
  }

  public static String getPEMEncodedString(List<X509CertificateHolder> certs)
      throws SCMSecurityException {
    ArrayList<String> pemEncodedList = new ArrayList<>(certs.size());
    for (X509CertificateHolder cert : certs) {
      pemEncodedList.add(getPEMEncodedString(cert));
    }
    return StringUtils.join(pemEncodedList, "\n");
  }

  /**
   * Returns the Certificate as a PEM encoded String.
   *
   * @param x509CertHolder - X.509 Certificate Holder.
   * @return PEM Encoded Certificate String.
   * @throws SCMSecurityException - On failure to create a PEM String.
   */
  public static String getPEMEncodedString(X509CertificateHolder x509CertHolder)
      throws SCMSecurityException {
    try {
      return getPEMEncodedString(getX509Certificate(x509CertHolder));
    } catch (CertificateException exp) {
      throw new SCMSecurityException(exp);
    }
  }

  /**
   * Returns the Certificate as a PEM encoded String.
   *
   * @param certificate - X.509 Certificate.
   * @return PEM Encoded Certificate String.
   * @throws SCMSecurityException - On failure to create a PEM String.
   */
  public static String getPEMEncodedString(X509Certificate certificate)
      throws SCMSecurityException {
    try {
      StringWriter stringWriter = new StringWriter();
      try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
        pemWriter.writeObject(certificate);
      }
      return stringWriter.toString();
    } catch (IOException e) {
      LOG.error("Error in encoding certificate." + certificate
          .getSubjectDN().toString(), e);
      throw new SCMSecurityException("PEM Encoding failed for certificate." +
          certificate.getSubjectDN().toString(), e, PEM_ENCODE_FAILED);
    }
  }

  /**
   * Gets the X.509 Certificate from PEM encoded String.
   *
   * @param pemEncodedString - PEM encoded String.
   * @return X509Certificate  - Certificate.
   * @throws CertificateException - Thrown on Failure.
   * @throws IOException          - Thrown on Failure.
   */
  public static X509Certificate getX509Certificate(String pemEncodedString)
      throws CertificateException, IOException {
    CertificateFactory fact = new CertificateFactory();
    try (InputStream input = IOUtils.toInputStream(pemEncodedString, UTF_8)) {
      return (X509Certificate) fact.engineGenerateCertificate(input);
    }
  }

  /**
   * Get Certificate location.
   *
   * @return Path
   */
  public Path getLocation() {
    return location;
  }

  /**
   * Write the Certificate pointed to the location by the configs.
   *
   * @param xCertificate - Certificate to write.
   * @throws SCMSecurityException - on Error.
   * @throws IOException          - on Error.
   */
  public void writeCertificate(X509CertificateHolder xCertificate)
      throws SCMSecurityException, IOException {
    String pem = getPEMEncodedString(xCertificate);
    writeCertificate(location.toAbsolutePath(),
        this.securityConfig.getCertificateFileName(), pem);
  }

  /**
   * Write the Certificate to the specific file.
   *
   * @param xCertificate - Certificate to write.
   * @param fileName - file name to write to.
   * @throws SCMSecurityException - On Error.
   * @throws IOException          - On Error.
   */
  public void writeCertificate(X509CertificateHolder xCertificate,
      String fileName)
      throws SCMSecurityException, IOException {
    String pem = getPEMEncodedString(xCertificate);
    writeCertificate(location.toAbsolutePath(), fileName, pem);
  }

  public void writeCertificate(String fileName, String pemEncodedCert)
      throws IOException {
    writeCertificate(location.toAbsolutePath(), fileName, pemEncodedCert);
  }

  /**
   * Helper function that writes data to the file.
   *
   * @param basePath              - Base Path where the file needs to written
   *                              to.
   * @param fileName              - Certificate file name.
   * @param pemEncodedCertificate - pemEncoded Certificate file.
   * @throws IOException - on Error.
   */
  public synchronized void writeCertificate(Path basePath, String fileName,
      String pemEncodedCertificate)
      throws IOException {
    checkBasePathDirectory(basePath);
    File certificateFile =
        Paths.get(basePath.toString(), fileName).toFile();

    try (FileOutputStream file = new FileOutputStream(certificateFile)) {
      IOUtils.write(pemEncodedCertificate, file, UTF_8);
    }

    Files.setPosixFilePermissions(certificateFile.toPath(), permissionSet);
  }

  private void checkBasePathDirectory(Path basePath) throws IOException {
    if (!basePath.toFile().exists()) {
      if (!basePath.toFile().mkdirs()) {
        LOG.error("Unable to create file path. Path: {}", basePath);
        throw new IOException("Creation of the directories failed."
            + basePath);
      }
    }
  }

  /**
   * Rertuns a default certificate using the default paths for this component.
   *
   * @return X509CertificateHolder.
   * @throws SCMSecurityException - on Error.
   * @throws CertificateException - on Error.
   * @throws IOException          - on Error.
   */
  //BUG HERE
  public X509CertificateHolder readCertificate() throws
      CertificateException, IOException {
    return readCertificate(this.location.toAbsolutePath(),
        this.securityConfig.getCertificateFileName());
  }

  /**
   * Returns the certificate from the specific PEM encoded file.
   *
   * @param basePath - base path
   * @param fileName - fileName
   * @return X%09 Certificate
   * @throws IOException          - on Error.
   * @throws SCMSecurityException - on Error.
   * @throws CertificateException - on Error.
   */
  public synchronized X509CertificateHolder readCertificate(Path basePath,
      String fileName) throws IOException, CertificateException {
    File certificateFile = Paths.get(basePath.toString(), fileName).toFile();
    return getX509CertificateHolder(certificateFile);
  }


  /**
   * Helper function to read certificate.
   *
   * @param certificateFile - Full path to certificate file.
   * @return X509CertificateHolder
   * @throws IOException          - On Error.
   * @throws CertificateException - On Error.
   */
  private X509CertificateHolder getX509CertificateHolder(File certificateFile)
      throws IOException, CertificateException {
    if (!certificateFile.exists()) {
      throw new IOException("Unable to find the requested certificate. Path: "
          + certificateFile.toString());
    }

    CertificateFactory fact = new CertificateFactory();
    try (FileInputStream is = new FileInputStream(certificateFile)) {
      return getCertificateHolder(
          (X509Certificate) fact.engineGenerateCertificate(is));
    }
  }

  public List<X509CertificateHolder> getCertList()
      throws IOException, CertificateException {
    CertPath certPath =
        getCertPath(this.securityConfig.getCertificateFileName());
    ArrayList<X509CertificateHolder> certList = new ArrayList<>();
    for (Certificate cert : certPath.getCertificates()) {
      certList.add(getCertificateHolder((X509Certificate) cert));
    }
    return certList;
  }

  public CertPath getCertPathFromPemEncodedString(
      String pemString) throws CertificateException, IOException {
    try (InputStream is =
             new ByteArrayInputStream(pemString.getBytes(DEFAULT_CHARSET))) {
      return generateCertPathFromInputStream(is);
    }
  }

  private CertPath generateCertPathFromInputStream(InputStream inputStream)
      throws CertificateException {
    CertificateFactory fact = new CertificateFactory();
    return fact.engineGenerateCertPath(inputStream, "PEM");
  }

  public CertPath getCertPath(String fileName)
      throws IOException, CertificateException {
    checkBasePathDirectory(location.toAbsolutePath());
    File certFile =
        Paths.get(location.toAbsolutePath().toString(), fileName).toFile();
    if (!certFile.exists()) {
      throw new IOException("Unable to find the requested certificate file. " +
          "Path: " + certFile);
    }
    try (FileInputStream is = new FileInputStream(certFile)) {
      return generateCertPathFromInputStream(is);
    }
  }

  /**
   * Returns the Certificate holder from X509Certificate class.
   *
   * @param x509cert - Certificate class.
   * @return X509CertificateHolder
   * @throws CertificateEncodingException - on Error.
   * @throws IOException                  - on Error.
   */
  public static X509CertificateHolder getCertificateHolder(
      X509Certificate x509cert)
      throws CertificateEncodingException, IOException {
    return new X509CertificateHolder(x509cert.getEncoded());
  }
}
