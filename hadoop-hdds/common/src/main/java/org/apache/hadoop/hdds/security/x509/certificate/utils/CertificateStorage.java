/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hdds.security.x509.certificate.utils;

import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.certificate.authority.CAType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.file.attribute.PosixFilePermission.OWNER_READ;
import static java.nio.file.attribute.PosixFilePermission.OWNER_WRITE;
import static java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE;

/**
 * Class for storing certificates to disk.
 */
public class CertificateStorage {

  private static final String CERT_FILE_EXTENSION = ".crt";
  public static final String CERT_FILE_NAME_FORMAT = "%s" + CERT_FILE_EXTENSION;

  public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

  private static final Logger LOG =
      LoggerFactory.getLogger(CertificateStorage.class);

  private static final Set<PosixFilePermission> PERMISSION_SET =
      Stream.of(OWNER_READ, OWNER_WRITE, OWNER_EXECUTE)
          .collect(Collectors.toSet());

  private SecurityConfig config;

  public CertificateStorage(SecurityConfig conf) {
    this.config = conf;
  }

  /**
   * Helper function that writes data to the file.
   *
   * @param basePath              - Base Path where the file needs to written
   *                              to..
   * @param pemEncodedCertificate - pemEncoded Certificate file.
   * @throws IOException - on Error.
   */
  public synchronized CertPath writeCertificate(Path basePath, String pemEncodedCertificate, CAType caType)
      throws IOException {

    CertificateCodec certificateCodec = config.getCertificateCodec();
    CertPath certPath = certificateCodec.getCertPathFromPemEncodedString(pemEncodedCertificate);

    X509Certificate cert = (X509Certificate) certPath.getCertificates().get(0);
    String certName = String.format(CERT_FILE_NAME_FORMAT,
        caType.getFileNamePrefix() + cert.getSerialNumber().toString());
    checkBasePathDirectory(basePath);
    Path finalPath = Paths.get(basePath.toAbsolutePath().toString(), certName);
    File certificateFile = finalPath.toFile();
    try (FileOutputStream file = new FileOutputStream(certificateFile)) {
      file.write(pemEncodedCertificate.getBytes(DEFAULT_CHARSET));
    }
    LOG.info("Save certificate to {}", certificateFile.getAbsolutePath());
    LOG.info("Certificate {}", pemEncodedCertificate);
    Files.setPosixFilePermissions(certificateFile.toPath(), PERMISSION_SET);
    return certPath;
  }

  public synchronized void writeCertificate(Path basePath, String pemEncodedCertificate) throws IOException {
    checkBasePathDirectory(basePath.getParent());
    File certificateFile = basePath.toFile();
    try (FileOutputStream file = new FileOutputStream(certificateFile)) {
      file.write(pemEncodedCertificate.getBytes(DEFAULT_CHARSET));
    }
    LOG.info("Save certificate to {}", certificateFile.getAbsolutePath());
    LOG.info("Certificate {}", pemEncodedCertificate);
    Files.setPosixFilePermissions(certificateFile.toPath(), PERMISSION_SET);
  }

  private static void checkBasePathDirectory(Path basePath) throws IOException {
    if (!basePath.toFile().exists()) {
      if (!basePath.toFile().mkdirs()) {
        LOG.error("Unable to create file path. Path: {}", basePath);
        throw new IOException("Creation of the directories failed."
            + basePath);
      }
    }
  }


  /*public synchronized void storeCertificate(String pemEncodedCert,
                                            CAType caType, CertificateCodec codec, boolean addToCertMap,
                                            boolean updateCA) throws CertificateException {
    try {
      CertPath certificatePath =
          CertificateCodec.getCertPathFromPemEncodedString(pemEncodedCert);
      X509Certificate cert = firstCertificateFrom(certificatePath);

      String certName = String.format(CERT_FILE_NAME_FORMAT,
          caType.getFileNamePrefix() + cert.getSerialNumber().toString());

      if (updateCA) {
        if (caType == CAType.SUBORDINATE) {
          caCertId = cert.getSerialNumber().toString();
        }
        if (caType == CAType.ROOT) {
          rootCaCertId = cert.getSerialNumber().toString();
        }
      }

      CertificateCodec.writeCertificate(
          Paths.get(codec.getLocation().toAbsolutePath().toString(), certName), pemEncodedCert);
      if (addToCertMap) {
        certificateMap.put(cert.getSerialNumber().toString(), certificatePath);
        if (caType == CAType.SUBORDINATE) {
          caCertificates.add(cert);
        }
        if (caType == CAType.ROOT) {
          rootCaCertificates.add(cert);
        }
      }
    } catch (IOException | java.security.cert.CertificateException e) {
      throw new CertificateException("Error while storing certificate.", e,
          CERTIFICATE_ERROR);
    }
  }


  private synchronized void readCertificateFile(Path filePath) {
    CertificateCodec codec = new CertificateCodec(config, location);
    String fileName = filePath.getFileName().toString();

    X509Certificate cert;
    try {
      CertPath allCertificates = codec.getCertPath(fileName);
      cert = firstCertificateFrom(allCertificates);
      String readCertSerialId = cert.getSerialNumber().toString();

      if (readCertSerialId.equals(certSerialId)) {
        this.certPath = allCertificates;
      }
      certificateMap.put(readCertSerialId, allCertificates);
      addCertsToSubCaMapIfNeeded(fileName, allCertificates);
      addCertToRootCaMapIfNeeded(fileName, allCertificates);

      updateCachedData(fileName, CAType.SUBORDINATE, this::updateCachedSubCAId);
      updateCachedData(fileName, CAType.ROOT, this::updateCachedRootCAId);

      logger.info("Added certificate {} from file: {}.", readCertSerialId,
          filePath.toAbsolutePath());
      if (logger.isDebugEnabled()) {
        logger.debug("Certificate: {}", cert);
      }
    } catch (java.security.cert.CertificateException
             | IOException | IndexOutOfBoundsException e) {
      logger.error("Error reading certificate from file: {}.",
          filePath.toAbsolutePath(), e);
    }
  }

  private synchronized void updateCachedRootCAId(String s) {
    BigInteger candidateNewId = new BigInteger(s);
    if (rootCaCertId == null
        || new BigInteger(rootCaCertId).compareTo(candidateNewId) < 0) {
      rootCaCertId = s;
    }
  }

  private synchronized void updateCachedSubCAId(String s) {
    BigInteger candidateNewId = new BigInteger(s);
    if (caCertId == null
        || new BigInteger(caCertId).compareTo(candidateNewId) < 0) {
      caCertId = s;
    }
  }

  private void updateCachedData(
      String fileName,
      CAType tryCAType,
      Consumer<String> updateCachedId
  ) throws IOException {
    String caTypePrefix = tryCAType.getFileNamePrefix();

    if (fileName.startsWith(caTypePrefix)) {
      updateCachedId.accept(
          fileName.substring(caTypePrefix.length(),
              fileName.length() - CERT_FILE_EXTENSION.length()
          ));
    }
  }



  private void addCertsToSubCaMapIfNeeded(String fileName, CertPath certs) {
    if (fileName.startsWith(CAType.SUBORDINATE.getFileNamePrefix())) {
      caCertificates.addAll(
          certs.getCertificates().stream()
              .map(x -> (X509Certificate) x)
              .collect(Collectors.toSet()));
    }
  }

  private void addCertToRootCaMapIfNeeded(String fileName, CertPath certs) {
    if (fileName.startsWith(CAType.ROOT.getFileNamePrefix())) {
      rootCaCertificates.add(firstCertificateFrom(certs));
    }
  }

  private static X509Certificate firstCertificateFrom(CertPath certificatePath) {
    return (X509Certificate) certificatePath.getCertificates().get(0);
  }*/
}
