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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
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

  public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

  private static final Logger LOG =
      LoggerFactory.getLogger(CertificateStorage.class);

  private static final Set<PosixFilePermission> PERMISSION_SET =
      Stream.of(OWNER_READ, OWNER_WRITE, OWNER_EXECUTE)
          .collect(Collectors.toSet());

  private final SecurityConfig config;
  private final Path location;

  public CertificateStorage(SecurityConfig conf, Path location) {
    this.config = conf;
    this.location = location;
  }

  /**
   * Helper function that writes data to the file.
   *
   * @param basePath              - Base Path where the file needs to written
   *                              to..
   * @param pemEncodedCertificate - pemEncoded Certificate file.
   * @throws IOException - on Error.
   */
  public static synchronized void writeCertificate(Path basePath,
                                                   String pemEncodedCertificate)
      throws IOException {
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
}
