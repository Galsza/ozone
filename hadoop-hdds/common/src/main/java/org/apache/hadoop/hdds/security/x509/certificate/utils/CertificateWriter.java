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
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Temporary class not sure of the usage.
 */
public final class CertificateWriter {
  private CertificateWriter() {
  }

  public static void writeCertificate(SecurityConfig config, String componentName, X509CertificateHolder certificate)
      throws IOException {
    String pem = CertificateCodec.getPEMEncodedString(certificate);
    String certDir = config.getCertificateLocation(componentName).toAbsolutePath().toString();
    Path certFilePath = Paths.get(certDir, config.getCertificateFileName());
    CertificateCodec.writeCertificate(certFilePath, pem);
  }
}
