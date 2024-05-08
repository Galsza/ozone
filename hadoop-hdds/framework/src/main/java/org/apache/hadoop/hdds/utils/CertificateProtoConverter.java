/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership.  The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.hadoop.hdds.utils;

import org.apache.hadoop.hdds.conf.ConfigurationSource;
import org.apache.hadoop.hdds.protocol.proto.SCMSecurityProtocolProtos.SCMGetCertResponseProto;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.exception.SCMSecurityException;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateCodec;

import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Class to forward ceritficate encoding and decoding functionality from codec to protos.
 */
public class CertificateProtoConverter {
  private ConfigurationSource conf;

  public CertificateProtoConverter(ConfigurationSource config) {
    conf = config;
  }

  public CertPath getCertFromProto(SCMGetCertResponseProto proto) throws IOException {
    try {
      return getCertCodec().getCertPathFromPemEncodedString(proto.getX509Certificate());
    } catch (CertificateException e) {
      throw new IOException(e);
    }
  }

  public X509Certificate getCaCertFromProto(SCMGetCertResponseProto proto) throws IOException {
    try {
      return getCertCodec().getX509Certificate(proto.getX509CACertificate());
    } catch (CertificateException e) {
      throw new IOException(e);
    }
  }

  public X509Certificate getRootCaCertFromProto(SCMGetCertResponseProto proto) throws IOException {
    try {
      return getCertCodec().getX509Certificate(proto.getX509RootCACertificate());
    } catch (CertificateException e) {
      throw new IOException(e);
    }
  }

  public SCMGetCertResponseProto.Builder setCertInProto(SCMGetCertResponseProto.Builder proto, CertPath certPath)
      throws IOException {
    try {
      return proto.setX509Certificate(getCertCodec().getPEMEncodedString(certPath));
    } catch (SCMSecurityException exp) {
      throw new IOException(exp);
    }
  }

  public SCMGetCertResponseProto.Builder setCaCertInProto(SCMGetCertResponseProto.Builder proto, CertPath certPath)
      throws IOException {
    try {
      return proto.setX509CACertificate(getCertCodec().getPEMEncodedString(certPath));
    } catch (SCMSecurityException exp) {
      throw new IOException(exp);
    }
  }

  public SCMGetCertResponseProto.Builder setRootCaCertInProto(SCMGetCertResponseProto.Builder proto, CertPath certPath)
      throws IOException {
    try {
      return proto.setX509RootCACertificate(getCertCodec().getPEMEncodedString(certPath));
    } catch (SCMSecurityException exp) {
      throw new IOException(exp);
    }
  }

  private CertificateCodec getCertCodec() {
    return new CertificateCodec(new SecurityConfig(conf), "");
  }
}
