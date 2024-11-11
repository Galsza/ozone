/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.hadoop.hdds.security.x509.certificate;

import org.apache.hadoop.hdds.protocol.proto.HddsProtos.CertInfoProto;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateCodec;
import org.apache.hadoop.hdds.utils.db.Codec;
import org.apache.hadoop.hdds.utils.db.DelegatedCodec;
import org.apache.hadoop.hdds.utils.db.Proto2Codec;

import jakarta.annotation.Nonnull;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.Objects;

/**
 * Class that wraps Certificate Info.
 */
public final class CertInfo implements Comparable<CertInfo>, Serializable {
  private static final Codec<CertInfo> CODEC = new DelegatedCodec<>(
      Proto2Codec.get(CertInfoProto.getDefaultInstance()),
      CertInfo::fromProtobuf,
      CertInfo::getProtobuf,
      CertInfo.class);

  public static Codec<CertInfo> getCodec() {
    return CODEC;
  }

  static final Comparator<CertInfo> COMPARATOR
      = Comparator.comparingLong(CertInfo::getTimestamp);

  private final X509Certificate x509Certificate;
  // Timestamp when the certificate got persisted in the DB.
  private final long timestamp;

  private CertInfo(X509Certificate x509Certificate, long timestamp) {
    this.x509Certificate = x509Certificate;
    this.timestamp = timestamp;
  }

  public static CertInfo fromProtobuf(CertInfoProto info) throws IOException {
    return new CertInfo.Builder()
        .setX509Certificate(info.getX509Certificate())
        .setTimestamp(info.getTimestamp())
        .build();
  }

  public CertInfoProto getProtobuf() throws IOException {
    return CertInfoProto.newBuilder()
        .setX509Certificate(getX509CertificatePEMEncodedString())
        .setTimestamp(getTimestamp())
        .build();
  }

  public X509Certificate getX509Certificate() {
    return x509Certificate;
  }

  public String getX509CertificatePEMEncodedString() throws IOException {
    return CertificateCodec.getPEMEncodedString(getX509Certificate());
  }

  public long getTimestamp() {
    return timestamp;
  }

  /**
   * Compares this object with the specified object for order.  Returns a
   * negative integer, zero, or a positive integer as this object is less
   * than, equal to, or greater than the specified object.
   *
   * @param o the object to be compared.
   * @return a negative integer, zero, or a positive integer as this object
   * is less than, equal to, or greater than the specified object.
   * @throws NullPointerException if the specified object is null
   * @throws ClassCastException   if the specified object's type prevents it
   *                              from being compared to this object.
   */
  @Override
  public int compareTo(@Nonnull CertInfo o) {
    return COMPARATOR.compare(this, o);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    CertInfo that = (CertInfo) o;

    return this.getX509Certificate().equals(that.getX509Certificate()) &&
        this.getTimestamp() == that.getTimestamp();
  }

  @Override
  public int hashCode() {
    return Objects.hash(getX509Certificate(), getTimestamp());
  }

  @Override
  public String toString() {
    return "CertInfo{" +
        "x509Certificate=" + x509Certificate.toString() +
        ", timestamp=" + timestamp +
        '}';
  }

  /**
   * Builder class for CertInfo.
   */
  @SuppressWarnings("checkstyle:hiddenfield")
  public static class Builder {
    private X509Certificate x509Certificate;
    private long timestamp;

    public Builder setX509Certificate(X509Certificate x509Certificate) {
      this.x509Certificate = x509Certificate;
      return this;
    }

    public Builder setX509Certificate(String x509Certificate) throws IOException {
      return setX509Certificate(
          (X509Certificate) CertificateCodec.getCertPathFrom(x509Certificate).getCertificates().get(0));
    }

    public Builder setTimestamp(long timestamp) {
      this.timestamp = timestamp;
      return this;
    }

    public CertInfo build() {
      return new CertInfo(x509Certificate, timestamp);
    }
  }
}
