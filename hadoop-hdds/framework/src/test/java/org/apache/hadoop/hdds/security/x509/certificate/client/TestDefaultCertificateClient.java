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
package org.apache.hadoop.hdds.security.x509.certificate.client;

import org.apache.hadoop.hdds.HddsConfigKeys;
import org.apache.hadoop.hdds.protocol.DatanodeDetails;
import org.apache.hadoop.hdds.protocol.MockDatanodeDetails;
import org.apache.hadoop.hdds.protocol.proto.SCMSecurityProtocolProtos.SCMGetCertResponseProto;
import org.apache.hadoop.hdds.protocolPB.SCMSecurityProtocolClientSideTranslatorPB;
import org.apache.hadoop.hdds.security.x509.certificate.authority.CAType;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateCodec;
import org.apache.hadoop.hdds.security.x509.certificate.utils.CertificateStorage;
import org.apache.hadoop.hdds.security.x509.exception.CertificateException;
import org.apache.hadoop.hdds.security.x509.keys.KeyCodec;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.function.Predicate;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;


import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.hdds.security.SecurityConfig;
import org.apache.hadoop.hdds.security.x509.keys.HDDSKeyGenerator;
import org.apache.hadoop.security.ssl.KeyStoreTestUtil;
import org.apache.ozone.test.GenericTestUtils;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.hadoop.fs.CommonConfigurationKeysPublic.IPC_CLIENT_CONNECT_MAX_RETRIES_KEY;
import static org.apache.hadoop.hdds.HddsConfigKeys.HDDS_METADATA_DIR_NAME;
import static org.apache.hadoop.hdds.scm.ScmConfigKeys.OZONE_SCM_NAMES;
import static org.apache.hadoop.hdds.security.x509.certificate.client.CertificateClient.InitResponse.FAILURE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link DefaultCertificateClient}.
 */
public class TestDefaultCertificateClient {

  private String certSerialId;
  private X509Certificate x509Certificate;
  private DNCertificateClient dnCertClient;
  private HDDSKeyGenerator keyGenerator;
  @TempDir
  private Path dnMetaDirPath;
  private SecurityConfig dnSecurityConfig;
  private SCMSecurityProtocolClientSideTranslatorPB scmSecurityClient;
  private static final String DN_COMPONENT = DNCertificateClient.COMPONENT_NAME;
  private KeyCodec dnKeyCodec;
  private CertificateCodec certificateCodec;
  private CertificateStorage certificateStorage;

  @BeforeEach
  public void setUp() throws Exception {
    OzoneConfiguration config = new OzoneConfiguration();
    config.setStrings(OZONE_SCM_NAMES, "localhost");
    config.setInt(IPC_CLIENT_CONNECT_MAX_RETRIES_KEY, 2);

    config.set(HDDS_METADATA_DIR_NAME, dnMetaDirPath.toString());
    dnSecurityConfig = new SecurityConfig(config);

    keyGenerator = new HDDSKeyGenerator(dnSecurityConfig);
    dnKeyCodec = new KeyCodec(dnSecurityConfig, DN_COMPONENT);

    Files.createDirectories(dnSecurityConfig.getKeyLocation(DN_COMPONENT));
    x509Certificate = generateX509Cert(null);
    certSerialId = x509Certificate.getSerialNumber().toString();
    scmSecurityClient = mock(SCMSecurityProtocolClientSideTranslatorPB.class);
    getCertClient();
    certificateCodec = dnSecurityConfig.getCertificateCodec();
    certificateStorage = new CertificateStorage(dnSecurityConfig);
  }

  private void getCertClient() throws IOException {
    if (dnCertClient != null) {
      dnCertClient.close();
    }

    dnCertClient = new DNCertificateClient(dnSecurityConfig, scmSecurityClient,
        MockDatanodeDetails.randomDatanodeDetails(), certSerialId, null,
        () -> System.exit(1));
  }

  @AfterEach
  public void tearDown() throws IOException {
    dnCertClient.close();
    dnCertClient = null;
  }

  /**
   * Tests: 1. getPrivateKey 2. getPublicKey 3. storePrivateKey 4.
   * storePublicKey
   */
  @Test
  public void testKeyOperations() throws Exception {
    cleanupOldKeyPair();
    PrivateKey pvtKey = dnCertClient.getPrivateKey();
    PublicKey publicKey = dnCertClient.getPublicKey();
    assertNull(publicKey);
    assertNull(pvtKey);

    KeyPair keyPair = generateKeyPairFiles();
    pvtKey = dnCertClient.getPrivateKey();
    assertNotNull(pvtKey);
    assertEquals(pvtKey, keyPair.getPrivate());

    publicKey = dnCertClient.getPublicKey();
    assertNotNull(publicKey);
    assertEquals(publicKey, keyPair.getPublic());
  }

  private KeyPair generateKeyPairFiles() throws Exception {
    cleanupOldKeyPair();
    KeyPair keyPair = keyGenerator.generateKey();
    dnKeyCodec.writePrivateKey(keyPair.getPrivate());
    dnKeyCodec.writePublicKey(keyPair.getPublic());
    return keyPair;
  }

  private void cleanupOldKeyPair() {
    FileUtils.deleteQuietly(Paths.get(
        dnSecurityConfig.getKeyLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getPrivateKeyFileName()).toFile());
    FileUtils.deleteQuietly(Paths.get(
        dnSecurityConfig.getKeyLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getPublicKeyFileName()).toFile());
  }

  /**
   * Tests: 1. storeCertificate 2. getCertificate 3. verifyCertificate
   */
  @Test
  public void testCertificateOps() throws Exception {
    X509Certificate cert = dnCertClient.getCertificate();
    assertNull(cert);
    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(x509Certificate),
        CAType.SUBORDINATE);

    cert = dnCertClient.getCertificate(
        x509Certificate.getSerialNumber().toString());
    assertNotNull(cert);
    assertThat(cert.getEncoded().length).isGreaterThan(0);
    assertEquals(x509Certificate, cert);

    // TODO: test verifyCertificate once implemented.
  }

  private X509Certificate generateX509Cert(KeyPair keyPair) throws Exception {
    if (keyPair == null) {
      keyPair = generateKeyPairFiles();
    }
    return KeyStoreTestUtil.generateCertificate("CN=Test", keyPair, 30,
        dnSecurityConfig.getSignatureAlgo());
  }

  @Test
  public void testSignDataStream() throws Exception {
    String data = RandomStringUtils.random(100);
    FileUtils.deleteQuietly(Paths.get(
        dnSecurityConfig.getKeyLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getPrivateKeyFileName()).toFile());
    FileUtils.deleteQuietly(Paths.get(
        dnSecurityConfig.getKeyLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getPublicKeyFileName()).toFile());

    // Expect error when there is no private key to sign.
    IOException ioException = assertThrows(IOException.class,
        () -> dnCertClient.signData(data.getBytes(UTF_8)));
    assertThat(ioException.getMessage())
        .contains("Error while signing the stream");

    generateKeyPairFiles();
    byte[] sign = dnCertClient.signData(data.getBytes(UTF_8));
    validateHash(sign, data.getBytes(UTF_8));
  }

  /**
   * Validate hash using public key of KeyPair.
   */
  private void validateHash(byte[] hash, byte[] data)
      throws Exception {
    Signature rsaSignature =
        Signature.getInstance(dnSecurityConfig.getSignatureAlgo(),
            dnSecurityConfig.getProvider());
    rsaSignature.initVerify(dnCertClient.getPublicKey());
    rsaSignature.update(data);
    assertTrue(rsaSignature.verify(hash));
  }

  /**
   * Tests: 1. verifySignature
   */
  @Test
  public void verifySignatureStream() throws Exception {
    String data = RandomStringUtils.random(500);
    byte[] sign = dnCertClient.signData(data.getBytes(UTF_8));

    // Positive tests.
    assertTrue(dnCertClient.verifySignature(data.getBytes(UTF_8), sign,
        x509Certificate));

    // Negative tests.
    assertFalse(dnCertClient.verifySignature(data.getBytes(UTF_8),
        "abc".getBytes(UTF_8), x509Certificate));

  }

  /**
   * Tests: 1. verifySignature
   */
  @Test
  public void verifySignatureDataArray() throws Exception {
    String data = RandomStringUtils.random(500);
    byte[] sign = dnCertClient.signData(data.getBytes(UTF_8));

    // Positive tests.
    assertTrue(dnCertClient.verifySignature(data.getBytes(UTF_8), sign,
        x509Certificate));

    // Negative tests.
    assertFalse(dnCertClient.verifySignature(data.getBytes(UTF_8),
        "abc".getBytes(UTF_8), x509Certificate));
  }

  @Test
  public void testCertificateLoadingOnInit() throws Exception {
    KeyPair keyPair = keyGenerator.generateKey();
    X509Certificate cert1 = generateX509Cert(keyPair);
    X509Certificate cert2 = generateX509Cert(keyPair);
    X509Certificate cert3 = generateX509Cert(keyPair);
    X509Certificate rootCa1 = generateX509Cert(keyPair);
    X509Certificate rootCa2 = generateX509Cert(keyPair);
    X509Certificate subCa1 = generateX509Cert(keyPair);
    X509Certificate subCa2 = generateX509Cert(keyPair);

    Path certPath = dnSecurityConfig.getCertificateLocation(DN_COMPONENT);

    // Certificate not found.
    CertificateException certException = assertThrows(
        CertificateException.class,
        () -> dnCertClient.getCertificate(cert1.getSerialNumber().toString()));
    assertThat(certException.getMessage())
        .contains("Error while getting certificate");
    certException = assertThrows(CertificateException.class,
        () -> dnCertClient.getCertificate(cert2.getSerialNumber().toString()));
    assertThat(certException.getMessage())
        .contains("Error while getting certificate");
    certException = assertThrows(CertificateException.class,
        () -> dnCertClient.getCertificate(cert3.getSerialNumber()
            .toString()));
    assertThat(certException.getMessage())
        .contains("Error while getting certificate");
    certificateStorage.writeCertificate(Paths.get(certPath.toString(), "1.crt"), cert1);
    certificateStorage.writeCertificate(Paths.get(certPath.toString(), "2.crt"), cert2);
    certificateStorage.writeCertificate(Paths.get(certPath.toString(), "3.crt"), cert3);
    certificateStorage.writeCertificate(Paths.get(certPath.toString(), CAType.ROOT.getFileNamePrefix() + "1.crt"),
        rootCa1);
    certificateStorage.writeCertificate(Paths.get(certPath.toString(), CAType.ROOT.getFileNamePrefix() + "2.crt"),
        rootCa2);
    certificateStorage.writeCertificate(
        Paths.get(certPath.toString(), CAType.SUBORDINATE.getFileNamePrefix() + "1.crt"), subCa1);
    certificateStorage.writeCertificate(Paths.get(certPath.toString(),
        CAType.SUBORDINATE.getFileNamePrefix() + "2.crt"), subCa2);

    // Re instantiate DN client which will load certificates from filesystem.
    if (dnCertClient != null) {
      dnCertClient.close();
    }
    DatanodeDetails dn = MockDatanodeDetails.randomDatanodeDetails();
    dnCertClient = new DNCertificateClient(dnSecurityConfig, null, dn,
        certSerialId, null, null);

    assertNotNull(dnCertClient.getCertificate(cert1.getSerialNumber()
        .toString()));
    assertNotNull(dnCertClient.getCertificate(cert2.getSerialNumber()
        .toString()));
    assertNotNull(dnCertClient.getCertificate(cert3.getSerialNumber()
        .toString()));

    assertEquals(2, dnCertClient.getAllCaCerts().size());
    assertThat(dnCertClient.getAllCaCerts()).contains(subCa1);
    assertThat(dnCertClient.getAllCaCerts()).contains(subCa2);
    assertEquals(2, dnCertClient.getAllRootCaCerts().size());
    assertThat(dnCertClient.getAllRootCaCerts()).contains(rootCa1);
    assertThat(dnCertClient.getAllRootCaCerts()).contains(rootCa2);
  }

  @Test
  public void testStoreCertificate() throws Exception {
    KeyPair keyPair = keyGenerator.generateKey();
    X509Certificate cert1 = generateX509Cert(keyPair);
    X509Certificate cert2 = generateX509Cert(keyPair);
    X509Certificate cert3 = generateX509Cert(keyPair);

    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(cert1), CAType.NONE);
    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(cert2), CAType.NONE);
    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(cert3), CAType.NONE);

    assertNotNull(dnCertClient.getCertificate(cert1.getSerialNumber()
        .toString()));
    assertNotNull(dnCertClient.getCertificate(cert2.getSerialNumber()
        .toString()));
    assertNotNull(dnCertClient.getCertificate(cert3.getSerialNumber()
        .toString()));
  }

  @Test
  public void testStoreMultipleRootCACertificate() throws Exception {
    KeyPair keyPair = keyGenerator.generateKey();
    X509Certificate cert1 = generateX509Cert(keyPair);
    X509Certificate cert2 = generateX509Cert(keyPair);
    X509Certificate cert3 = generateX509Cert(keyPair);

    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(cert1), CAType.ROOT);
    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(cert2), CAType.ROOT);
    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(cert3), CAType.ROOT);

    assertEquals(cert1, dnCertClient.getCertificate(cert1.getSerialNumber()
        .toString()));
    assertEquals(cert2, dnCertClient.getCertificate(cert2.getSerialNumber()
        .toString()));
    assertEquals(cert3, dnCertClient.getCertificate(cert3.getSerialNumber()
        .toString()));
  }

  @Test
  public void testInitCertAndKeypairValidationFailures() throws Exception {
    GenericTestUtils.LogCapturer dnClientLog = GenericTestUtils.LogCapturer
        .captureLogs(dnCertClient.getLogger());
    KeyPair keyPair = keyGenerator.generateKey();
    KeyPair keyPair1 = keyGenerator.generateKey();
    dnClientLog.clearOutput();

    // Case 1. Expect failure when keypair validation fails.
    FileUtils.deleteQuietly(Paths.get(
        dnSecurityConfig.getKeyLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getPrivateKeyFileName()).toFile());
    FileUtils.deleteQuietly(Paths.get(
        dnSecurityConfig.getKeyLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getPublicKeyFileName()).toFile());
    dnKeyCodec.writePrivateKey(keyPair.getPrivate());
    dnKeyCodec.writePublicKey(keyPair1.getPublic());

    // Check for DN.
    assertEquals(FAILURE, dnCertClient.init());
    assertThat(dnClientLog.getOutput()).contains("Keypair validation failed");
    dnClientLog.clearOutput();

    // Case 2. Expect failure when certificate is generated from different
    // private key and keypair validation fails.
    getCertClient();
    FileUtils.deleteQuietly(Paths.get(
        dnSecurityConfig.getKeyLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getCertificateFileName()).toFile());

    certificateStorage.writeCertificate(Paths.get(dnSecurityConfig.getCertificateLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getCertificateFileName()), x509Certificate);
    // Check for DN.
    assertEquals(FAILURE, dnCertClient.init());
    assertThat(dnClientLog.getOutput()).contains("Keypair validation failed");
    dnClientLog.clearOutput();

    // Case 3. Expect failure when certificate is generated from different
    // private key and certificate validation fails.

    // Re-write the correct public key.
    FileUtils.deleteQuietly(Paths.get(
        dnSecurityConfig.getKeyLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getPublicKeyFileName()).toFile());
    getCertClient();
    dnKeyCodec.writePublicKey(keyPair.getPublic());

    // Check for DN.
    assertEquals(FAILURE, dnCertClient.init());
    assertThat(dnClientLog.getOutput())
        .contains("Stored certificate is generated with different");
    dnClientLog.clearOutput();

    // Case 4. Failure when public key recovery fails.
    getCertClient();
    FileUtils.deleteQuietly(Paths.get(
        dnSecurityConfig.getKeyLocation(DN_COMPONENT).toString(),
        dnSecurityConfig.getPublicKeyFileName()).toFile());

    // Check for DN.
    assertEquals(FAILURE, dnCertClient.init());
    assertThat(dnClientLog.getOutput()).contains("Can't recover public key");
  }

  @Test
  public void testTimeBeforeExpiryGracePeriod() throws Exception {
    KeyPair keyPair = keyGenerator.generateKey();
    Duration gracePeriod = dnSecurityConfig.getRenewalGracePeriod();

    X509Certificate cert = KeyStoreTestUtil.generateCertificate("CN=Test",
        keyPair, (int) (gracePeriod.toDays()),
        dnSecurityConfig.getSignatureAlgo());
    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(cert), CAType.SUBORDINATE);
    Duration duration = dnCertClient.timeBeforeExpiryGracePeriod(cert);
    assertTrue(duration.isZero());

    cert = KeyStoreTestUtil.generateCertificate("CN=Test",
        keyPair, (int) (gracePeriod.toDays() + 1),
        dnSecurityConfig.getSignatureAlgo());
    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(cert), CAType.SUBORDINATE);
    duration = dnCertClient.timeBeforeExpiryGracePeriod(cert);
    assertThat(duration.toMillis()).isLessThan(Duration.ofDays(1).toMillis())
        .isGreaterThan(Duration.ofHours(23).plusMinutes(59).toMillis());
  }

  @Test
  public void testRenewAndStoreKeyAndCertificate() throws Exception {
    // save the certificate on dn
    certificateStorage.writeCertificate(dnSecurityConfig.getCertFilePath(DN_COMPONENT), x509Certificate);

    X509Certificate newCert = generateX509Cert(null);
    String pemCert = certificateCodec.getPEMEncodedString(newCert);
    SCMGetCertResponseProto responseProto =
        SCMGetCertResponseProto
            .newBuilder().setResponseCode(
                SCMGetCertResponseProto
                    .ResponseCode.success)
            .setX509Certificate(pemCert)
            .setX509CACertificate(pemCert)
            .build();
    when(scmSecurityClient.getDataNodeCertificateChain(any(), anyString()))
        .thenReturn(responseProto);

    String certID = dnCertClient.getCertificate().getSerialNumber().toString();
    // a success renew
    String newCertId = dnCertClient.renewAndStoreKeyAndCertificate(true);
    assertNotEquals(certID, newCertId);
    assertEquals(dnCertClient.getCertificate().getSerialNumber()
        .toString(), certID);

    File newKeyDir = new File(dnSecurityConfig.getKeyLocation(
        dnCertClient.getComponentName()).toString() +
            HddsConfigKeys.HDDS_NEW_KEY_CERT_DIR_NAME_SUFFIX);
    File newCertDir = new File(dnSecurityConfig.getCertificateLocation(
        dnCertClient.getComponentName()).toString() +
            HddsConfigKeys.HDDS_NEW_KEY_CERT_DIR_NAME_SUFFIX);
    File backupKeyDir = new File(dnSecurityConfig.getKeyLocation(
        dnCertClient.getComponentName()).toString() +
            HddsConfigKeys.HDDS_BACKUP_KEY_CERT_DIR_NAME_SUFFIX);
    File backupCertDir = new File(dnSecurityConfig.getCertificateLocation(
        dnCertClient.getComponentName()).toString() +
            HddsConfigKeys.HDDS_BACKUP_KEY_CERT_DIR_NAME_SUFFIX);

    // backup directories exist
    assertTrue(backupKeyDir.exists());
    assertTrue(backupCertDir.exists());
    // new directories should not exist
    assertFalse(newKeyDir.exists());
    assertFalse(newCertDir.exists());

    // cleanup backup key and cert dir
    dnCertClient.cleanBackupDir();

    Files.createDirectories(newKeyDir.toPath());
    Files.createDirectories(newCertDir.toPath());
    KeyPair keyPair = KeyStoreTestUtil.generateKeyPair("RSA");
    KeyCodec newKeyCodec = new KeyCodec(dnSecurityConfig, newKeyDir.toPath());
    newKeyCodec.writeKey(keyPair);

    X509Certificate cert = KeyStoreTestUtil.generateCertificate(
        "CN=OzoneMaster", keyPair, 30, "SHA256withRSA");

    dnCertClient.storeCertificate(certificateCodec.getPEMEncodedString(cert), CAType.NONE,
        newCertDir.toPath(), false, false);
    // a success renew after auto cleanup new key and cert dir
    dnCertClient.renewAndStoreKeyAndCertificate(true);
  }

  /**
   * This test aims to test the side effects of having an executor in the
   * background that renews the component certificate if needed.
   * During close, we need to shut down this executor in order to ensure that
   * there are no racing threads that are renewing the same set of certificates.
   *
   * The test checks if at instantiation the thread is created and there
   * is only one thread that are being created, while it also checks that after
   * close the thread is closed, and is not there anymore.
   *
   * @param metaDir the temporary folder for metadata persistence.
   *
   * @throws Exception in case an unexpected error happens.
   */
  @Test
  public void testCloseCertificateClient(@TempDir File metaDir)
      throws Exception {
    OzoneConfiguration ozoneConf = new OzoneConfiguration();
    ozoneConf.set(HDDS_METADATA_DIR_NAME, metaDir.getPath());
    SecurityConfig conf = new SecurityConfig(ozoneConf);
    String compName = "test";

    X509Certificate cert = generateX509Cert(null);
    certificateStorage.writeCertificate(conf.getCertFilePath(compName), cert);

    Logger logger = mock(Logger.class);
    String certId = cert.getSerialNumber().toString();
    DefaultCertificateClient client = new DefaultCertificateClient(
        conf, null, logger, certId, compName, "", null, null
    ) {

      @Override
      protected String signAndStoreCertificate(
          PKCS10CertificationRequest request, Path certificatePath) {
        return "";
      }

      @Override
      protected SCMGetCertResponseProto getCertificateSignResponse(
          PKCS10CertificationRequest request) {
        return null;
      }

      @Override
      protected String signAndStoreCertificate(
          PKCS10CertificationRequest request, Path certWritePath,
          boolean renew) {
        return null;
      }
    };

    Thread[] threads = new Thread[Thread.activeCount()];
    Thread.enumerate(threads);
    Predicate<Thread> monitorFilterPredicate =
        t -> t != null
            && t.getName().equals(compName + "-CertificateRenewerService");
    long monitorThreadCount = Arrays.stream(threads)
        .filter(monitorFilterPredicate)
        .count();
    assertThat(monitorThreadCount).isEqualTo(1L);
    Thread monitor = Arrays.stream(threads)
        .filter(monitorFilterPredicate)
        .findFirst()
        .get(); // we should have one otherwise prev assertion fails.

    client.close();
    monitor.join();

    threads = new Thread[Thread.activeCount()];
    monitorThreadCount = Arrays.stream(threads)
        .filter(monitorFilterPredicate)
        .count();
    assertThat(monitorThreadCount).isEqualTo(0L);
  }
}
