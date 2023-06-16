package org.apache.hadoop.hdds.security.x509.certificate.client;

import org.apache.hadoop.hdds.security.x509.SecurityConfig;
import org.apache.hadoop.util.ClosableIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class RootCaRotationPoller implements Runnable, Closeable {

  private List<Consumer<List<String>>> rootCaListConsumers;
  private ScheduledExecutorService poller;
  private Duration duration;
  private static final Logger LOG =
      LoggerFactory.getLogger(RootCaRotationPoller.class);

  RootCaRotationPoller(SecurityConfig securityConfig) {
    poller = Executors.newSingleThreadScheduledExecutor();
    duration = securityConfig.getRootCaClientPollingFrequency();
  }

  private void pollRootCas() {
    List<String> rootCaList = new ArrayList<>(); //TODO
    rootCaListConsumers.forEach(c -> c.accept(rootCaList));
  }

  public void addRootCaRotationConsumer(Consumer<List<String>> consumer) {
    rootCaListConsumers.add(consumer);
  }

  @Override
  public void run() {
    poller.scheduleAtFixedRate(this::pollRootCas, 0,
        duration.getSeconds(), TimeUnit.SECONDS);
  }

  @Override
  public void close() {
    executorServiceShutdownGraceful(poller);
  }

  private void executorServiceShutdownGraceful(ExecutorService executor) {
    executor.shutdown();
    try {
      if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
        executor.shutdownNow();
      }

      if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
        LOG.error("Unable to shutdown state machine properly.");
      }
    } catch (InterruptedException e) {
      LOG.error("Error attempting to shutdown.", e);
      executor.shutdownNow();
      Thread.currentThread().interrupt();
    }
  }
}
