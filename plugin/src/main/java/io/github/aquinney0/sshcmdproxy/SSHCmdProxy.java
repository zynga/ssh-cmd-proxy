package io.github.aquinney0.sshcmdproxy;

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import javax.inject.Inject;
import org.gradle.api.*;
import org.gradle.api.flow.FlowAction;
import org.gradle.api.flow.FlowParameters;
import org.gradle.api.flow.FlowProviders;
import org.gradle.api.flow.FlowScope;
import org.gradle.api.initialization.Settings;
import org.gradle.api.provider.Property;
import org.gradle.api.provider.ProviderFactory;
import org.gradle.api.tasks.Input;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class SSHCmdProxy
    implements Plugin<Settings>, Closeable, ProxyInstance.ConfigurationSource {
  private static final Logger logger = LoggerFactory.getLogger(SSHCmdProxy.class);
  private final Map<URI, ProxyInstance> proxyInstances = new ConcurrentHashMap<>();

  @Inject
  protected abstract FlowScope getFlowScope();

  @Inject
  protected abstract FlowProviders getFlowProviders();

  @Inject
  protected abstract ProviderFactory getProviderFactory();

  @Override
  public void apply(final Settings settings) {
    getFlowScope()
        .always(
            ProxyClose.class,
            spec ->
                spec.getParameters()
                    .getTarget()
                    .set(
                        getFlowProviders()
                            .getBuildWorkResult()
                            .map(
                                result -> {
                                  logger.info(
                                      "Build completion (success: {}), queuing close action.",
                                      result.getFailure().isEmpty());
                                  return SSHCmdProxy.this;
                                })));
  }

  private URI getProxy(final Supplier<String> identifier, final String uri) {
    final URI inputURI = URI.create(uri);
    try {
      if (!"ssh".equals(inputURI.getScheme().toLowerCase(Locale.US))) {
        throw new RuntimeException("Invalid scheme: " + inputURI.getScheme());
      }
      final URI proxyURI =
          proxyInstances
              .compute(
                  new URI(
                      inputURI.getScheme().toLowerCase(Locale.US),
                      null,
                      inputURI.getHost(),
                      inputURI.getPort(),
                      null,
                      null,
                      null),
                  (key, proxyInstance) -> {
                    if (proxyInstance != null) {
                      logger.info("Found preexisting proxy: {}", inputURI);
                      return proxyInstance;
                    }
                    try {
                      logger.info("Creating proxy: {}", inputURI);
                      final MessageDigest md = MessageDigest.getInstance("SHA-256");
                      md.update(identifier.get().getBytes(StandardCharsets.UTF_8));
                      md.update(key.toString().getBytes(StandardCharsets.UTF_8));
                      // The same root project directory and Git server should attempt the same port
                      // every time. This is an optimization to prevent unnecessary repository
                      // cloning.
                      return new ProxyInstance(
                          key,
                          7272 + (new BigInteger(1, md.digest(), 0, 2).intValue() >> 1),
                          SSHCmdProxy.this);
                    } catch (Throwable e) {
                      throw new RuntimeException(e);
                    }
                  })
              .getURI();
      return new URI(
          proxyURI.getScheme(),
          inputURI.getUserInfo(),
          proxyURI.getHost(),
          proxyURI.getPort(),
          inputURI.getPath(),
          inputURI.getQuery(),
          inputURI.getFragment());
    } catch (Throwable t) {
      logger.warn("Unable to proxy Git service: {}, skipping proxy. {}", uri, t.getMessage());
      return inputURI;
    }
  }

  public static URI sshProxy(final Settings settings, final String uri) {
    return settings
        .getPlugins()
        .getPlugin(SSHCmdProxy.class)
        .getProxy(
            () -> {
              try {
                return settings.getRootDir().getCanonicalPath();
              } catch (IOException e) {
                throw new RuntimeException(e);
              }
            },
            uri);
  }

  @Override
  public void close() {
    final Collection<URI> keys = new ArrayList<>(proxyInstances.keySet());
    for (final URI key : keys) {
      proxyInstances.computeIfPresent(
          key,
          (uri, proxyInstance) -> {
            try {
              proxyInstance.close();
            } catch (Throwable t) {
              logger.warn("Error closing proxy: {}", proxyInstance.getURI());
            }
            return null;
          });
    }
  }

  @Override
  public Optional<String> getProperty(final String propertyName) {
    final Optional<String> result =
        Optional.ofNullable(getProviderFactory().gradleProperty(propertyName).getOrNull());
    result.ifPresentOrElse(
        value -> logger.info("Read property '{}'.", propertyName),
        () -> logger.info("No value for property '{}'", propertyName));
    return result;
  }

  @Override
  public Collection<String> getProperties(String propertyNamePrefix) {
    final Map<String, String> properties =
        Optional.ofNullable(
                getProviderFactory().gradlePropertiesPrefixedBy(propertyNamePrefix).getOrNull())
            .orElse(Collections.emptyMap());
    logger.info(
        "Read keys for property prefix '{}': {}",
        propertyNamePrefix,
        new ArrayList<>(properties.keySet()));
    return properties.values();
  }

  static class ProxyClose implements FlowAction<ProxyClose.Parameters> {
    interface Parameters extends FlowParameters {
      @Input
      Property<Closeable> getTarget();
    }

    @Override
    public void execute(ProxyClose.Parameters parameters) {
      try {
        parameters.getTarget().get().close();
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
