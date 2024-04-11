package com.zynga.aquinney.sshcmdproxy;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.unix.UnixAgentFactory;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.config.hosts.HostPatternsHolder;
import org.apache.sshd.client.config.hosts.KnownHostEntry;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.EdDSASecurityProviderRegistrar;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.command.AbstractCommandSupport;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ProxyInstance implements Closeable {
  private static final Logger logger = LoggerFactory.getLogger(ProxyInstance.class);
  private static final String localhost = InetAddress.getLoopbackAddress().getHostName();

  static {
    /**
     * When included in a Gradle build, a conflicting classloader registers an instance of the EdDSA
     * security provider that this cannot use. This sets it back to the version from this
     * classloader. The EdDSA implementation is sensitive to the classloader (uses 'instanceof').
     */
    Security.removeProvider(SecurityUtils.EDDSA);
    Security.addProvider(new EdDSASecurityProviderRegistrar().getSecurityProvider());
  }

  private final SshServer sshServer;

  public ProxyInstance(
      final URI gitService, final int targetPort, final ConfigurationSource configurationSource)
      throws IOException {
    final SimpleGeneratorHostKeyProvider idProvider =
        new SimpleGeneratorHostKeyProvider() {
          {
            setAlgorithm("RSA");
          }
        };
    try {
      sshServer =
          ((Supplier<SshServer>)
                  () -> {
                    for (int port = targetPort; port < 65536 && port - targetPort < 100; port++) {
                      final SshServer sshd = SshServer.setUpDefaultServer();
                      try {
                        sshd.setHost(localhost);
                        sshd.setKeyPairProvider(idProvider);
                        // Accept all client certs.
                        sshd.setPublickeyAuthenticator((user, key, session) -> true);
                        // Accept any password.
                        sshd.setPasswordAuthenticator((user, password, session) -> true);
                        sshd.setCommandFactory(
                            (channel, command) -> {
                              try {
                                return new ProxyClient(
                                    command,
                                    null,
                                    new URI(
                                        gitService.getScheme(),
                                        channel.getSession().getUsername(),
                                        gitService.getHost(),
                                        gitService.getPort(),
                                        null,
                                        null,
                                        null),
                                    configurationSource);
                              } catch (URISyntaxException e) {
                                throw new RuntimeException(e);
                              }
                            });
                        sshd.setPort(port);
                        sshd.start();
                        return sshd;
                      } catch (BindException t) {
                        logger.warn("Port {} unavailable for proxy: {}", port, gitService);
                        try {
                          sshd.close();
                        } catch (IOException e) {
                          throw new RuntimeException(e);
                        }
                      } catch (IOException e) {
                        throw new RuntimeException(e);
                      }
                    }
                    throw new RuntimeException("Could not find open port for proxy: " + gitService);
                  })
              .get();
    } catch (RuntimeException re) {
      if (re.getCause() instanceof IOException ioe) {
        throw ioe;
      }
      throw re;
    }
    {
      KnownHostEntry.getDefaultKnownHostsFile().toFile().getParentFile().mkdirs();
      try (final FileChannel channel =
          FileChannel.open(
              KnownHostEntry.getDefaultKnownHostsFile(),
              StandardOpenOption.CREATE,
              StandardOpenOption.WRITE)) {
        channel.lock();
        final byte[] originalKnownHosts =
            Files.readAllBytes(KnownHostEntry.getDefaultKnownHostsFile());
        channel.truncate(0);
        channel.write(
            ByteBuffer.wrap(
                ("["
                        + sshServer.getHost()
                        + "]:"
                        + sshServer.getPort()
                        + " "
                        + PublicKeyEntry.toString(
                            idProvider.loadKeys(null).iterator().next().getPublic())
                        + System.lineSeparator())
                    .getBytes(StandardCharsets.UTF_8)));
        channel.write(ByteBuffer.wrap(originalKnownHosts));
      }
    }
    try {
      logger.info(
          "SSH proxy started: {}->{}",
          getURI(),
          new URI(
              gitService.getScheme(),
              null,
              gitService.getHost(),
              gitService.getPort(),
              null,
              null,
              null));
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  public URI getURI() {
    try {
      return new URI("ssh", null, sshServer.getHost(), sshServer.getPort(), null, null, null);
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void close() throws IOException {
    try {
      sshServer.close();
    } catch (IOException e) {
      logger.warn("Could not close SSH proxy server: " + getURI());
      throw e;
    } finally {
      if (Files.exists(KnownHostEntry.getDefaultKnownHostsFile())) {
        try (final FileChannel channel =
            FileChannel.open(KnownHostEntry.getDefaultKnownHostsFile(), StandardOpenOption.WRITE)) {
          channel.lock();
          final List<String> lines =
              Files.readAllLines(KnownHostEntry.getDefaultKnownHostsFile(), StandardCharsets.UTF_8);
          channel.truncate(0);
          for (final String currentLine : lines) {
            final KnownHostEntry currentEntry = new KnownHostEntry();
            try {
              KnownHostEntry.parseKnownHostEntry(currentEntry, currentLine);
            } catch (Throwable t) { // Swallow it.
            }
            if (currentEntry.getKeyEntry() == null
                || currentEntry.getPatterns().size() != 1
                || !HostPatternsHolder.isSpecificHostPattern(
                    currentEntry.getPatterns().iterator().next().getPattern().toString())
                || !HostPatternsHolder.isHostMatch(
                    sshServer.getHost(), sshServer.getPort(), currentEntry.getPatterns())) {
              channel.write(
                  ByteBuffer.wrap(
                      (currentLine + System.lineSeparator()).getBytes(StandardCharsets.UTF_8)));
            }
          }
        }
      }
    }
    logger.info("SSH proxy closed: {}", getURI());
  }

  public interface ConfigurationSource {
    Optional<String> getProperty(final String propertyName);

    // Never returns null.
    Collection<String> getProperties(final String propertyNamePrefix);
  }

  private static class ProxyClient extends AbstractCommandSupport {
    private final URI gitService;
    private final ConfigurationSource configurationSource;

    public ProxyClient(
        final String command,
        final CloseableExecutorService executorService,
        final URI gitService,
        final ConfigurationSource configurationSource) {
      super(command, executorService);
      try {
        this.gitService =
            new URI(
                gitService.getScheme(),
                gitService.getUserInfo(),
                gitService.getHost(),
                gitService.getPort() > 0 ? gitService.getPort() : SshConstants.DEFAULT_PORT,
                null,
                null,
                null);
      } catch (URISyntaxException e) {
        throw new RuntimeException(e);
      }
      this.configurationSource = configurationSource;
    }

    @Override
    public void run() {
      final Instant startTime = Instant.now();
      try (SshClient sshClient = SshClient.setUpDefaultClient()) {
        if (GenericUtils.isEmpty(sshClient.getString(SshAgent.SSH_AUTHSOCKET_ENV_NAME))
            && !GenericUtils.isEmpty(System.getenv(SshAgent.SSH_AUTHSOCKET_ENV_NAME))) {
          sshClient
              .getProperties()
              .put(
                  SshAgent.SSH_AUTHSOCKET_ENV_NAME,
                  System.getenv(SshAgent.SSH_AUTHSOCKET_ENV_NAME));
        }
        sshClient.setFilePasswordProvider(
            new FilePasswordProvider() {
              private final List<String> keyPasswords =
                  configurationSource
                      .getProperties("com.zynga.aquinney.ssh-cmd-proxy.key-password-")
                      .stream()
                      .toList();

              @Override
              public String getPassword(
                  SessionContext session, NamedResource resourceKey, int retryIndex) {
                return retryIndex < keyPasswords.size() ? keyPasswords.get(retryIndex) : null;
              }

              @Override
              public ResourceDecodeResult handleDecodeAttemptResult(
                  SessionContext session,
                  NamedResource resourceKey,
                  int retryIndex,
                  String password,
                  Exception err) {
                return retryIndex < keyPasswords.size() - 1
                    ? ResourceDecodeResult.RETRY
                    : ResourceDecodeResult.TERMINATE;
              }
            });
        sshClient.start();
        logger.info("[{}] Starting connection...", gitService);
        try (final ClientSession clientSession =
            sshClient
                .connect(gitService.toString())
                .verify(
                    Duration.ofMillis(
                        numberProperty("com.zynga.aquinney.ssh-cmd-proxy.connect-timeout", 3000)))
                .getClientSession()) {
          logger.info("[{}] Connection successful.", gitService);
          if (!GenericUtils.isEmpty(sshClient.getString(SshAgent.SSH_AUTHSOCKET_ENV_NAME))) {
            sshClient.setAgentFactory(
                new UnixAgentFactory() {
                  @Override
                  public SshAgent createClient(Session session, FactoryManager manager)
                      throws IOException {
                    return new UnixSocketAgentClient(
                        manager, sshClient.getString(SshAgent.SSH_AUTHSOCKET_ENV_NAME));
                  }
                });
          }
          sshClient.setPasswordIdentityProvider(
              session -> {
                final InetSocketAddress socketAddress =
                    (InetSocketAddress) clientSession.getConnectAddress();
                final String basePropertyName =
                    "com.zynga.aquinney.ssh-cmd-proxy.password-"
                        + Optional.ofNullable(clientSession.getUsername())
                            .map(username -> username + "@")
                            .orElse("")
                        + socketAddress.getHostName();
                for (final String propertyName :
                    List.of(basePropertyName + ":" + socketAddress.getPort(), basePropertyName)) {
                  final Optional<String> result = configurationSource.getProperty(propertyName);
                  if (result.isPresent()) {
                    return List.of(result.get());
                  }
                  if (socketAddress.getPort() != SshConstants.DEFAULT_PORT) {
                    break;
                  }
                }
                return null;
              });
          logger.info("[{}] Starting authentication...", gitService);
          clientSession
              .auth()
              .verify(
                  Duration.ofMillis(
                      numberProperty("com.zynga.aquinney.ssh-cmd-proxy.auth-timeout", 3000)));
          logger.info("[{}] Authentication successful.", gitService);
          try (final ClientChannel clientChannel = clientSession.createExecChannel(getCommand())) {
            clientChannel.setIn(getInputStream());
            clientChannel.setOut(getOutputStream());
            clientChannel.setErr(getErrorStream());
            logger.info("[{}] Opening channel...", gitService);
            clientChannel
                .open()
                .verify(
                    Duration.ofMillis(
                        numberProperty("com.zynga.aquinney.ssh-cmd-proxy.channel-timeout", 3000)));
            logger.info("[{}] Channel opened successfully.", gitService);
            clientChannel.waitFor(List.of(ClientChannelEvent.CLOSED), 0);
          }
        }
        onExit(0);
        logger.info(
            "[{}] Command successful ({}): {}",
            gitService,
            Duration.between(startTime, Instant.now()),
            getCommand());
      } catch (Throwable t) {
        onExit(1, t.getMessage());
        logger.warn(
            "[{}] Error executing command ({}): {} {}",
            gitService,
            Duration.between(startTime, Instant.now()),
            getCommand(),
            t.getMessage());
      }
    }

    private long numberProperty(String propertyName, long defaultValue) {
      try {
        return configurationSource
            .getProperty(propertyName)
            .map(Long::parseLong)
            .orElse(defaultValue);
      } catch (Throwable t) {
        logger.warn(
            "Unable to parse number from property '{}', using default value of {}.",
            propertyName,
            defaultValue);
        return defaultValue;
      }
    }
  }

  public static void main(String[] args) throws Throwable {
    try (final ProxyInstance proxyInstance =
        new ProxyInstance(
            URI.create("ssh://github.com"),
            7272,
            new ConfigurationSource() {
              @Override
              public Optional<String> getProperty(String propertyName) {
                return Optional.empty();
              }

              @Override
              public Collection<String> getProperties(String propertyNamePrefix) {
                return Collections.emptyList();
              }
            })) {
      Runtime.getRuntime()
          .addShutdownHook(
              new Thread(
                  () -> {
                    try {
                      proxyInstance.close();
                      System.out.println("SHUTDOWN SUCCESSFUL");
                    } catch (IOException e) {
                      throw new RuntimeException(e);
                    }
                  }));
      System.out.println("SERVER STARTED: " + proxyInstance.getURI());
      Thread.sleep(Duration.ofMinutes(10).toMillis());
    }
  }
}
