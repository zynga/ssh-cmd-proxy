package com.zynga.aquinney.sshcmdproxy;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.StreamCorruptedException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.sshd.agent.common.AbstractAgentProxy;
import org.apache.sshd.agent.unix.AgentClient;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.FactoryManagerHolder;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * Basically a copy of the MINA AgentClient class:
 *
 * <p><a
 * href="https://github.com/apache/mina-sshd/blob/sshd-2.12.1/sshd-core/src/main/java/org/apache/sshd/agent/unix/AgentClient.java">AgentClient</a>
 *
 * <p>The difference is that this uses the Java 16 support for UNIX domain sockets instead of
 * relying on the Apache Portable Runtime and Tomcat Native, thus eliminating the dependence on
 * having an external set of system-dependent libraries preinstalled.
 */
class UnixSocketAgentClient extends AbstractAgentProxy implements Runnable, FactoryManagerHolder {
  private final String authSocket;
  private final FactoryManager manager;
  private final Buffer receiveBuffer;
  private final Queue<Buffer> messages;
  private final SocketChannel channel;
  private final Future<?> pumper;
  private final AtomicBoolean open = new AtomicBoolean(true);

  public UnixSocketAgentClient(FactoryManager manager, String authSocket) throws IOException {
    this(manager, authSocket, null);
  }

  public UnixSocketAgentClient(
      FactoryManager manager, String authSocket, CloseableExecutorService executor)
      throws IOException {
    super(
        (executor == null)
            ? ThreadUtils.newSingleThreadExecutor("UnixSocketAgentClient[" + authSocket + "]")
            : executor);
    this.manager = Objects.requireNonNull(manager, "No factory manager instance provided");
    this.authSocket = authSocket;
    this.receiveBuffer = new ByteArrayBuffer();
    this.messages = new ArrayBlockingQueue<>(10);
    this.channel = SocketChannel.open(StandardProtocolFamily.UNIX);
    try {
      if (!this.channel.connect(UnixDomainSocketAddress.of(authSocket))) {
        throw new SshException("Could not connect to UNIX socket: " + authSocket);
      }
    } catch (SshException sshe) {
      throw sshe;
    } catch (Throwable t) {
      throw new SshException("Error connecting to UNIX socket: " + authSocket, t);
    }
    this.pumper = getExecutorService().submit(this);
  }

  @Override
  public FactoryManager getFactoryManager() {
    return manager;
  }

  public String getAuthSocket() {
    return authSocket;
  }

  @Override
  public boolean isOpen() {
    return open.get();
  }

  @Override
  public void run() {
    try {
      final ByteBuffer buffer = ByteBuffer.allocate(1024);
      final byte[] bytes = new byte[buffer.limit()];
      while (isOpen()) {
        buffer.clear();
        final int bytesRead = channel.read(buffer);
        if (bytesRead < 0) {
          throw new IOException("Stream finished.");
        }
        buffer.flip();
        buffer.get(bytes, 0, buffer.limit());
        messageReceived(new ByteArrayBuffer(bytes, 0, bytesRead));
      }
    } catch (Exception e) {
      boolean debugEnabled = log.isDebugEnabled();
      if (isOpen()) {
        log.warn(
            "run({}) {} while still open: {}", this, e.getClass().getSimpleName(), e.getMessage());
        if (debugEnabled) {
          log.debug("run(" + this + ") open client exception", e);
        }
      } else {
        if (debugEnabled) {
          log.debug("run(" + this + ") closed client loop exception", e);
        }
      }
    } finally {
      try {
        close();
      } catch (IOException e) {
        if (log.isDebugEnabled()) {
          log.debug(
              "run({}) {} while closing: {}", this, e.getClass().getSimpleName(), e.getMessage());
        }
      }
    }
  }

  protected void messageReceived(Buffer buffer) throws Exception {
    Buffer message = null;
    synchronized (receiveBuffer) {
      receiveBuffer.putBuffer(buffer);
      if (receiveBuffer.available() >= Integer.BYTES) {
        int rpos = receiveBuffer.rpos();
        int len = receiveBuffer.getInt();
        // Protect against malicious or corrupted packets
        if (len < 0) {
          throw new StreamCorruptedException("Illogical message length: " + len);
        }
        receiveBuffer.rpos(rpos);
        if (receiveBuffer.available() >= (Integer.BYTES + len)) {
          message = new ByteArrayBuffer(receiveBuffer.getBytes());
          receiveBuffer.compact();
        }
      }
    }
    if (message != null) {
      synchronized (messages) {
        messages.offer(message);
        messages.notifyAll();
      }
    }
  }

  @Override
  public void close() throws IOException {
    if (open.getAndSet(false)) {
      channel.close();
    }
    // make any waiting thread aware of the closure
    synchronized (messages) {
      messages.notifyAll();
    }
    if ((pumper != null) && (!pumper.isDone())) {
      pumper.cancel(true);
    }
    super.close();
  }

  @Override
  protected synchronized Buffer request(Buffer buffer) throws IOException {
    int wpos = buffer.wpos();
    buffer.wpos(0);
    buffer.putUInt(wpos - 4);
    buffer.wpos(wpos);
    ByteBuffer byteBuffer = ByteBuffer.allocate(buffer.available());
    byteBuffer.put(buffer.array(), buffer.rpos(), buffer.available());
    byteBuffer.flip();
    synchronized (messages) {
      while (byteBuffer.hasRemaining()) {
        channel.write(byteBuffer);
      }
      return waitForMessageBuffer();
    }
  }

  // NOTE: assumes messages lock is obtained prior to calling this method
  protected Buffer waitForMessageBuffer() throws IOException {
    FactoryManager mgr = getFactoryManager();
    long idleTimeout =
        PropertyResolverUtils.getLongProperty(
            mgr, AgentClient.MESSAGE_POLL_FREQUENCY, AgentClient.DEFAULT_MESSAGE_POLL_FREQUENCY);
    if (idleTimeout <= 0L) {
      idleTimeout = AgentClient.DEFAULT_MESSAGE_POLL_FREQUENCY;
    }
    boolean traceEnabled = log.isTraceEnabled();
    for (int count = 1; ; count++) {
      if (!isOpen()) {
        throw new SshException("Client is being closed");
      }
      if (!messages.isEmpty()) {
        return messages.poll();
      }
      if (traceEnabled) {
        log.trace("waitForMessageBuffer({}) wait iteration #{}", this, count);
      }
      try {
        messages.wait(idleTimeout);
      } catch (InterruptedException e) {
        throw (IOException)
            new InterruptedIOException(
                    "Interrupted while waiting for messages at iteration #" + count)
                .initCause(e);
      }
    }
  }

  @Override
  public String toString() {
    return getClass().getSimpleName() + "[socket=" + getAuthSocket() + "]";
  }
}
