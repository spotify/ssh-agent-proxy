/*-
 * -\-\-
 * ssh-agent-proxy
 * --
 * Copyright (C) 2016 Spotify AB
 * --
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -/-/-
 */

/**
 * Copyright (c) 2015 Spotify AB.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.spotify.sshagentproxy;

import static com.google.common.base.Strings.isNullOrEmpty;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;
import com.google.common.base.Throwables;
import java.io.File;
import java.io.IOException;
import java.nio.channels.Channels;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import jnr.unixsocket.UnixSocketAddress;
import jnr.unixsocket.UnixSocketChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class contains a static factory method that creates a default implementation of
 * {@link AgentProxy}.
 */
public class AgentProxies {

  public static AgentProxy newInstance() {
    return DefaultAgentProxy.fromEnvironmentVariable();
  }

  static AgentProxy withCustomInputOutput(final AgentInput in, final AgentOutput out) {
    return new DefaultAgentProxy(in, out);
  }

  static class DefaultAgentProxy implements AgentProxy {

    private static final Logger log = LoggerFactory.getLogger(DefaultAgentProxy.class);

    private final AgentInput in;
    private final AgentOutput out;

    public static DefaultAgentProxy fromEnvironmentVariable() {
      final String socketPath = System.getenv("SSH_AUTH_SOCK");
      if (isNullOrEmpty(socketPath)) {
        throw new RuntimeException(
            "The environment variable SSH_AUTH_SOCK is not set. Please configure your ssh-agent.");
      }

      try {
        final UnixSocketChannel channel = UnixSocketChannel.open(
            new UnixSocketAddress(new File(socketPath)));

        log.debug("connected to " + channel.getRemoteSocketAddress());

        return new DefaultAgentProxy(new AgentInput(Channels.newInputStream(channel)),
                                     new AgentOutput(Channels.newOutputStream(channel)));
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    @VisibleForTesting
    DefaultAgentProxy(final AgentInput in, final AgentOutput out) {
      this.out = out;
      this.in = in;
    }

    @Override
    public List<Identity> list() throws IOException {
      out.requestIdentities();
      return in.readIdentitiesAnswer();
    }

    @Override
    public byte[] sign(final Identity identity, final byte[] data) throws IOException {
      // TODO (dxia) Support other SSH keys
      final String keyFormat = identity.getKeyFormat();
      if (!keyFormat.equals(Rsa.RSA_LABEL)) {
        throw Throwables.propagate(new RuntimeException(String.format(
            "Unknown key type %s. This code currently only supports %s.",
            keyFormat, Rsa.RSA_LABEL)));
      }

      out.signRequest((RSAPublicKey) identity.getPublicKey(), data);
      return in.readSignResponse();
    }

    @Override
    public void close() throws IOException {
      out.close();
      in.close();
    }

    @Override
    public String toString() {
      return Objects.toStringHelper(this)
          .toString();
    }
  }
}

