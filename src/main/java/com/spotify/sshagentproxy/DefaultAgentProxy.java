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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;
import com.google.common.base.Throwables;
import com.google.common.collect.Lists;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.channels.Channels;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Iterator;
import java.util.List;

import jnr.unixsocket.UnixSocketAddress;
import jnr.unixsocket.UnixSocketChannel;

import static com.google.common.base.Strings.isNullOrEmpty;

/**
 * AgentProxy is intended for command line tools where their invoker
 * also controls an ssh-agent process that can be contacted via a UNIX
 * referenced by the SSH_AUTH_SOCK environment variable.
 */
public class DefaultAgentProxy implements AgentProxy {

  private static final Logger log = LoggerFactory.getLogger(DefaultAgentProxy.class);

  private final AgentInput in;
  private final AgentOutput out;

  @SuppressWarnings("unused")
  public DefaultAgentProxy() {
    final String socketPath = System.getenv("SSH_AUTH_SOCK");
    if (isNullOrEmpty(socketPath)) {
      throw new RuntimeException(
          "The environment variable SSH_AUTH_SOCK is not set. Please configure your ssh-agent.");
    }

    try {
      final UnixSocketChannel channel = UnixSocketChannel.open(
          new UnixSocketAddress(new File(socketPath)));

      log.debug("connected to " + channel.getRemoteSocketAddress());

      in = new AgentInput(Channels.newInputStream(channel));
      out = new AgentOutput(Channels.newOutputStream(channel));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @VisibleForTesting
  DefaultAgentProxy(final AgentOutput out, final AgentInput in) {
    this.out = out;
    this.in = in;
  }

  @Override
  public List<Identity> list() {
    final List<Identity> identities = Lists.newArrayList();

    try {
      out.requestIdentities();

      final IdentitiesAnswer answer = in.readIdentitiesAnswer();
      final Iterator<Identity> keyIterator = in.readIdentitiesAnswerData2(answer);

      while (keyIterator.hasNext()) {
        identities.add(keyIterator.next());
      }
    } catch (IOException e) {
      throw Throwables.propagate(e);
    }

    return identities;
  }

  @Override
  public byte[] sign(final byte[] data, final KeyFingerprint fingerprint)
      throws IllegalArgumentException, KeyNotFoundException {
    final PublicKey publicKey;
    try {
      publicKey = findKey(fingerprint);
    } catch (IOException e) {
      throw Throwables.propagate(e);
    }

    if (publicKey == null) {
      throw new KeyNotFoundException("Your ssh-agent does not have the required key added. "
                                     + "This usually indicates that ssh-add has not been run.");
    }

    final String keyType = "ssh-" + publicKey.getAlgorithm().toLowerCase();
    if (!keyType.equals(RSA.RSA_LABEL)) {
      throw Throwables.propagate(new RuntimeException(String.format(
          "Unknown key type %s. This code currently only supports %s.", keyType, RSA.RSA_LABEL)));
    }

    try {
      out.signRequest((RSAPublicKey) publicKey, data);
      final SignResponse response = in.readSignResponse();
      final Iterator<byte[]> iterator = in.readSignResponseData(response);

      final byte[] responseType = iterator.next();

      // TODO (dxia) Support other SSH keys
      final String signatureFormatId = new String(responseType);
      if (!signatureFormatId.equals(RSA.RSA_LABEL)) {
        throw new RuntimeException("I unexpectedly got a non-RSA signature format ID in the "
                                   + "SSH2_AGENT_SIGN_RESPONSE's signature blob.");
      }

      return iterator.next();
    } catch (IOException e) {
      throw Throwables.propagate(e);
    }
  }

  /**
   * Get the SSH public key from the ssh-agent based on fingerprint.
   * @param fingerprint {@link KeyFingerprint} of the SSH public key to find.
   * @return Corresponding {@link PublicKey}
   * @throws IOException
   */
  private PublicKey findKey(final KeyFingerprint fingerprint) throws IOException {
    out.requestIdentities();
    final IdentitiesAnswer answer = in.readIdentitiesAnswer();
    final Iterator<RSAPublicKey> keyIterator = in.readIdentitiesAnswerData(answer);

    while (keyIterator.hasNext()) {
      final RSAPublicKey key = keyIterator.next();
      if (fingerprint.matches(key)) {
        return key;
      }
    }

    // If we get here, it means there's no key with the requested finger print.
    return null;
  }

  @Override
  public void close() throws Exception {
    out.close();
    in.close();
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
        .toString();
  }
}

