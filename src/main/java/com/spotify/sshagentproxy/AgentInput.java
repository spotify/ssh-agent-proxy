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

import com.google.common.base.Objects;
import com.google.common.base.Throwables;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAPublicKey;
import java.util.Iterator;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;

/**
 * A class that represents ssh-agent input.
 */
class AgentInput implements Closeable {

  private static final Logger log = LoggerFactory.getLogger(AgentInput.class);

  private final InputStream in;

  AgentInput(final InputStream in) {
    checkNotNull(in, "InputStream cannot be null.");
    this.in = in;
  }

  /**
   * Read the first 9 bytes from the {@link InputStream} which make up the SSH2_AGENT_SIGN_RESPONSE
   * headers. Return an {@link SignResponse} object that represents the message.
   * @return {@link SignResponse}
   */
   SignResponse readSignResponse() throws IOException {
     final byte[] bytes = readBytes(9, "SSH2_AGENT_SIGN_RESPONSE");
     log.debug("Received SSH2_AGENT_SIGN_RESPONSE message from ssh-agent.");
     return SignResponse.from(bytes);
   }

  /**
   * Read the rest of the SSH2_AGENT_SIGN_RESPONSE message from ssh-agent given a
   * {@link SignResponse}.
   * @param signResponse {@link SignResponse}
   * @return byte[]
   * @throws IOException
   */
  Iterator<byte[]> readSignResponseData(final SignResponse signResponse) throws IOException {
    // 5 is the sum of the number of bytes of response code and response length
    final byte[] bytes = readBytes(signResponse.getLength() - 5);
    return new ByteIterator(bytes);
  }

  /**
   * Read the first 9 bytes from the {@link InputStream} which make up the
   * SSH2_AGENT_IDENTITIES_ANSWER headers. Return an {@link IdentitiesAnswer} object that
   * represents the message.
   * @return {@link IdentitiesAnswer}
   */
  IdentitiesAnswer readIdentitiesAnswer() throws IOException {
    final byte[] bytes = readBytes(9, "SSH2_AGENT_IDENTITIES_ANSWER");
    log.debug("Received SSH2_AGENT_IDENTITIES_ANSWER message from ssh-agent.");
    return IdentitiesAnswer.from(bytes);
  }

  /**
   * Returns an {@link Iterator} of {@link RSAPublicKey} given an {@link IdentitiesAnswer}.
   * @param answer {@link IdentitiesAnswer}
   * @return Iterator&lt;RSAPublicKey&gt;
   * @throws IOException
   */
  Iterator<RSAPublicKey> readIdentitiesAnswerData(final IdentitiesAnswer answer)
      throws IOException {
    // 5 is the sum of the number of bytes of response code and count
    final byte[] bytes = readBytes(answer.getLength() - 5);
    return new RSAPublicKeyIterator(bytes);
  }

  /**
   * Returns an {@link Iterator} of {@link Identity} given an {@link IdentitiesAnswer}.
   * @param answer {@link IdentitiesAnswer}
   * @return Iterator&lt;Identitygt;
   * @throws IOException
   */
  Iterator<Identity> readIdentitiesAnswerData2(final IdentitiesAnswer answer)
      throws IOException {
    // 5 is the sum of the number of bytes of response code and count
    final byte[] bytes = readBytes(answer.getLength() - 5);
    return new IdentityIterator(bytes);
  }

  /**
   * Read n bytes from the {@link InputStream}.
   * @param n bytes to read
   * @return byte[]
   */
  private byte[] readBytes(final int n) throws IOException {
    return readBytes(n, null);
  }

  /**
   * Read n bytes from the {@link InputStream}.
   * @param n bytes to read
   * @param messageType An optional String indicating the expected SSH2 agent's message type.
   * @return byte[]
   */
  private byte[] readBytes(final int n, String messageType) throws IOException {
    final String errMsg = isNullOrEmpty(messageType) ?
                          "Error reading from ssh-agent." :
                          "Error reading " + messageType + " from ssh-agent.";

    final byte[] result = new byte[n];

    final int bytesRead;
    try {
      bytesRead = in.read(result, 0, n);
    } catch (IOException e) {
      log.error(errMsg);
      throw Throwables.propagate(e);
    }

    if (bytesRead == -1) {
      log.error(errMsg);
      throw new IOException(errMsg);
    }

    return result;
  }

  @Override
  public void close() throws IOException {
    in.close();
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
        .add("in", in)
        .toString();
  }
}
