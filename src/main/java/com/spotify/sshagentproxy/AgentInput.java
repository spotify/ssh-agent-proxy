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
import com.google.common.collect.Lists;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;
import java.util.List;

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
   * Return a list of {@link Identity} from the bytes in the ssh-agent's {@link InputStream}.
   * @return A list of {@link Identity}
   * @throws IOException
   */
  List<Identity> readIdentitiesAnswer() throws IOException {
    // Read the first 9 bytes from the InputStream which are the
    // SSH2_AGENT_IDENTITIES_ANSWER headers. Return an IdentitiesAnswerHeaders object that
    // represents the message.
    final byte[] headerBytes = readBytes(9, "SSH2_AGENT_IDENTITIES_ANSWER");
    log.debug("Received SSH2_AGENT_IDENTITIES_ANSWER message from ssh-agent.");
    final IdentitiesAnswerHeaders headers = IdentitiesAnswerHeaders.from(headerBytes);

    // 5 is the sum of the number of bytes of response code and count
    final byte[] bytes = readBytes(headers.getLength() - 5);
    final Iterator<byte[]> byteIterator = new ByteIterator(bytes);

    final List<Identity> identities = Lists.newArrayList();
    while (byteIterator.hasNext()) {
      final byte[] keyBlob = byteIterator.next();
      final byte[] keyComment = byteIterator.next();
      try {
        identities.add(DefaultIdentity.from(keyBlob, new String(keyComment)));
      } catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException ignored) {
        log.warn("Unable to parse SSH identity. Skipping.");
        byteIterator.next();
      }
    }

    return identities;
  }

  /**
   * Return an array of bytes from the ssh-agent representing data signed by a private SSH key.
   * @return An array of signed bytes.
   * @throws IOException
   */
   byte[] readSignResponse() throws IOException {
     // Read the first 9 bytes from the InputStream which are the SSH2_AGENT_SIGN_RESPONSE headers.
     final byte[] headerBytes = readBytes(9, "SSH2_AGENT_SIGN_RESPONSE");
     log.debug("Received SSH2_AGENT_SIGN_RESPONSE message from ssh-agent.");
     final SignResponseHeaders headers = SignResponseHeaders.from(headerBytes);

     // Read the rest of the SSH2_AGENT_SIGN_RESPONSE message from ssh-agent.
     // 5 is the sum of the number of bytes of response code and response length
     final byte[] bytes = readBytes(headers.getLength() - 5);
     final ByteIterator iterator = new ByteIterator(bytes);
     final byte[] responseType = iterator.next();

     final String signatureFormatId = new String(responseType);
     if (!signatureFormatId.equals(RSA.RSA_LABEL)) {
       throw new RuntimeException("I unexpectedly got a non-RSA signature format ID in the "
                                  + "SSH2_AGENT_SIGN_RESPONSE's signature blob.");
     }

     return iterator.next();
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
