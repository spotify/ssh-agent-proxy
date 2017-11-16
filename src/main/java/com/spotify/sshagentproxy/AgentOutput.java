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

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.base.Objects;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class that represents the ssh-agent output.
 */
class AgentOutput implements Closeable {

  private static final Logger log = LoggerFactory.getLogger(AgentOutput.class);

  // Number of bytes in an int
  private static final int INT_BYTES = 4;

  // ssh-agent communication protocol constants
  private static final int SSH2_AGENTC_REQUEST_IDENTITIES = 11;
  private static final int SSH2_AGENTC_SIGN_REQUEST = 13;

  private final OutputStream out;

  AgentOutput(final OutputStream out) {
    checkNotNull(out, "OutputStream cannot be null.");
    this.out = out;
  }

  /**
   * Send a SSH2_AGENTC_REQUEST_IDENTITIES message to ssh-agent.
   */
  void requestIdentities() throws IOException {
    writeField(out, SSH2_AGENTC_REQUEST_IDENTITIES);
    log.debug("Sent SSH2_AGENTC_REQUEST_IDENTITIES message to ssh-agent.");
  }

  /**
   * Convert int to a big-endian byte array containing the minimum number of bytes required to
   * represent it. Write those bytes to an {@link OutputStream}.
   * @param out {@link OutputStream}
   * @param num int
   */
  private static void writeField(final OutputStream out, final int num) throws IOException {
    final byte[] bytes = BigInteger.valueOf(num).toByteArray();
    writeField(out, bytes);
  }

  /**
   * Write bytes to an {@link OutputStream} and prepend with four bytes indicating their length.
   * @param out {@link OutputStream}
   * @param bytes Array of bytes.
   */
  private static void writeField(final OutputStream out, final byte[] bytes)
      throws IOException {
    // All protocol messages are prefixed with their length in bytes, encoded
    // as a 32 bit unsigned integer.
    final ByteBuffer buffer = ByteBuffer.allocate(INT_BYTES + bytes.length);
    buffer.putInt(bytes.length);
    buffer.put(bytes);
    out.write(buffer.array());
    out.flush();
  }

  /**
   * Send a SSH2_AGENTC_SIGN_REQUEST message to ssh-agent.
   * @param rsaPublicKey The {@link RSAPublicKey} that tells ssh-agent which private key to use to
   *                     sign the data.
   * @param data         The data in bytes to be signed.
   */
  void signRequest(final RSAPublicKey rsaPublicKey, final byte[] data) throws IOException {
    // TODO (dxia) Support more than just Rsa keys
    final String keyType = Rsa.RSA_LABEL;
    final byte[] publicExponent = rsaPublicKey.getPublicExponent().toByteArray();
    final byte[] modulus = rsaPublicKey.getModulus().toByteArray();

    // Four bytes indicating length of string denoting key type
    // Four bytes indicating length of public exponent
    // Four bytes indicating length of modulus
    final int publicKeyLength = 4 + keyType.length()
                                + 4 + publicExponent.length
                                + 4 + modulus.length;

    // The message is made of:
    // Four bytes indicating length in bytes of rest of message
    // One byte indicating SSH2_AGENTC_SIGN_REQUEST
    // Four bytes denoting length of public key
    // Bytes representing the public key
    // Four bytes for length of data
    // Bytes representing data to be signed
    // Four bytes of flags
    final ByteBuffer buff = ByteBuffer.allocate(
        INT_BYTES + 1 + INT_BYTES + publicKeyLength + INT_BYTES + data.length + 4);

    // 13 =
    // One byte indicating SSH2_AGENTC_SIGN_REQUEST
    // Four bytes denoting length of public key
    // Four bytes for length of data
    // Four bytes of flags
    buff.putInt(publicKeyLength + data.length + 13);
    buff.put((byte) SSH2_AGENTC_SIGN_REQUEST);

    // Add the public key
    buff.putInt(publicKeyLength);
    buff.putInt(keyType.length());
    for (final byte b : keyType.getBytes()) {
      buff.put(b);
    }
    buff.putInt(publicExponent.length);
    buff.put(publicExponent);
    buff.putInt(modulus.length);
    buff.put(modulus);

    // Add the data to be signed
    buff.putInt(data.length);
    buff.put(data);

    // Add empty flags
    buff.put(new byte[] {0, 0, 0, 0});

    out.write(buff.array());
    out.flush();

    log.debug("Sent SSH2_AGENTC_SIGN_REQUEST message to ssh-agent.");
  }

  @Override
  public void close() throws IOException {
    out.close();
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
        .add("out", out)
        .toString();
  }
}
