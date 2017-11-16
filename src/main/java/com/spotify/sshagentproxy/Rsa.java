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

import com.google.common.base.Objects;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Iterator;
import org.apache.commons.codec.binary.Base64;

class Rsa {

  static final String RSA_LABEL = "ssh-rsa";

  private Rsa() {
  }

  /**
   * Create an {@link RSAPublicKey} from bytes.
   * @param key Array of bytes representing Rsa public key.
   * @return {@link RSAPublicKey}
   */
  static RSAPublicKey from(final byte[] key)
      throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {

    final String s = new String(key);
    final byte[] encoded;
    final String decoded;
    if (s.startsWith(RSA_LABEL)) {
      decoded = s.split(" ")[1];
      encoded = Base64.decodeBase64(decoded);
    } else {
      encoded = key;
      decoded = Base64.encodeBase64String(key);
    }

    final Iterator<byte[]> fields = new ByteIterator(encoded);
    final String sigType = new String(fields.next());
    if (!sigType.equals(RSA_LABEL)) {
      throw new RuntimeException(String.format(
          "Unknown key type %s. This code currently only supports %s.", sigType, RSA_LABEL));
    }

    final RSAPublicKeySpec keySpec =
        TraditionalKeyParser.parsePemPublicKey(RSA_LABEL + " " + decoded + " ");
    final KeyFactory keyFactory = KeyFactory.getInstance("Rsa");
    return (RSAPublicKey) keyFactory.generatePublic(keySpec);
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
        .toString();
  }
}
