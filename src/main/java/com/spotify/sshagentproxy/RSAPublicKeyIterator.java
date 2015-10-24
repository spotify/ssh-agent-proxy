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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;

/**
 * TBA
 */
class RSAPublicKeyIterator implements Iterator<RSAPublicKey> {

  private static final Logger log = LoggerFactory.getLogger(RSAPublicKeyIterator.class);

  private final Iterator<byte[]> byteIterator;

  RSAPublicKeyIterator(final byte[] bytes) {
    this.byteIterator = new ByteIterator(bytes);
  }

  @Override
  public boolean hasNext() {
    return byteIterator.hasNext();
  }

  @Override
  public RSAPublicKey next() {
    byte[] bytes;
    RSAPublicKey key = null;

    while (key == null && byteIterator.hasNext()) {
      bytes = byteIterator.next();
      try {
        key = RSA.from(bytes);
      } catch (InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException ignored) {
        log.warn("Unable to parse SSH public key as RSA key. Skipping.");
        byteIterator.next();
      }
    }

    byteIterator.next(); // Ignore filename for key

    return key;
  }

  @Override
  public void remove() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
        .toString();
  }
}
