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
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Iterator;

/**
 * Represents a key held by ssh-agent.
 */
public class Identity {

  private static final String RSA_LABEL = "ssh-rsa";
  private static final String DSS_LABEL = "ssh-dss";

  private final String keyFormat;
  private final PublicKey publicKey;
  private final String comment;

  private Identity(final String keyFormat, final PublicKey publicKey, final String comment) {
    this.keyFormat = keyFormat;
    this.publicKey = publicKey;
    this.comment = comment;
  }

  static Identity from(final byte[] keyBlob, final String comment)
      throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
    final Iterator<byte[]> keyBlobIterator = new ByteIterator(keyBlob);
    final String keyFormat = new String(keyBlobIterator.next());

    final PublicKey publicKey;
    switch (keyFormat) {
      case RSA_LABEL:
        publicKey = RSA.from(keyBlob);
        break;
      case DSS_LABEL:
      default:
        throw new UnsupportedOperationException(String.format(
            "Got unsupported key format '%s'. Skipping.", keyFormat));
    }

    keyBlobIterator.next();
    return new Identity(keyFormat, publicKey, comment);
  }

  public String getKeyFormat() {
    return keyFormat;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }

  public String getComment() {
    return comment;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    Identity identity = (Identity) o;

    if (keyFormat != null ? !keyFormat.equals(identity.keyFormat) : identity.keyFormat != null) {
      return false;
    }
    if (publicKey != null ? !publicKey.equals(identity.publicKey) : identity.publicKey != null) {
      return false;
    }
    return !(comment != null ? !comment.equals(identity.comment) : identity.comment != null);

  }

  @Override
  public int hashCode() {
    int result = keyFormat != null ? keyFormat.hashCode() : 0;
    result = 31 * result + (publicKey != null ? publicKey.hashCode() : 0);
    result = 31 * result + (comment != null ? comment.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return Objects.toStringHelper(this)
        .add("keyFormat", keyFormat)
        .add("publicKey", publicKey)
        .add("comment", comment)
        .toString();
  }
}
