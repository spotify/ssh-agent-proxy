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

import java.util.Arrays;
import java.util.Iterator;

/**
 * Takes an array of bytes. On every call to next(), it reads the first four bytes as a length n
 * and returns the next n bytes after that.
 */
class ByteIterator implements Iterator<byte[]> {

  private final byte[] data;
  private int cursor;

  ByteIterator(final byte[] data) {
    this.data = data;
    this.cursor = 0;
  }

  @Override
  public boolean hasNext() {
    return this.cursor < this.data.length;
  }

  @Override
  public byte[] next() {
    int l = s2i(Arrays.copyOfRange(this.data, this.cursor, this.data.length));
    this.cursor += 4;
    final byte[] bytes = Arrays.copyOfRange(this.data, this.cursor, this.cursor + l);
    this.cursor += l;
    return bytes;
  }

  /**
   * Read four bytes off the provided byte string and return the value as a big endian
   * 32 bit unsigned integer
   * @param bytes Array of bytes.
   * @return int
   */
  private int s2i(final byte[] bytes) {
    int num = 0;
    for (int i = 0; i < 4; i++) {
      num += (bytes[i] & 0xff) << ((3 - i) * 8);
    }
    return num;
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
