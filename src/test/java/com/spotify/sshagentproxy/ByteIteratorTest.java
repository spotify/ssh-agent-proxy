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

import org.junit.Test;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Random;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

public class ByteIteratorTest {

  @Test
  public void testNext() {
    byte[] bytes = new byte[]{0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 4, 0, 0, 1, 2};
    final Iterator<byte[]> iterator = new ByteIterator(bytes);
    assertThat(iterator.next(), equalTo(new byte[] {1, 2, 3}));
    assertThat(iterator.next(), equalTo(new byte[] {0, 0, 1, 2}));
    assertFalse(iterator.hasNext());
  }

  @Test
  public void testTurnByteIntoUnsignedInt() {
    // Test that signed bytes using 2's complement are turned into unsigned ints
    byte[] bytes = new byte[437];
    new Random().nextBytes(bytes);
    bytes[0] = 0;
    bytes[1] = 0;
    bytes[2] = 1;
    bytes[3] = -79;

    final Iterator<byte[]> iterator = new ByteIterator(bytes);
    assertThat(iterator.next(), equalTo(Arrays.copyOfRange(bytes, 4, bytes.length)));
    assertFalse(iterator.hasNext());
  }
}
