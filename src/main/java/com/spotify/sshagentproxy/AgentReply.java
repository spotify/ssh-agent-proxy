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

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * An abstract class that represents a message headers from the ssh-agent.
 * There are always three headers consisting of the first four bytes, fifth byte, and next four
 * bytes. What these bytes mean depends on the message type.
 */
abstract class AgentReply {

  /**
   * Get first four bytes as an int
   * @param bytes Bytes to parse
   * @return int
   */
  protected static int first(final byte[] bytes) {
    return intFromSubArray(bytes, 0, 4);
  }

  /**
   * Get fifth byte as an int
   * @param bytes Bytes to parse
   * @return int
   */
  protected static int second(final byte[] bytes) {
    return bytes[4];
  }

  /**
   * Get sixth through ninth byte as an int
   * @param bytes Bytes to parse
   * @return int
   */
  protected static int third(final byte[] bytes) {
    return intFromSubArray(bytes, 5, 9);
  }

  /**
   * Take a slice of an array of bytes and interpret it as an int.
   * @param bytes Array of bytes
   * @param from  Start index in the array
   * @param to    End index in the array
   * @return int
   */
  private static int intFromSubArray(final byte[] bytes, final int from, final int to) {
    final byte[] subBytes = Arrays.copyOfRange(bytes, from, to);
    final ByteBuffer wrap = ByteBuffer.wrap(subBytes);
    return wrap.getInt();
  }
}
