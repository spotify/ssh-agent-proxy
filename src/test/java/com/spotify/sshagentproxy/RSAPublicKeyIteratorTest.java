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

import java.security.interfaces.RSAPublicKey;
import java.util.Iterator;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class RSAPublicKeyIteratorTest {

  @Test
  public void test() throws Exception {
    final byte[] bytes = new byte[] {
        0, 0, 1, 23, 0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 1,
        0, -76, -73, -41, 64, 111, 53, 14, -80, 13, 118, 77, 98, 85, -78, -76, 36, 27, -39, 127,
        -117, 124, 118, -42, -37, -29, -88, 75, -63, -43, 68, -43, -91, -88, -57, -26, 102, -128,
        -83, -87, 60, 75, 62, -17, -106, 64, 35, -127, -27, -43,-100, -109, -62, -100, -12, 103, 3,
        -25, 91, -98, -41, -33, 110, 47, 99, -87, -7, -80, -62, 10, 122, -44, -16, 55, 8, 20, -104,
        -45, -24, -7, 21, -23, 9, 106, -97, 85, -69, 8, 92, 122, 44, -49, 95, -25, 45, 100, 75,
        -112, -123, 119, 9, 70, 85, -96, -67, -99, -98, -54, -96, 75, 84, -58, -102, 100, 33, 84,
        91, -73, -74, -49, 2, -48, 71, 48, -110, -73, 123, -120, -97, -43, -108, 66, 52, -33, -2,
        119, -106, 74, 25, -26, 0, 53, -92, -104, -60, -95, 9, -28, -38, -32, 40, -43, 48, -15, 115,
        -101, 94, 5, -69, 83, 71, 121, 1, 36, -112, 7, -47, -1, -13, 13, 4, -45, -86, 21, -47, -31,
        64, -2, 115, 34, 79, -106, -1, -25, 24, 107, 0, -105, -50, 100, -23, -2, 114, 80, 55, -51,
        -21, 121, -101, -97, 74, -108, 82, -116, -15, -39, 27, -43, -93, -34, 21, 25, -43, -40, -84,
        57, 88, -46, 76, 74, -120, 91, -16, -92, 35, 114, -11, -1, -90, -82, 3, -34, 34, -75, 53,
        63, -108, -39, -84, -78, -126, -117, -43, -106, 29, 1, -117, 63, 29, 93, -101, 81, 94, 104,
        -87, -10, 115, 0, 0, 0, 23, 47, 85, 115, 101, 114, 115, 47, 100, 120, 105, 97, 47, 46, 115,
        115, 104, 47, 105, 100, 95, 114, 115, 97,
    };

    final Iterator<RSAPublicKey> keys = new RSAPublicKeyIterator(bytes);
    int i = 0;
    while (keys.hasNext()) {
      keys.next();
      i++;
    }
    assertThat(i, equalTo(1));
  }

  @Test(expected = ArrayIndexOutOfBoundsException.class)
  public void testMalformedMessage() throws Exception {
    final Iterator<RSAPublicKey> keys = new RSAPublicKeyIterator(new byte[]{1});
    while (keys.hasNext()) {
      keys.next();
    }
  }

}
