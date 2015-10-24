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

import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class AgentOutputTest {

  private final OutputStream out = mock(OutputStream.class);

  @Test
  public void testRequestIdentities() throws Exception {
    final AgentOutput agentOut = new AgentOutput(out);
    agentOut.requestIdentities();
    verify(out).write(new byte[]{0, 0, 0, 1, 11});
  }

  @Test
  public void testSignRequest() throws Exception {
    final String publicKeyStr =
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIPsEQebkSPDdUAkxY3QNlGasXWhYf8m57tRjnVsU5BqKpRVEu" +
        "6rfK8OIWu3l57Kc7oGicRX0RmQHmNr0We11WmQrYxqd4NEQQaKGSTaYyY7vyNC42gCjWCYape8+0ZL/l7px7/to8" +
        "n/l8ljIIdrDblQ7mxSo1omDAliZnXuuh7xWx6Wt1v3SsJ0EgFMwWCOw7xUH86UMM5D9OYIZFiRD/1hQjrezLH34T" +
        "d8L48cDKh8XF3BmpdlMNxUmWBYckmPm88xG1btCKpghtcqTkrzVbZSz1uIsSeXJzxGRKUkkkvyQaQYBhMoZTYxSb" +
        "QCMTiWsnALe4iyhfUDP2TjAr1qSv david@example.com";

    final AgentOutput agentOut = new AgentOutput(out);
    final RSAPublicKeySpec publicKeySpec = TraditionalKeyParser.parsePemPublicKey(publicKeyStr);
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    final byte[] bytes = new byte[]{1, 2, 3, 4};

    agentOut.signRequest(publicKey, bytes);
    verify(out).write(new byte[] {
        0, 0, 1, 40, 13, 0, 0, 1, 23, 0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1,
        0, 1, 0, 0, 1, 1, 0, -56, 62, -63, 16, 121, -71, 18, 60, 55, 84, 2, 76, 88, -35, 3, 101,
        25, -85, 23, 90, 22, 31, -14, 110, 123, -75, 24, -25, 86, -59, 57, 6, -94, -87, 69, 81,
        46, -22, -73, -54, -16, -30, 22, -69, 121, 121, -20, -89, 59, -96, 104, -100, 69, 125, 17,
        -103, 1, -26, 54, -67, 22, 123, 93, 86, -103, 10, -40, -58, -89, 120, 52, 68, 16, 104,
        -95, -110, 77, -90, 50, 99, -69, -14, 52, 46, 54, -128, 40, -42, 9, -122, -87, 123, -49,
        -76, 100, -65, -27, -18, -100, 123, -2, -38, 60, -97, -7, 124, -106, 50, 8, 118, -80, -37,
        -107, 14, -26, -59, 42, 53, -94, 96, -64, -106, 38, 103, 94, -21, -95, -17, 21, -79, -23,
        107, 117, -65, 116, -84, 39, 65, 32, 20, -52, 22, 8, -20, 59, -59, 65, -4, -23, 67, 12,
        -28, 63, 78, 96, -122, 69, -119, 16, -1, -42, 20, 35, -83, -20, -53, 31, 126, 19, 119,
        -62, -8, -15, -64, -54, -121, -59, -59, -36, 25, -87, 118, 83, 13, -59, 73, -106, 5, -121,
        36, -104, -7, -68, -13, 17, -75, 110, -48, -118, -90, 8, 109, 114, -92, -28, -81, 53, 91,
        101, 44, -11, -72, -117, 18, 121, 114, 115, -60, 100, 74, 82, 73, 36, -65, 36, 26, 65,
        -128, 97, 50, -122, 83, 99, 20, -101, 64, 35, 19, -119, 107, 39, 0, -73, -72, -117, 40,
        95, 80, 51, -10, 78, 48, 43, -42, -92, -81, 0, 0, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0,
    });
  }

}
