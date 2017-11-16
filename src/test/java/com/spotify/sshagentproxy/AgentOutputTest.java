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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.junit.Test;

public class AgentOutputTest extends TestConstants {

  private final OutputStream out = mock(OutputStream.class);

  @Test
  public void testRequestIdentities() throws Exception {
    final AgentOutput agentOut = new AgentOutput(out);
    agentOut.requestIdentities();
    verify(out).write(new byte[]{0, 0, 0, 1, 11});
  }

  @Test
  public void testSignRequest() throws Exception {
    final AgentOutput agentOut = new AgentOutput(out);
    final RSAPublicKeySpec publicKeySpec = TraditionalKeyParser.parsePemPublicKey(PUBLIC_KEY2);
    final KeyFactory keyFactory = KeyFactory.getInstance("Rsa");
    final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    final byte[] bytes = new byte[]{1, 2, 3, 4};

    agentOut.signRequest(publicKey, bytes);
    verify(out).write(new byte[] {
        0, 0, 1, 40, 13, 0, 0, 1, 23, 0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3,
        1, 0, 1, 0, 0, 1, 1, 0, -101, -45, 102, -66, 72, -24, 64, 113, 40, -125, -113, 31, 65,
        31, 75, 113, -64, 67, 71, -70, 62, 108, 93, -77, 60, -49, 89, -109, -24, 106, 36,
        -116, -25, -42, 116, 90, -45, 31, 60, 0, 20, -74, -18, 8, 114, -66, 65, 3, 28, -102,
        22, -17, 31, -41, 91, -71, 109, -63, 93, -106, 24, -59, 19, -125, -100, 95, -79, 20,
        3, 63, -95, -104, 13, -72, -106, -8, 40, 35, 21, -102, 55, -86, -32, 112, -106, 98,
        -6, -36, -109, -12, -76, 110, 33, 66, -53, 76, -37, -38, 112, -44, -29, -123, 74, 91,
        84, -63, 11, 76, 107, 121, -40, 38, -25, -3, 99, -58, -119, -78, -3, 37, -50, 95, 37,
        21, -85, 31, 38, -10, 29, -17, -89, 86, 111, -123, -29, 103, -16, -119, 118, 43, -62,
        -9, 85, -42, -59, -74, -71, -19, -51, 38, -112, -91, -11, 11, -56, -12, -118, -53,
        37, 112, 101, 24, 92, 101, 5, 21, -57, 86, 81, -54, -124, -74, 49, 99, 101, 44, 29,
        101, 38, -126, 118, -87, -4, 80, -94, -9, -87, 94, -120, 111, -25, 103, -125, -17,
        -45, -118, -39, -55, -14, 7, 40, 49, 75, 113, 103, 93, -78, 107, -8, -84, -20, 75,
        1, -101, -59, 108, -57, -93, 110, -28, -82, 93, 119, 88, -50, 77, 91, 9, 109, 48, -119,
        3, -99, -113, 65, 3, -74, -122, 109, -88, 105, -51, 50, 90, 99, -18, 98, 14, 28, 94,
        41, 119, 68, -51, -116, 17, 0, 0, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0,
    });
  }

}
