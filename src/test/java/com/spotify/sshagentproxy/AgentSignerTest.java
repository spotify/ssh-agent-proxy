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

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Iterator;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AgentSignerTest {

  private static final String PUBLIC_KEY =
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIPsEQebkSPDdUAkxY3QNlGasXWhYf8m57tRjnVsU5BqKpRVEu" +
      "6rfK8OIWu3l57Kc7oGicRX0RmQHmNr0We11WmQrYxqd4NEQQaKGSTaYyY7vyNC42gCjWCYape8+0ZL/l7px7/to8" +
      "n/l8ljIIdrDblQ7mxSo1omDAliZnXuuh7xWx6Wt1v3SsJ0EgFMwWCOw7xUH86UMM5D9OYIZFiRD/1hQjrezLH34T" +
      "d8L48cDKh8XF3BmpdlMNxUmWBYckmPm88xG1btCKpghtcqTkrzVbZSz1uIsSeXJzxGRKUkkkvyQaQYBhMoZTYxSb" +
      "QCMTiWsnALe4iyhfUDP2TjAr1qSv david@example.com";

  private final AgentOutput out = mock(AgentOutput.class);
  private final AgentInput in = mock(AgentInput.class);

  @Test
  public void testSign() throws Exception {
    final RSAPublicKeySpec publicKeySpec = TraditionalKeyParser.parsePemPublicKey(PUBLIC_KEY);
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    final RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    final KeyFingerprint keyFingerprint = new KeyFingerprint(publicKey);
    final byte[] data = "hello world".getBytes();

    final byte[] answerBytes = new byte[]{0, 0, 2, 120, 12, 0, 0, 0, 2};
    final IdentitiesAnswer answer = IdentitiesAnswer.from(answerBytes);
    when(in.readIdentitiesAnswer()).thenReturn(answer);

    final byte[] answerData = new byte[]{
        0, 0, 1, 23, 0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 1,
        0, -76, -73, -41, 64, 111, 53, 14, -80, 13, 118, 77, 98, 85, -78, -76, 36, 27, -39, 127,
        -117, 124, 118, -42, -37, -29, -88, 75, -63, -43, 68, -43, -91, -88, -57, -26, 102, -128,
        -83, -87, 60, 75, 62, -17, -106, 64, 35, -127, -27, -43, -100, -109, -62, -100, -12, 103,
        3, -25, 91, -98, -41, -33, 110, 47, 99, -87, -7, -80, -62, 10, 122, -44, -16, 55, 8, 20,
        -104, -45, -24, -7, 21, -23, 9, 106, -97, 85, -69, 8, 92, 122, 44, -49, 95, -25, 45, 100,
        75, -112, -123, 119, 9, 70, 85, -96, -67, -99, -98, -54, -96, 75, 84, -58, -102, 100, 33,
        84, 91, -73, -74, -49, 2, -48, 71, 48, -110, -73, 123, -120, -97, -43, -108, 66, 52, -33,
        -2, 119, -106, 74, 25, -26, 0, 53, -92, -104, -60, -95, 9, -28, -38, -32, 40, -43, 48,
        -15, 115, -101, 94, 5, -69, 83, 71, 121, 1, 36, -112, 7, -47, -1, -13, 13, 4, -45, -86,
        21, -47, -31, 64, -2, 115, 34, 79, -106, -1, -25, 24, 107, 0, -105, -50, 100, -23, -2,
        114, 80, 55, -51, -21, 121, -101, -97, 74, -108, 82, -116, -15, -39, 27, -43, -93, -34,
        21, 25, -43, -40, -84, 57, 88, -46, 76, 74, -120, 91, -16, -92, 35, 114, -11, -1, -90,
        -82, 3, -34, 34, -75, 53, 63, -108, -39, -84, -78, -126, -117, -43, -106, 29, 1, -117, 63,
        29, 93, -101, 81, 94, 104, -87, -10, 115, 0, 0, 0, 29, 47, 85, 115, 101, 114, 115, 47,
        100, 97, 118, 105, 100, 47, 46, 115, 115, 104, 47, 105, 100, 95, 114, 115, 97, 46, 119,
        111, 114, 107, 0, 0, 1, 23, 0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0,
        1, 0, 0, 1, 1, 0, -56, 62, -63, 16, 121, -71, 18, 60, 55, 84, 2, 76, 88, -35, 3, 101, 25,
        -85, 23, 90, 22, 31, -14, 110, 123, -75, 24, -25, 86, -59, 57, 6, -94, -87, 69, 81, 46,
        -22, -73, -54, -16, -30, 22, -69, 121, 121, -20, -89, 59, -96, 104, -100, 69, 125, 17,
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
        95, 80, 51, -10, 78, 48, 43, -42, -92, -81, 0, 0, 0, 24, 47, 85, 115, 101, 114, 115, 47,
        100, 97, 118, 105, 100, 47, 46, 115, 115, 104, 47, 105, 100, 95, 114, 115, 97,
    };
    final Iterator<RSAPublicKey> keys = new RSAPublicKeyIterator(answerData);
    when(in.readIdentitiesAnswerData(eq(answer))).thenReturn(keys);

    final byte[] signBytes = new byte[]{0, 0, 1, 20, 14, 0, 0, 1, 15};
    final SignResponse response = SignResponse.from(signBytes);
    when(in.readSignResponse()).thenReturn(response);

    final byte[] signedData = new byte[]{
        0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 1, 0, 28, 79, -53, -106, 101, 104, 46,
        1, -109, 89, -20, -31, -19, -36, 79, 94, 102, 124, -28, 59, 70, -1, 76, -83, -94, 19, -54,
        -26, -27, -44, -4, 117, 49, 113, -91, -99, -95, -59, 87, -2, 45, -11, 122, 99, -97, -55,
        59, -3, -30, -44, -58, 87, 46, -71, 60, 71, 9, 49, -117, 5, -113, 8, 82, -61, 40, 96, 42,
        -26, 55, 123, 99, 60, -106, -106, 59, -90, 107, 5, 49, -10, 59, -30, 97, -80, -117, -46,
        -16, 58, 66, -44, -116, 19, 110, -63, 125, 96, -86, -71, -91, 124, 59, 123, 34, -88, -28,
        -80, 7, 81, -58, 70, 89, 32, 120, 76, -26, 48, 49, 53, -126, 120, -113, 1, 0, -77, 37,
        -37, -54, 110, 7, -2, -84, 119, -99, -79, 50, -75, -49, -55, 83, -99, 94, -86, -33, 97,
        65, 70, 58, 88, 122, -16, 25, 19, -22, 65, 89, 40, -28, -6, -86, -84, 103, 10, -70, -26,
        73, 56, 45, -127, -104, -127, 61, 107, -75, 113, 96, -89, -13, 56, 119, 49, 123, -100, 41,
        -45, -112, 78, 123, -128, 96, 56, -59, -58, -27, -123, -11, 41, 113, -21, 10, -43, 121,
        125, -30, 11, -107, 58, -48, 77, 124, -18, -45, -109, 55, 68, 90, -40, -7, -56, -102, -1,
        -37, 1, 115, 112, 37, 86, -71, -110, -125, -50, -8, -63, -84, 57, -7, 37, 3, 49, -97, 9,
        23, -30, 87, -17, 26, 109, 108, 65, 125, -85, -55, 2, 101, -91, 25, 64,
    };
    when(in.readSignResponseData(eq(response))).thenReturn(new ByteIterator(signedData));

    final byte[] signed;
    try (final AgentProxy proxy = new AgentProxy(out, in)) {
      signed = proxy.sign(data, keyFingerprint);
    }

    final String hex = Hex.encodeHexString(signed);
    final String expectedHex =
        "1c4fcb9665682e019359ece1eddc4f5e667ce43b46ff4cada213cae6e5d4fc753171a59da1c557fe2df57a63" +
        "9fc93bfde2d4c6572eb93c4709318b058f0852c328602ae6377b633c96963ba66b0531f63be261b08bd2f03a" +
        "42d48c136ec17d60aab9a57c3b7b22a8e4b00751c6465920784ce630313582788f0100b325dbca6e07feac77" +
        "9db132b5cfc9539d5eaadf6141463a587af01913ea415928e4faaaac670abae649382d8198813d6bb57160a7" +
        "f33877317b9c29d3904e7b806038c5c6e585f52971eb0ad5797de20b953ad04d7ceed39337445ad8f9c89aff" +
        "db0173702556b99283cef8c1ac39f92503319f0917e257ef1a6d6c417dabc90265a51940";
    assertThat(hex, equalTo(expectedHex));
  }


}