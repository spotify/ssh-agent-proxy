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

import com.google.common.base.Throwables;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public abstract class TestConstants {

  protected static final byte[] KEY_BLOB1 = new byte[] {
      0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 1, 0, -76, -73,
      -41, 64, 111, 53, 14, -80, 13, 118, 77, 98, 85, -78, -76, 36, 27, -39, 127, -117, 124, 118,
      -42, -37, -29, -88, 75, -63, -43, 68, -43, -91, -88, -57, -26, 102, -128, -83, -87, 60, 75,
      62, -17, -106, 64, 35, -127, -27, -43, -100, -109, -62, -100, -12, 103, 3, -25, 91, -98,
      -41, -33, 110, 47, 99, -87, -7, -80, -62, 10, 122, -44, -16, 55, 8, 20, -104, -45, -24, -7,
      21, -23, 9, 106, -97, 85, -69, 8, 92, 122, 44, -49, 95, -25, 45, 100, 75, -112, -123, 119,
      9, 70, 85, -96, -67, -99, -98, -54, -96, 75, 84, -58, -102, 100, 33, 84, 91, -73, -74, -49,
      2, -48, 71, 48, -110, -73, 123, -120, -97, -43, -108, 66, 52, -33, -2, 119, -106, 74, 25,
      -26, 0, 53, -92, -104, -60, -95, 9, -28, -38, -32, 40, -43, 48, -15, 115, -101, 94, 5, -69,
      83, 71, 121, 1, 36, -112, 7, -47, -1, -13, 13, 4, -45, -86, 21, -47, -31, 64, -2, 115, 34,
      79, -106, -1, -25, 24, 107, 0, -105, -50, 100, -23, -2, 114, 80, 55, -51, -21, 121, -101,
      -97, 74, -108, 82, -116, -15, -39, 27, -43, -93, -34, 21, 25, -43, -40, -84, 57, 88, -46,
      76, 74, -120, 91, -16, -92, 35, 114, -11, -1, -90, -82, 3, -34, 34, -75, 53, 63, -108, -39,
      -84, -78, -126, -117, -43, -106, 29, 1, -117, 63, 29, 93, -101, 81, 94, 104, -87, -10, 115,
  };
  protected static final String COMMENT1 = "/Users/dxia/.ssh/id_rsa";

  protected static final byte[] KEY_BLOB2 = new byte[] {
      0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 1, 0, -101, -45,
      102, -66, 72, -24, 64, 113, 40, -125, -113, 31, 65, 31, 75, 113, -64, 67, 71, -70, 62, 108,
      93, -77, 60, -49, 89, -109, -24, 106, 36, -116, -25, -42, 116, 90, -45, 31, 60, 0, 20, -74,
      -18, 8, 114, -66, 65, 3, 28, -102, 22, -17, 31, -41, 91, -71, 109, -63, 93, -106, 24, -59,
      19, -125, -100, 95, -79, 20, 3, 63, -95, -104, 13, -72, -106, -8, 40, 35, 21, -102, 55, -86,
      -32, 112, -106, 98, -6, -36, -109, -12, -76, 110, 33, 66, -53, 76, -37, -38, 112, -44, -29,
      -123, 74, 91, 84, -63, 11, 76, 107, 121, -40, 38, -25, -3, 99, -58, -119, -78, -3, 37, -50,
      95, 37, 21, -85, 31, 38, -10, 29, -17, -89, 86, 111, -123, -29, 103, -16, -119, 118, 43,
      -62, -9, 85, -42, -59, -74, -71, -19, -51, 38, -112, -91, -11, 11, -56, -12, -118, -53, 37,
      112, 101, 24, 92, 101, 5, 21, -57, 86, 81, -54, -124, -74, 49, 99, 101, 44, 29, 101, 38,
      -126, 118, -87, -4, 80, -94, -9, -87, 94, -120, 111, -25, 103, -125, -17, -45, -118, -39,
      -55, -14, 7, 40, 49, 75, 113, 103, 93, -78, 107, -8, -84, -20, 75, 1, -101, -59, 108, -57,
      -93, 110, -28, -82, 93, 119, 88, -50, 77, 91, 9, 109, 48, -119, 3, -99, -113, 65, 3, -74,
      -122, 109, -88, 105, -51, 50, 90, 99, -18, 98, 14, 28, 94, 41, 119, 68, -51, -116, 17,
  };
  protected static final String COMMENT2 = "/Users/dxia/.ssh/id_rsa.example";
  protected static final String PUBLIC_KEY2 =
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCb02a+SOhAcSiDjx9BH0txwENHuj5sXbM8z1mT6GokjOfWdFrTH"
      + "zwAFLbuCHK+QQMcmhbvH9dbuW3BXZYYxRODnF+xFAM/oZgNuJb4KCMVmjeq4HCWYvrck/S0biFCy0zb2nDU44VK"
      + "W1TBC0xredgm5/1jxomy/SXOXyUVqx8m9h3vp1ZvheNn8Il2K8L3VdbFtrntzSaQpfULyPSKyyVwZRhcZQUVx1Z"
      + "RyoS2MWNlLB1lJoJ2qfxQovepXohv52eD79OK2cnyBygxS3FnXbJr+KzsSwGbxWzHo27krl13WM5NWwltMIkDnY"
      + "9BA7aGbahpzTJaY+5iDhxeKXdEzYwR david@example.com";

  protected static final byte[] DATA = "Matt Damon: space pirate!".getBytes();

  protected static final byte[] SIGN_RESPONSE_HEADERS = new byte[] {
      0, 0, 1, 20, 14, 0, 0, 1, 15, 0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 1, 0,
  };
  protected static final byte[] SIGN_RESPONSE_DATA = new byte[] {
      105, 106, 27, 119, -107, -25,
      -88, 101, 23, -27, -28, 34, -121, 2, -90, -58, -14, -68, 74, -17, 20, 41, 15, 81, 100,
      -110, -112, 22, -114, 29, 89, -108, -27, 123, 81, -27, 3, -63, 45, -78, 47, -55, -116, 84,
      -15, -110, 66, -71, -45, 104, 20, -42, 127, 39, -53, 89, 63, -120, 40, -71, -2, -20, -75,
      -9, -108, -128, -56, 34, 34, -13, -78, -104, -18, -28, -120, -118, -102, 17, 95, 0, 86,
      89, 5, -91, -34, -18, -1, 94, 83, 41, 31, -112, 104, 96, 7, 17, -47, -122, -77, 113, -95,
      -109, 55, 46, 120, -118, 117, -27, 43, -8, -83, 124, -107, 96, 56, 35, -70, -121, 27, -82,
      89, 48, 33, 74, 58, 8, 118, -69, 54, -67, 123, -63, -67, -88, 7, -30, 57, -102, 114, -72,
      18, 13, 25, 81, 67, 95, 61, -114, 81, 68, 23, 126, -7, -8, 57, -76, -62, 32, -118, -18,
      28, 64, 17, 115, 125, 106, -62, 12, -94, -15, -56, 46, -80, -55, 109, 62, 4, 122, 42,
      -124, -104, -23, 10, 64, 66, -32, -126, -77, 1, -46, 15, -91, 89, -105, 52, -87, -124,
      -26, -127, -67, 65, -89, -122, 105, 93, 105, 9, 55, 89, -94, 100, -114, -98, 127, 78, 98,
      41, 67, -104, -50, -31, -102, -113, -14, -36, 54, 9, 4, -76, -102, 110, 125, 96, -27, 82,
      19, 24, -121, 78, 6, 120, -88, -113, -46, -34, -100, -60, 12, -18, 68, 106, -49, -56,
      -107, -81, 127,
  };

  protected static byte[] SIGN_RESPONSE_BYTES = new byte[0];
  static {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      out.write(SIGN_RESPONSE_HEADERS);
      out.write(SIGN_RESPONSE_DATA);
    } catch (IOException e) {
      throw Throwables.propagate(e);
    }

    SIGN_RESPONSE_BYTES = out.toByteArray();
  }
}
