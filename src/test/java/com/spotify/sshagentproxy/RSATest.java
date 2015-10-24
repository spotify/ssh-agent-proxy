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
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class RSATest {

  @Test
  public void testFrom() throws Exception {
    final String publicKey =
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0t9dAbzUOsA12TWJVsrQkG9l/i3x21tvjqEvB1UTVpajH5maArak8"
        + "Sz7vlkAjgeXVnJPCnPRnA+dbntffbi9jqfmwwgp61PA3CBSY0+j5FekJap9VuwhceizPX+ctZEuQhXcJRlWgvZ2eyq"
        + "BLVMaaZCFUW7e2zwLQRzCSt3uIn9WUQjTf/neWShnmADWkmMShCeTa4CjVMPFzm14Fu1NHeQEkkAfR//MNBNOqFdHh"
        + "QP5zIk+W/+cYawCXzmTp/nJQN83reZufSpRSjPHZG9Wj3hUZ1disOVjSTEqIW/CkI3L1/6auA94itTU/lNmssoKL1Z"
        + "YdAYs/HV2bUV5oqfZz dxia@spotify.com";

    final RSAPublicKey key = RSA.from(publicKey.getBytes());
    assertThat(key.getAlgorithm(), equalTo("RSA"));
    assertThat(key.getPublicExponent(), equalTo(BigInteger.valueOf(65537)));
  }
}