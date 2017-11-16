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

import static com.spotify.sshagentproxy.SignResponseHeaders.SSH2_AGENT_SIGN_RESPONSE;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class SignResponseHeadersTest {

  @Test
  public void test() throws Exception {
    final byte[] bytes = new byte[]{
        0, 1, 0, 123, SSH2_AGENT_SIGN_RESPONSE, 0, 0, 121, 1
    };
    final SignResponseHeaders a = SignResponseHeaders.from(bytes);
    assertThat(a.getLength(), equalTo((int) Math.pow(16, 4) + 123));
    assertThat(a.getResponseCode(), equalTo(SSH2_AGENT_SIGN_RESPONSE));
    assertThat(a.getResponseLength(), equalTo((int) Math.pow(16, 2) * 121 + 1));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testAssertion() throws Exception {
    SignResponseHeaders.from(new byte[] {0, 0, 1});
  }
}
