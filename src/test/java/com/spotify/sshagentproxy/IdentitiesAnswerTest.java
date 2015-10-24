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

import static com.spotify.sshagentproxy.IdentitiesAnswer.SSH2_AGENT_IDENTITIES_ANSWER;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class IdentitiesAnswerTest {

  @Test
  public void test() throws Exception {
    final byte[] bytes = new byte[]{
        0, 1, 0, 123, SSH2_AGENT_IDENTITIES_ANSWER, 0, 0, 121, 1
    };

    final IdentitiesAnswer a = IdentitiesAnswer.from(bytes);
    assertThat(a.getLength(), equalTo((int) Math.pow(16, 4) + 123));
    assertThat(a.getResponseCode(), equalTo(SSH2_AGENT_IDENTITIES_ANSWER));
    assertThat(a.getCount(), equalTo((int) Math.pow(16, 2) * 121 + 1));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testAssertion() throws Exception {
    IdentitiesAnswer.from(new byte[]{0, 0, 1});
  }
}
