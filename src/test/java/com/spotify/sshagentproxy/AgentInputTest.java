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

import java.io.ByteArrayInputStream;

import static com.spotify.sshagentproxy.IdentitiesAnswer.SSH2_AGENT_IDENTITIES_ANSWER;
import static com.spotify.sshagentproxy.SignResponse.SSH2_AGENT_SIGN_RESPONSE;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

public class AgentInputTest {

  @Test
  public void testIdentitiesAnswer() throws Exception {
    final ByteArrayInputStream in = new ByteArrayInputStream(new byte[] {
        0, 0, 1, 1, SSH2_AGENT_IDENTITIES_ANSWER, 0, 1, 2, 3,
    });

    final AgentInput agentIn = new AgentInput(in);
    final IdentitiesAnswer answer = agentIn.readIdentitiesAnswer();
    assertThat(answer.getLength(), equalTo((int) Math.pow(16, 2) + 1));
    assertThat(answer.getResponseCode(), equalTo(SSH2_AGENT_IDENTITIES_ANSWER));
    assertThat(answer.getCount(), equalTo((int) Math.pow(16, 4) +
                                          (int) Math.pow(16, 2) * 2 + 3));
  }

  @Test
  public void testReadSignResponse() throws Exception {
    final ByteArrayInputStream in = new ByteArrayInputStream(new byte[] {
        0, 0, 1, 1, SSH2_AGENT_SIGN_RESPONSE, 0, 1, 2, 3
    });

    final AgentInput agentIn = new AgentInput(in);
    final SignResponse response = agentIn.readSignResponse();
    assertThat(response.getLength(), equalTo((int) Math.pow(16, 2) + 1));
    assertThat(response.getResponseCode(), equalTo(SSH2_AGENT_SIGN_RESPONSE));
    assertThat(response.getResponseLength(), equalTo((int) Math.pow(16, 4) +
                                                     (int) Math.pow(16, 2) * 2 + 3));
  }

}
