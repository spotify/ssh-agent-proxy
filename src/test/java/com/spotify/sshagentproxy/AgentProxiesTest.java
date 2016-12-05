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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import org.junit.Test;

import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AgentProxiesTest extends TestConstants {

  private final AgentOutput out = mock(AgentOutput.class);
  private final AgentInput in = mock(AgentInput.class);

  @Test
  public void testList() throws Exception {
    final List<Identity> expectedIds = ImmutableList.of(
        DefaultIdentity.from(KEY_BLOB1, COMMENT1),
        DefaultIdentity.from(KEY_BLOB2, COMMENT2)
    );
    when(in.readIdentitiesAnswer()).thenReturn(expectedIds);

    final List<Identity> identities = Lists.newArrayList();
    try (final AgentProxy proxy = AgentProxies.withCustomInputOutput(in, out)) {
      identities.addAll(proxy.list());
    }

    assertThat(identities, equalTo(expectedIds));
  }

  @Test
  public void testSign() throws Exception {
    final Identity identity = DefaultIdentity.from(KEY_BLOB2, COMMENT2);
    when(in.readSignResponse()).thenReturn(SIGN_RESPONSE_DATA);

    final byte[] signed;
    try (final AgentProxy proxy = AgentProxies.withCustomInputOutput(in, out)) {
      signed = proxy.sign(identity, DATA);
    }

    assertArrayEquals(signed, SIGN_RESPONSE_DATA);
  }
}