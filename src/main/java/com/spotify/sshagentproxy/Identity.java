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

import java.security.PublicKey;

/**
 * Represents a key held by ssh-agent.
 */
public interface Identity {

  /**
   * Return the key format as a string, e.g. "ssh-rsa", "ssh-dss", etc.
   */
  String getKeyFormat();

  /**
   * Return the {@link PublicKey}.
   */
  PublicKey getPublicKey();

  /**
   * Return the key comment as a string.
   */
  String getComment();

  /**
   * Return an array of bytes encoded as per RFC 4253 section 6.6 "Public Key Algorithms"
   * for either of the supported key types: "ssh-dss" or "ssh-rsa".
   */
  byte[] getKeyBlob();

}
