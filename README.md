# ssh-agent-proxy [![Circle CI](https://circleci.com/gh/spotify/ssh-agent-proxy.svg?style=svg)](https://circleci.com/gh/spotify/ssh-agent-proxy)

A Java library that talks to the local ssh-agent.

## Getting started

```java
import org.apache.commons.codec.binary.Hex;

final byte[] dataToSign = {0xa, 0x2, (byte) 0xff};
final AgentProxy agentProxy = AgentProxies.newInstance();
final List<Identity> identities = agentProxy.list();
for (final Identity identity : identities) {
  if (identity.getPublicKey().getAlgorithm().equals("RSA")) {
    final byte[] signedData = agentProxy.sign(identity, dataToSign);
    System.out.println(Hex.encodeHexString(signedData));
  }
}
```

## How to build

`mvn verify`
