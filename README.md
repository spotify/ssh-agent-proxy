# ssh-agent-proxy

[![Build Status](https://travis-ci.org/spotify/ssh-agent-proxy.svg?branch=master)](https://travis-ci.org/spotify/ssh-agent-proxy)
[![codecov](https://codecov.io/gh/spotify/ssh-agent-proxy/branch/master/graph/badge.svg)](https://codecov.io/gh/spotify/ssh-agent-proxy)
[![Maven Central](https://img.shields.io/maven-central/v/com.spotify/ssh-agent-proxy.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.spotify%22%20ssh-agent-proxy)
[![License](https://img.shields.io/github/license/spotify/ssh-agent-proxy.svg)](LICENSE)

A Java library that talks to the local ssh-agent. This project is currently in beta phase.

* [Download](#download)
* [Getting started](#getting-started)
* [Prerequisites](#prerequisites)
* [Code of conduct](#code-of-conduct)

## Download

Download the latest JAR or grab [via Maven][maven-search].

```xml
<dependency>
  <groupId>com.spotify</groupId>
  <artifactId>ssh-agent-proxy</artifactId>
  <version>0.1.5</version>
</dependency>
```

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


## Prerequisities

Any platform that has the following

* Java 7+
* Maven 3 (for compiling)


## Code of conduct

This project adheres to the [Open Code of Conduct][code-of-conduct]. By participating, you are
expected to honor this code.

  [code-of-conduct]: https://github.com/spotify/code-of-conduct/blob/master/code-of-conduct.md
  [maven-search]: https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.spotify%22%20ssh-agent-proxy
