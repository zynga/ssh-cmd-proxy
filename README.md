# SSH Command Proxy

A [Gradle](https://gradle.org/) plugin that fixes some technical deficiencies and expands the capabilities of [source dependencies](https://blog.gradle.org/introducing-source-dependencies).

## Why?

Gradle has support for 'source dependencies', which allow a project to depend on a separate Git repository containing source code instead of a precompiled artifact repository, such as [Artifactory](https://jfrog.com/artifactory/) or the [Maven Repository](https://mvnrepository.com/). This has the potential to greatly reduce the overhead of updating shared libraries within an organization where changes are expected to be rapid and immediately consumed.

The problem with this feature is that Gradle uses an outdated set of Git libraries, which in turn use some very outdated SSH features to access remote source dependencies. In particular, there are two major issues caused by this:

* Limited authentication mechanisms.
    * No support for modern private key formats (eg. EdDSA).
    * No support for password authentication.
    * No support for encrypted private keys.
* SHA1 for all key hashing. On top of being insecure, SHA1 hashes are explicitly [forbidden](https://github.blog/2021-09-01-improving-git-protocol-security-github/#dropping-insecure-algorithms) by GitHub. ***This means that Gradle source dependencies will not work with GitHub under any circumstances!***

This plugin fixes these issues by automatically spinning up local, ephemeral SSH proxy servers when a source dependency is identified in a build to act as a ‘man in the middle’ when Gradle attempts to retrieve the dependency. With this setup, the proxy can connect to the source repository using a [modern SSH implementation](https://mina.apache.org/sshd-project/), and provide a backward compatible SSH server to Gradle at the same time. In addition to modernizing the SSH implementation, the proxy server can inject additional authentication mechanisms, such as support for passwords, modern private key formats, key encryption, and SSH agent support, all of which Gradle source dependencies lack. This is important as it ensures that all possible users are not simply locked out of one of the most popular Git hosting services because of their development infrastructure.

Unlike other plugins that may address this issue by introducing their own set of configuration structures and dependency resolution mechanisms, this plugin does not attempt to replace a core Gradle feature and therefore has full support from modern IDEs, which recognize source dependencies and treat them appropriately.

## Basic Usage

### settings.gradle.kts
The only difference when compared to the base usage of source dependencies, aside from including the plugin, is the call to 'sshProxy' when specifying the dependency's URI. If the input URI does not use the SSH scheme or is otherwise invalid, no proxy redirection takes place and it will behave as if the plugin were not applied to the repository specification.

```
import com.zynga.aquinney.sshcmdproxy.SSHCmdProxy.sshProxy;

pluginManagement {
    repositories {
        mavenLocal()
        gradlePluginPortal()
    }
}

plugins {
    // Apply the foojay-resolver plugin to allow automatic download of JDKs
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.4.0"
    id("com.zynga.aquinney.ssh-cmd-proxy") version "1.0"
}

rootProject.name = "project"
include("app")

sourceControl {
    gitRepository(sshProxy(settings, "ssh://git@github.com/aquinney0/TestGradleLibrary.git")) {
        producesModule("com.zynga.payments:lib")
    }
}
```

No other changes are necessary for this plugin specifically.

## Advanced Configuration
### Apache MINA
The plugin uses [Apache MINA](https://mina.apache.org/) for both SSH server and client access, entirely within the Gradle JVM and therefore makes use of several configurable Java environment settings. Individual parameters can be overridden via several mechanisms outlined in their [documentation](https://github.com/apache/mina-sshd/blob/master/docs/internals.md#advanced-configuration-and-interaction). If non-interactive access to Git servers is possible on the user's machine, then no additional configuration is likely to be necessary as the SSH implementation makes use of standard SSH configuration points, such as [known_hosts](https://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files#~/.ssh/known_hosts), the standard key identity files ('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'), and many other SSH standards.

On systems that support UNIX domain sockets (Linux, MacOS, UNIX, Windows 10 build 17063), the plugin can make use of an [SSH agent](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/using-ssh-agent-forwarding) for public key authentication if the SSH_AUTH_SOCK environment variable is set up correctly.

### Plugin Settings
Plugin settings can be applied via [Gradle configuration](https://docs.gradle.org/current/userguide/build_environment.html) to customize some functionality. All entries are optional and need only be added if customization or additional authentication methods are required.

* **com.zynga.aquinney.ssh-cmd-proxy.key-password-<ANY_VALUE>** - string value that indicates a password that should be used in attempting to decode an encrypted private key file. The plugin may use these values if other methods of authentication were not successful. There can be any number of these properties and the plugin will attempt each on encrypted private key files until one is successful.
* **com.zynga.aquinney.ssh-cmd-proxy.password-\<USER\>@\<HOST\>[:\<PORT\>]** - string value that indicates the password to use when connecting as a particular user to an SSH Git service. If the default SSH port (22) is targeted, the port section can be omitted. This value may be used if other authentication mechanisms are not successful.
* **com.zynga.aquinney.ssh-cmd-proxy.connect-timeout** - integer value that represents the maximum amount of time in milliseconds that the proxy server will wait in attempting to get a connection to a remote SSH Git service. Defaults to 3000.
* **com.zynga.aquinney.ssh-cmd-proxy.auth-timeout** - integer value that represents the maximum amount ot time in milliseconds that the proxy server will wait in attempting to authenticate after connecting to a remote SSH Git service. Defaults to 3000.
* **com.zynga.aquinney.ssh-cmd-proxy.channel-timeout** - integer value that represents the maximum amount ot time in milliseconds that the proxy server will wait in attempting to open a channel after authenticating with a remote SSH Git service. Defaults to 3000.

#### Example ~/.gradle/gradle.properties
```properties
# The suffixes of these property names is not relevant - they are used for local private key decryption and are tried iteratively.
com.zynga.aquinney.ssh-cmd-proxy.key-password-firstFileSecret=password
com.zynga.aquinney.ssh-cmd-proxy.key-password-secondFileSecret=thisIsMyDecryptionKey

# Passwords may only be applied to the user/host/port indicated in the property names.
com.zynga.aquinney.ssh-cmd-proxy.password-aquinney0@github.com=andrewsPassword
com.zynga.aquinney.ssh-cmd-proxy.password-aquinney@github-internal.zynga.com\:22=andrewsCorporatePassword

com.zynga.aquinney.ssh-cmd-proxy.connect-timeout=1000
com.zynga.aquinney.ssh-cmd-proxy.auth-timeout=1000
com.zynga.aquinney.ssh-cmd-proxy.channel-timeout=1000
```

## Requirements

* Java 17
* Tested on Gradle 8.6

The plugin is built for Java 17. Theoretically, it could be targeted at 16, but no earlier since it makes use of the Java 16 support for UNIX domain sockets. The new Java support is used instead of relying on MINA's method that requires the Tomcat Native libraries preinstalled.

## Contributing

The code uses the [Google Java Style](https://github.com/google/google-java-format).