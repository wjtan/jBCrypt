 [ ![Download](https://api.bintray.com/packages/wjtan/maven/jbcrypt/images/download.svg) ](https://bintray.com/wjtan/maven/jbcrypt/_latestVersion)

# JBCrypt
jBCrypt is an implementation of the OpenBSD Blowfish password hashing algorithm,
as described in ["A Future-Adaptable Password
Scheme"](http://www.openbsd.org/papers/bcrypt-paper.ps) by Niels Provos and
David Mazieres.  

This system hashes passwords using a version of Bruce Schneier's Blowfish block
cipher with modifications designed to raise the cost of off-line password
cracking. The computation cost of the algorithm is parameterised, so it can be
increased as computers get faster.  

JUnit regression tests are available in in TestBCrypt.java

jBCrypt is licensed under a ISC/BSD licence. See the LICENSE file for details.

Please report bugs to Damien Miller <djm@mindrot.org>. Please check the
TODO file first, in case your problem is something I already know about
(please send patches!)

A simple example that demonstrates most of the features:

	// Hash a password for the first time
	String hashed = BCrypt.hashpw(password, BCrypt.gensalt());

	// gensalt's log_rounds parameter determines the complexity
	// the work factor is 2**log_rounds, and the default is 10
	String hashed = BCrypt.hashpw(password, BCrypt.gensalt(12));

	// Check that an unencrypted password matches one that has
	// previously been hashed
	if (BCrypt.checkpw(candidate, hashed))
		System.out.println("It matches");
	else
		System.out.println("It does not match");

There is also a [C#/.NET port by Derek Slager](http://derekslager.com/blog/posts/2007/10/bcrypt-dotnet-strong-password-hashing-for-dotnet-and-mono.ashx)


# Package notes

This is an distribution of [jBCrypt](https://github.com/anebril/jBCrypt/tree/gcsvn-merged-0.4-overflow-fix) patched by [anebril](https://github.com/anebril),
based on the discussion in [Stackoverflow](https://stackoverflow.com/questions/38597604/java-bcrypt-not-supporting-newer-versions-seeds-prefixed-with-2b-2y-etc).
It has been packaged to ease use in existing applications.

## Maven setup

Use it in your project by adding the following to your project *pom.xml*:

        <dependency>
            <groupId>sg.wjtan</groupId>
            <artifactId>jBCrypt</artifactId>
            <version>0.4.1</version>
        </dependency>