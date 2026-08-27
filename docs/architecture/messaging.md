# The messaging surface

Kagi's part in an end-to-end encrypted conversation: it attests to which
messaging keys belong to which enrolled device, serves the key packages a
device publishes so others can add it while it is offline, and holds the
endpoint state that keeps a ratchet from going backwards. It never sees a
group secret.

One listener carries the family. `e2ee_router` owns `/e2ee/` and fans to the
three endpoints behind it, because wave's `http` has a single `req_out` and
an application behind it is one module.

## Credentials

`POST /e2ee/credential`.

A device that takes part in an encrypted conversation needs keys that are not
the ones it authenticates with. Some authenticators cannot sign an arbitrary
message at all; a signing key is not a key-agreement key; and reusing one key
across authentication and messaging creates cross-protocol and correlation
risks that separate keys do not have.

So a device generates its messaging keys locally, proves it holds them and
holds its enrolled identity, and kagi signs the binding between the two.

The proof is checked against the directory's key, never a supplied one. The
request does carry the device's enrolment JWK, because the module needs a key
to verify a signature with, but the JWK is accepted only once its thumbprint
matches the `cnf.jkt` the ledger recorded at enrolment. Verifying against a
key that arrived with the request would let anything that can reach the port
mint a credential for any device id.

A credential is a JWS typed `cty=ke+jwt`, deliberately distinct from the
device certificate's `dc+jwt`: a token accepted in the wrong role means
something other than what the verifier assumed. It carries the device, the
tenant, both public keys, the ciphersuite, the key generation, and the
assurance level of the enrolment it rests on — recorded once from the
enrolment rather than re-derived, so a credential cannot claim hardware
backing the enrolment never had.

The contract lives in `modules/common/e2ee_credential.rs`, which conclave
mounts from the published `kagi-common` source tree. One definition, two
repositories.

**What a credential does not prove** is that the issuer is honest. It stops a
delivery or storage service substituting a device key; it does not stop a
compromised issuer introducing a device that was never enrolled. Detecting
that needs participant-visible device lists and out-of-band verification,
which live above this layer.

## Key packages

`POST /e2ee/keypackages` publishes; `POST /e2ee/keypackages/claim` consumes.

A group protocol adds a member by consuming a key package that member
published in advance. The package carries an initial key-agreement key, and
the security of the resulting group depends on that key being used once — a
package handed out twice puts two groups on the same initial secret, which is
precisely the forward-secrecy property the protocol was chosen for.

So claiming is a one-time operation, and it is the only interesting thing
here. A claim must consume and return a package in one indivisible step; a
store that read the pool, chose a package and wrote the pool back would hand
the same package to two concurrent joiners under load.

The bytes are the group protocol's own encoding and are opaque to kagi. What
kagi decides is who may publish one, that each is consumed at most once, and
that one whose credential no longer holds is not served. A package's
reference is a hash over its bytes, so a substituted package is a different
package and cannot be passed off as the one that was published.

A pool can also hold a last-resort package, served only once the one-time
packages are exhausted and reported as what it is. It keeps a long-offline
device addable, at the cost of the initial secret for those additions no
longer being unique — a caller that cannot tell the two apart cannot report
the difference to anyone who might care.

Rotation is not additive: a device that rotates its messaging keys has said
the earlier ones are not the ones it uses, so packages published under an
earlier generation stop being claimable.

## Endpoint state

`POST /e2ee/state/load` returns the current state and its revision;
`POST /e2ee/state/commit` advances it.

A group protocol's endpoint holds a ratchet, and its safety rests on state
only ever moving forward. A generation used twice means a key and nonce used
twice, which is not a degraded guarantee but no guarantee at all. Every way
state can move backwards — a restored backup, a stale replica, a snapshot
taken before the last send — is a way to lose confidentiality.

Two mechanisms carry that. A **conditional commit** quotes the revision the
caller believed it was advancing from, so two writers racing produce one
winner and one refusal rather than a merge nobody designed; the revision is
assigned by the endpoint and cannot be constructed for state a caller did not
load. And a **backward commit poisons the endpoint**: a caller that quotes
the current revision, so it did load the current state, and then offers a
position behind it has a ratchet that has gone backwards. Continuing would
encrypt under a position already used, so the endpoint stops until a person
has worked out what replaced the state.

Offering the *same* position is distinguished from offering an older one.
Both are refused — committing a position twice is how an optimistic retry
turns into a reused generation — but only one is evidence that something is
wrong.

The state is the module's own memory. That is what makes a separate
high-water mark unnecessary, since a mark in the same memory could never
disagree with the state it attests to, and it is also what a restart does not
survive: a module that comes back holds no endpoints and will accept a first
commit at any position. An endpoint whose module has restarted rejoins rather
than resumes.

The ordering a caller owes is commit before use, never after. The endpoint
guarantees that a committed state is durable and that a backward one is
caught; it cannot know that a caller sent a message under a state it never
committed.

## The group protocol itself

Not a module. `tests/harness/src/mls.rs` is a thin `openmls` adapter used as
a conformance fixture: a key schedule, a ratchet tree and a commit-processing
state machine are exactly the kind of code that is plausible when wrong, and
writing another one would mean owning a novel implementation of the part of
the system with the least tolerance for subtle error.

The suite is `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`, P-256 throughout,
because that is what the key-custody contract supports on every backend it
claims. X25519 exists as software in the fluxor SDK and is used by TLS, but
`ALG_X25519` is reserved and unsupported by the stable `key_vault` contract,
so an X25519 profile would need a vault capability extension and an
implementation for every claimed backend first.
