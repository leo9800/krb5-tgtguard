# krb5-tgtguard

this is a Kerberos 5 (krb5) `kdcpolicy` plugin to reject `TGS-REQ`s with ticket-granting-tickets (TGT) issued before password changing of corresponding user, which effectively revoke any potential-compromised TGT that gained by advisaries with users' compromised password after password changing, either with `kadmin cpw` by contacting admin or `kpasswd`.

without this plugin:

```
timepoint event
A         user's password compromised
B         hacker do kinit with compromised password, retrieved TGT
C         user noticed account breach and changed password
D         hacker can still get service tickets (ST) with TGT gained at timepoint B
E         hacker may access service with ST gained at D, impersonating as the victim of account breach
```

with this plugin:

```
timepoint event
A         user's password compromised
B         hacker do kinit with compromised password, retrieved TGT
C         user noticed account breach and changed password
D         hacker try to get service ticket (ST) with TGT gained at timepoint B, but KDC rejects with KRB5KDC_ERR_POLICY
E         (hacker cannot gain access to service and impersonate as the victim of account breach)
```

limitations:

 1. if an advisary has already gain service tickets (ST) with TGT retrieved with compromised password, the ST are still valid until it expires, they can not be revoked by this plugin.
 2. if an advisary has already gain cross-realm TGT to another realm (denoted as `FOOBAR`) with TGT retrieved with compromised password, the cross-realm TGT would not be revoked by this plugin and still valid to KDC (TGS) at `FOOBAR`.

this 2 limitations may not possible to be addressed with MIT Kerberos only and without heavily modification upon its source code. for 1, Kerberos lacks of a standard for counterpart of introspection as in OIDC, a service have no way to verify if a service ticket is still valid against the KDC without modifying the protocol or use of side channel; (e.g. storing timestamp of last password change with LDAP) the second issue are indeed same, the KDC at `FOOBAR` have no way to verify if the cross-realm TGT is revoked by querying the KDC which issued it because lack of introspection, or a side-channel approach (e.g. LDAP) is required.

how to use:

```
gcc -std=c99 -Wall -Werror -o tgtguard.so -shared -g tgtguard.c
install -Dm0755 tgtguard.so /usr/lib/krb5/plugins/tgtguard.so
```

append the content below to `/var/lib/krb5kdc/kdc.conf` and restart `krb5-kdc`:

```
[plugins]
	kdcpolicy = {
		module = tgtguard:/usr/lib/krb5/plugins/tgtguard.so
	}
```
