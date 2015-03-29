<h2>SAML Utilities Splunk add-on</h2>

<h4>Description</h4>
The SAML Utilities add-on for Splunk adds a command named <code><strong>SAML</strong></code> to the Splunk search language which can be used to parse encoded SAML messages in Splunk searches.

<h4>Installation</h4>
SAML Utilities is a standard Splunk add-on and requires no special configuration.  A restart of Splunk is required to complete installation.

<h4>Usage</h4>
The <code><strong>saml</strong></code> command is implemented as a single search command which can be used to parse encoded SAML messages.

<strong>Usage: <code>saml type=\<authnrequest|response\> field</code></strong>

The following example will parse a Base64 encoded SAML AuthnRequest and return a decoded XML string.

<code>... | saml type=authnrequest SAMLRequest</code>

<h4>Arguments</h4>
<h5>type</h5>

The type argument specifies the type of SAML message to parse (authnrequest or response).

<h5>field</h5>

The Splunk field to parse.

<h4>SAML Reference</h4>
https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=security
http://en.wikipedia.org/wiki/Security_Assertion_Markup_Language
