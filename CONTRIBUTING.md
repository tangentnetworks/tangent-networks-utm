<!--
SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks

SPDX-License-Identifier: BSD-3-Clause
-->

# Contributing to Tangent Networks UTM

Direct repository contributions, issue tracking, and merge requests are disabled for this project. 

If you would like to report a bug, share a security disclosure, provide an architectural critique, or submit a feature request, please send plaintext email to both of the following addresses:

* tangent.net@zohomail.in
* tangent@tangentnet.top

---

## IMPORTANT: Email Delivery & Whitelisting

The mail server for `tangentnet.top` operates **without a configured PTR (Reverse DNS) record**. Because many major email providers (such as Gmail and Outlook) automatically drop, reject, or mark inbound messages as spam when communicating with a host lacking FCrDNS, you must take defensive measures to guarantee your report is delivered:

1. **Add to Address Book / Contacts:** Before sending your email, add both `tangent.net@zohomail.in` and `tangent@tangentnet.top` to your email client's Safe Senders list, Contacts, or Address Book.
2. **Check Non-Delivery Receipts (NDRs):** If your mail system rejects the message or returns a "550 Rogue MX/Missing PTR" delivery failure, please resend the report exclusively to the `tangent.net@zohomail.in` tracking endpoint.

---

## Subject Line Requirements

To ensure your email clears inbound processing and sorting filters, your subject line **MUST** explicitly begin with one of the following prefixes:

* `[REPORT]`  -- For bug disclosures, script errors, or security vulnerabilities.
* `[FEATURE]` -- For architectural suggestions, enhancements, or feature requests.

Thank you for supporting independent, security-focused engineering.