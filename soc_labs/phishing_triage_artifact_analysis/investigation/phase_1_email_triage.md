# Phase 1: Authentication Header Triage

An end-user forwarded a high-priority billing notification claiming to be from "PayPal Accounting" regarding an unauthorized $849.00 payment.

Opening the raw `.eml` structure revealed immediate discrepancies:
```
@'
Delivered-To: victim.employee@company-internal.local
Received: by 10.100.1.15 with SMTP id a15csp10243;
        Wed, 21 Oct 2026 08:14:22 -0700 (PDT)
Received: from mail-relay.attacker-infra.xyz (attacker-infra.xyz [198.51.100.45])
        by mx.company-internal.local with ESMTPS id q87si491823
        for <victim.employee@company-internal.local>;
        Wed, 21 Oct 2026 08:14:21 -0700 (PDT)
Authentication-Results: mx.company-internal.local;
       spf=fail (sender IP is 198.51.100.45) smtp.mailfrom=attacker-infra.xyz;
       dkim=fail header.d=paypal.com header.b=X9zLk;
       dmarc=fail (p=REJECT dis=NONE) header.from=paypal.com
From: "PayPal Accounting" <service-billing@paypal.com>
Reply-To: refund-processor@secure-billing-portal.cc
To: victim.employee@company-internal.local
Subject: URGENT: Unauthorized Invoice #89218 Paid ($849.00 USD)
Date: Wed, 21 Oct 2026 15:14:10 +0000
Message-ID: <20261021151410.89218@attacker-infra.xyz>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>Dear Customer,</p>
<p>You sent a payment of <b>$849.00 USD</b> to CryptoTrade Global Ltd.</p>
<p>If you did not authorize this transaction, click below immediately to dispute:</p>
<p><a href="http://login.secure-billing-portal.cc/dispute?id=89218">Cancel and Refund Transaction</a></p>
<p>Thank you,<br>PayPal Support Team</p>
</body>
</html>
'@ | Out-File -Encoding utf8 "C:\Triage\invoice_urgent.eml"
```

1. **Display Name vs. Routing Discrepancy:**
   ```text
   From: "PayPal Accounting" <service-billing@paypal.com>
   Reply-To: refund-processor@secure-billing-portal.cc
   ```
   * *Finding:* The display header claims legitimate PayPal origin, but any reply is directed to an external attacker-controlled domain (`secure-billing-portal.cc`).

2. **Server Hop Analysis (`Received:` Trace):**
   * Inspecting the earliest physical mail transfer hop:
     ```text
     Received: from mail-relay.attacker-infra.xyz (attacker-infra.xyz [198.51.100.45])
             by mx.company-internal.local with ESMTPS ...
     ```
   * *Finding:* The actual connecting SMTP relay was `198.51.100.45`, completely detached from PayPal's genuine infrastructure.

3. **Authentication Record Failures:**
   ```text
   Authentication-Results: mx.company-internal.local;
          spf=fail (sender IP is 198.51.100.45) smtp.mailfrom=attacker-infra.xyz;
          dkim=fail header.d=paypal.com;
          dmarc=fail (p=REJECT dis=NONE) header.from=paypal.com
   ```
   * **SPF:** FAILED. Originating IP `198.51.100.45` is not listed in PayPal's SPF record.
   * **DKIM:** FAILED. The digital signature failed cryptographic verification.
   * **DMARC:** FAILED. SPF and DKIM domains do not align with the `From:` header domain (`paypal.com`).