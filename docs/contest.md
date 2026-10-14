# Contest check — 2026-10-14

Sources: [official rules](https://paypalaihackathon.devpost.com/rules) and [official FAQ](https://paypalaihackathon.devpost.com/details/faqs).

Deadline observed: 12 November 2026, 12:00 PST, equivalent to 22:00 Europe/Bucharest. Proposed internal milestones: candidate 7 November, submission 9 November. No submission or registration was performed.

The rules require an actual AI integration with central PayPal sandbox functionality, a new or substantially updated working application, a public source repository with an open-source license, runnable judge access, and a public YouTube demonstration under three minutes. Complete repository setup instructions can satisfy demo access; public hosting is optional.

Romania is not among the named geographic exclusions. Personal age, conflicts of interest and any applicable restrictions are not verified. Developer account availability is separate from eligibility. Terms have not been accepted here.

This fixture slice does not satisfy the actual AI/sandbox requirements. Repository publication, demo footage, video upload and submission remain open.

Technical primary sources consulted:

- [Show order details](https://developer.paypal.com/api/orders/v2/orders-get)
- [Webhook signature verification](https://developer.paypal.com/api/webhooks/v1/verify-webhook-signature-post)
- [Webhook verification troubleshooting](https://developer.paypal.com/invoicing/troubleshooting)

The implementation prepares server-side order reads and sends original webhook JSON in a verification envelope. Fake-transport tests do not establish genuine sandbox connectivity.
