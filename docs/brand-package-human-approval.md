# Brand package human approval

`frank_executor.brand_approval_cli` is the finite operator boundary for the
`human-approval` step in `zenith.anima.brand-package-v1`. It registers only
`zenith-brand-reviewer`, with `brand.review.human` and the two required brand
resources. It cannot claim an automated step or another Run.

The operator first selects Runtime authority for that exact Actor and Run. The
CLI then registers the Actor, lists the one eligible step and creates a
five-minute fenced claim. The UI must show the three immutable input artifact
references and retain the resulting claim before it asks the operator to
approve or reject the direction.

An approval uses a pinned `frank.brand-approval-decision.v1` file. The file
contains the exact claim, input digest, explicit decision and reason, a bounded
Markdown approval record, and stable artifact and terminal request IDs. The CLI
commits that record through Runtime before it completes the Attempt. A rejection
fails the Attempt without an approval artifact. An unknown HTTP result is
reconciled by retrying the identical decision file and request IDs; creating a
new decision is not reconciliation.

This actor is separate from `frank-hermes-pilot`. After approval, the owner must
select fresh finite authority for the automated actor before the final package
step can run. The CLI grants no provider, Service, membership or browser
authority.
