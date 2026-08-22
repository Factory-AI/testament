# Decision-durability prototype

Informative, disposable research for
`RES-PROTOTYPE-DECISION-DURABILITY-001`. One PostgreSQL transaction commits a
synthetic decision, audit, and receipt. A second transaction injects a fault
before receipt creation and rolls back all earlier writes. Process-death and
fsync faults remain later production tests.
