# NetworkWatch

A strictly defensive Java log-analysis utility for synthetic authentication and traffic events. Explainable rules flag failed-authentication bursts, unusual regions, and traffic volume; baseline models detect outliers; timeline buckets support triage; and incident reports use deterministic redacted identifiers.

Run `mvn test`, then `mvn -q package && java -cp target/classes dev.networkwatch.Main sample/synthetic-logs.csv`. The sample uses reserved documentation addresses and invented identities. Rules are triage aids, not proof of compromise; this project contains no exploitation or credential-attack functionality.
