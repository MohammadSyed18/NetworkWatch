# NetworkWatch

A strictly defensive Java log-analysis utility for synthetic authentication and traffic events. Explainable rules flag failed-authentication bursts, unusual region counts, and traffic volume, then emit a risk score and deterministic redacted subject identifier.

Run `mvn test`, then `mvn -q package && java -cp target/classes dev.networkwatch.Main sample/synthetic-logs.csv`. The sample uses reserved documentation addresses and invented identities. Rules are triage aids, not proof of compromise; this project contains no exploitation or credential-attack functionality.
