# networkwatch

Java tools for looking through authentication and traffic logs. rules flag failed-login bursts, unfamiliar regions, and unusual traffic volume; reports group events into timelines and use redacted identifiers.

```sh
mvn test
mvn -q package
java -cp target/classes dev.networkwatch.Main sample/synthetic-logs.csv
```

the sample logs use invented identities and reserved documentation addresses. flags are starting points for investigation, not proof of a compromise. this is a defensive log-analysis project.

## Implementation details

Authentication bursts use per-subject, per-source sliding time windows. Events from separate sources or distant time intervals are not combined into a single burst.

## Batch analysis

[EventCsv](src/main/java/dev/networkwatch/EventCsv.java) parses bounded line-oriented CSV with quoted fields, explicit booleans, and contextual row errors. [EventPipeline](src/main/java/dev/networkwatch/EventPipeline.java) validates and deduplicates events, separates subjects, and builds baselines only from records before an explicit split epoch. Later events cannot influence their own baseline.

[BatchReportFormatter](src/main/java/dev/networkwatch/BatchReportFormatter.java) reports redacted subject IDs, risk rules, unseen regions, and unusual traffic samples. It does not print raw account names. Identifiers are deterministic pseudonyms rather than reversible encryption or a guarantee of anonymity.

```sh
mvn test
java -cp target/classes dev.networkwatch.Main sample/synthetic-logs.csv 0
```

A split of zero uses all events as current and disables historical-baseline comparisons when no history exists. Tests cover mixed subjects, duplicate events, baseline leakage, quoted CSV, invalid booleans, and negative byte counts.
