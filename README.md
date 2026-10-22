# NetworkWatch

Java tools for looking through authentication and traffic logs. Rules flag failed-login bursts, unfamiliar regions, and unusual traffic volume; reports group events into timelines and use redacted identifiers.

```sh
mvn test
mvn -q package
java -cp target/classes dev.networkwatch.Main sample/synthetic-logs.csv
```

The sample logs use invented identities and reserved documentation addresses. Flags are starting points for investigation, not proof of a compromise. This is a defensive log-analysis project.
