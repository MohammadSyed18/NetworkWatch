# networkwatch

Java tools for looking through authentication and traffic logs. rules flag failed-login bursts, unfamiliar regions, and unusual traffic volume; reports group events into timelines and use redacted identifiers.

```sh
mvn test
mvn -q package
java -cp target/classes dev.networkwatch.Main sample/synthetic-logs.csv
```

the sample logs use invented identities and reserved documentation addresses. flags are starting points for investigation, not proof of a compromise. this is a defensive log-analysis project.
