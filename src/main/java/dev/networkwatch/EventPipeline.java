package dev.networkwatch;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Per-subject analysis with an explicit historical/current split to avoid leakage. */
public final class EventPipeline {
    public record SubjectReport(String subject, int historicalEvents, int currentEvents,
                                Analyzer.Incident incident, Set<String> unseenRegions,
                                int unusualTrafficSamples, List<Timeline.Bucket> timeline) {}
    public record BatchReport(int inputEvents, int uniqueEvents, long splitEpoch,
                              List<SubjectReport> subjects) {}

    public static void validate(Analyzer.Event event) {
        if (event == null || event.epoch() < 0 || event.bytes() < 0
                || event.user() == null || event.user().isBlank()
                || event.source() == null || event.source().isBlank()
                || event.region() == null || event.region().isBlank()
                || !Set.of("auth", "traffic").contains(event.kind())) {
            throw new IllegalArgumentException("invalid event fields");
        }
    }

    public BatchReport analyze(List<Analyzer.Event> input, long splitEpoch) {
        if (splitEpoch < 0) throw new IllegalArgumentException("split must be nonnegative");
        input.forEach(EventPipeline::validate);
        var unique = new LinkedHashSet<>(input);
        var grouped = new TreeMap<String,List<Analyzer.Event>>();
        for (var event : unique) grouped.computeIfAbsent(event.user(), ignored -> new ArrayList<>()).add(event);
        var reports = new ArrayList<SubjectReport>();
        for (var entry : grouped.entrySet()) {
            var historical = entry.getValue().stream().filter(event -> event.epoch() < splitEpoch).toList();
            var current = entry.getValue().stream().filter(event -> event.epoch() >= splitEpoch)
                .sorted(Comparator.comparingLong(Analyzer.Event::epoch)).toList();
            if (current.isEmpty()) continue;
            var baseline = Baseline.from(historical);
            int unusual = historical.stream().noneMatch(event -> event.kind().equals("traffic")) ? 0
                : (int) current.stream().filter(event -> event.kind().equals("traffic") && baseline.unusualBytes(event.bytes())).count();
            reports.add(new SubjectReport(Analyzer.redact(entry.getKey()), historical.size(), current.size(),
                new Analyzer().analyze(current), historical.isEmpty() ? Set.of() : baseline.newRegions(current),
                unusual, new Timeline().bucket(current, 300)));
        }
        return new BatchReport(input.size(), unique.size(), splitEpoch, List.copyOf(reports));
    }
}
