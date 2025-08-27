package dev.networkwatch;

import java.util.*;

public final class BurstDetector {
    public long maximumFailedAuth(List<Analyzer.Event> events, long windowSeconds) {
        if (windowSeconds <= 0) throw new IllegalArgumentException("window must be positive");
        var failures = events.stream().filter(e -> e.kind().equals("auth") && !e.success())
            .sorted(Comparator.comparingLong(Analyzer.Event::epoch)).toList();
        var windows = new HashMap<String, ArrayDeque<Long>>();
        long maximum = 0;
        for (var event : failures) {
            String key = event.user()+"\u0000"+event.source();
            var window = windows.computeIfAbsent(key, ignored -> new ArrayDeque<>());
            while (!window.isEmpty() && event.epoch()-window.peekFirst() >= windowSeconds) window.removeFirst();
            window.addLast(event.epoch());
            maximum = Math.max(maximum, window.size());
        }
        return maximum;
    }
}
