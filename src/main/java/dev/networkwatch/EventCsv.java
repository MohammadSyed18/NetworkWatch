package dev.networkwatch;

import java.util.ArrayList;
import java.util.List;

/** Bounded line-oriented CSV import with explicit booleans and validated events. */
public final class EventCsv {
    public List<Analyzer.Event> parse(List<String> lines) {
        var events = new ArrayList<Analyzer.Event>();
        for (int number = 0; number < lines.size(); number++) {
            String line = lines.get(number);
            if (line.isBlank() || line.startsWith("epoch,")) continue;
            try {
                var fields = fields(line);
                if (fields.size() != 7) throw new IllegalArgumentException("requires seven columns");
                if (!fields.get(4).equals("true") && !fields.get(4).equals("false")) {
                    throw new IllegalArgumentException("success must be true or false");
                }
                var event = new Analyzer.Event(Long.parseLong(fields.get(0)), fields.get(1),
                    fields.get(2), fields.get(3), Boolean.parseBoolean(fields.get(4)),
                    Long.parseLong(fields.get(5)), fields.get(6));
                EventPipeline.validate(event);
                events.add(event);
            } catch (IllegalArgumentException error) {
                throw new IllegalArgumentException("line " + (number + 1) + ": " + error.getMessage(), error);
            }
        }
        return List.copyOf(events);
    }

    private List<String> fields(String line) {
        if (line.length() > 16384) throw new IllegalArgumentException("CSV line too long");
        var fields = new ArrayList<String>();
        var current = new StringBuilder();
        boolean quoted = false;
        boolean closed = false;
        for (int i = 0; i < line.length(); i++) {
            char value = line.charAt(i);
            if (quoted) {
                if (value == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        current.append('"'); i++;
                    } else { quoted = false; closed = true; }
                } else current.append(value);
            } else if (value == ',') {
                fields.add(current.toString()); current.setLength(0); closed = false;
            } else if (value == '"' && current.isEmpty() && !closed) {
                quoted = true;
            } else {
                if (closed || value == '"') throw new IllegalArgumentException("invalid CSV quote");
                current.append(value);
            }
        }
        if (quoted) throw new IllegalArgumentException("unterminated quoted field");
        fields.add(current.toString());
        return fields;
    }
}
