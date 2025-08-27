package dev.networkwatch;

public final class BatchReportFormatter {
    private String safe(String value) {
        return value.replace("\\", "\\\\").replace("|", "\\|")
            .replace("\n", " ").replace("\r", " ").replace("<", "&lt;").replace(">", "&gt;");
    }
    public String markdown(EventPipeline.BatchReport report) {
        var out = new StringBuilder("# Defensive log review\n\n");
        out.append("Input events: ").append(report.inputEvents()).append("; unique: ")
            .append(report.uniqueEvents()).append("; split epoch: ").append(report.splitEpoch()).append("\n\n");
        out.append("| Subject | Current events | Risk | New regions | Unusual traffic samples |\n")
            .append("| --- | ---: | ---: | --- | ---: |\n");
        for (var subject : report.subjects()) {
            out.append("| ").append(safe(subject.subject())).append(" | ").append(subject.currentEvents())
                .append(" | ").append(subject.incident().risk()).append(" | ")
                .append(safe(String.join(", ", new java.util.TreeSet<>(subject.unseenRegions()))))
                .append(" | ").append(subject.unusualTrafficSamples()).append(" |\n");
        }
        out.append("\nScores prioritize review; they do not establish malicious activity. Baselines use only events before the split.\n");
        return out.toString();
    }
}
