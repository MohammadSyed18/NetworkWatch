package dev.networkwatch;

import java.nio.file.Files;
import java.nio.file.Path;

public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2) throw new IllegalArgumentException("usage: networkwatch <logs.csv> [baseline-split-epoch]");
        var events = new EventCsv().parse(Files.readAllLines(Path.of(args[0])));
        long split = args.length == 2 ? Long.parseLong(args[1]) : 0;
        System.out.print(new BatchReportFormatter().markdown(new EventPipeline().analyze(events,split)));
    }
}
