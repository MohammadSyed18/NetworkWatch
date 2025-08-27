package dev.networkwatch;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.List;

class EventPipelineTest {
    @Test void separatesSubjectsDeduplicatesAndKeepsFutureOutOfBaseline() {
        var old = new Analyzer.Event(10,"alice","192.0.2.1","traffic",true,100,"US");
        var current = new Analyzer.Event(110,"alice","192.0.2.1","traffic",true,900,"CA");
        var other = new Analyzer.Event(120,"bob","192.0.2.2","auth",false,0,"US");
        var report = new EventPipeline().analyze(List.of(old,current,current,other),100);
        assertEquals(3, report.uniqueEvents());
        assertEquals(2, report.subjects().size());
        var alice = report.subjects().stream().filter(item -> item.subject().equals(Analyzer.redact("alice"))).findFirst().orElseThrow();
        assertEquals(1, alice.historicalEvents());
        assertEquals(1, alice.unusualTrafficSamples());
        assertTrue(alice.unseenRegions().contains("CA"));
        assertFalse(new BatchReportFormatter().markdown(report).contains("alice"));
    }
    @Test void csvHandlesQuotedFieldsAndRejectsInvalidBooleans() {
        var events = new EventCsv().parse(List.of("100,alice,192.0.2.1,auth,true,0,\"US, East\""));
        assertEquals("US, East", events.getFirst().region());
        assertThrows(IllegalArgumentException.class, () -> new EventCsv().parse(List.of("100,a,b,auth,perhaps,0,US")));
        assertThrows(IllegalArgumentException.class, () -> new EventCsv().parse(List.of("100,a,b,auth,true,-1,US")));
    }
}
