package dev.networkwatch;
import static org.junit.jupiter.api.Assertions.*;import org.junit.jupiter.api.Test;import java.util.*;
class BurstDetectorTest {
 Analyzer.Event event(long time,String source){return new Analyzer.Event(time,"user",source,"auth",false,0,"US");}
 @Test void windowsDoNotCombineDistantAttempts(){var events=List.of(event(0,"a"),event(10,"a"),event(20,"a"),event(1000,"a"));assertEquals(3,new BurstDetector().maximumFailedAuth(events,300));}
 @Test void sourcesRemainSeparateAndBoundaryExpires(){var events=List.of(event(0,"a"),event(10,"b"),event(300,"a"));assertEquals(1,new BurstDetector().maximumFailedAuth(events,300));}
}
