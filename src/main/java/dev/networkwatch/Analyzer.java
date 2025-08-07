package dev.networkwatch;
import java.nio.charset.StandardCharsets;import java.security.*;import java.util.*;
public final class Analyzer {
 public record Event(long epoch,String user,String source,String kind,boolean success,long bytes,String region){}
 public record Finding(String rule,int points,String explanation){}
 public record Incident(String subject,int risk,List<Finding> findings){}
 public Incident analyze(List<Event> events){if(events.isEmpty())throw new IllegalArgumentException("events required");String user=events.getFirst().user();var f=new ArrayList<Finding>();long failed=events.stream().filter(e->e.kind.equals("auth")&&!e.success).count();if(failed>=5)f.add(new Finding("failed-auth-burst",40,failed+" failed authentications"));long regions=events.stream().map(Event::region).distinct().count();if(regions>=3)f.add(new Finding("region-change",25,regions+" regions observed"));long bytes=events.stream().filter(e->e.kind.equals("traffic")).mapToLong(Event::bytes).sum();if(bytes>10_000_000)f.add(new Finding("traffic-volume",30,"traffic exceeded 10 MB"));int risk=Math.min(100,f.stream().mapToInt(Finding::points).sum());return new Incident(redact(user),risk,List.copyOf(f));}
 public static String redact(String value){try{byte[] d=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));return "subject-"+HexFormat.of().formatHex(d,0,6);}catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}}
 public List<Event> parse(List<String> lines){var out=new ArrayList<Event>();int n=0;for(String line:lines){n++;if(line.startsWith("epoch")||line.isBlank())continue;String[] c=line.split(",",-1);if(c.length!=7)throw new IllegalArgumentException("invalid line "+n);out.add(new Event(Long.parseLong(c[0]),c[1],c[2],c[3],Boolean.parseBoolean(c[4]),Long.parseLong(c[5]),c[6]));}return out;}
}
