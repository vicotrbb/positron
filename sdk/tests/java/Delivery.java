import dev.positron.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.util.*;
public final class Delivery {
 private static JsonNode fixture;
 private static JsonNode response(String name){for(var c:fixture.path("responses"))if(c.path("id").asText().equals(name))return c.path("input").deepCopy();throw new AssertionError(name);}
 private static void check(boolean value){if(!value)throw new AssertionError("delivery outcome differs");}
 private static void refused(Runnable run){try{run.run();throw new AssertionError("invalid delivery accepted");}catch(Codec.WireException expected){}}
 public static void main(String[] args)throws Exception {
  fixture=Codec.parse(Files.readAllBytes(Path.of(args[0],"query-golden-fixtures.json")));
  var tracker=new BatchTracker("session");var first=response("one-batch-complete");check(tracker.filter(first).size()==1);check(tracker.filter(first).isEmpty());
  var changed=first.deepCopy();((ObjectNode)changed.path("events").get(1).path("batch").path("rows").get(0).path("cells").get(0).path("nativeValue")).put("textValue","changed");refused(()->tracker.filter(changed));check(tracker.filter(first).isEmpty());check(Query.terminalStatus(first.path("events").get(2).path("terminal")).equals("complete"));
  var tail=new BatchTracker("tail");check(tail.acknowledgement()==null);var start=response("tail-single-incomplete");check(tail.filter(start).size()==1);check(tail.filter(start).isEmpty());check(tail.acknowledgement().sequence().equals("0"));
  var next=response("tail-next-incomplete");var gap=next.deepCopy();((ObjectNode)gap.path("events").get(1).path("batch")).put("sequence","4");refused(()->tail.filter(gap));check(tail.filter(next).size()==1);refused(()->tail.filter(start));
  var schema=new BatchTracker("tail");schema.filter(start);var other=next.deepCopy();((ObjectNode)other.path("events").get(0).path("header").path("columns").get(0)).put("name","other");refused(()->schema.filter(other));check(schema.filter(next).size()==1);
  var falseTerminal=start.path("events").get(2).path("terminal").deepCopy();((ObjectNode)falseTerminal).put("state","complete");refused(()->Query.terminalStatus(falseTerminal));
  System.out.println("JVM bounded delivery passed");
 }
}
