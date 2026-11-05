import dev.positron.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.*;
import java.util.*;

public final class Goldens {
 private static void check(boolean value,String id){if(!value)throw new AssertionError(id);}
 private static void refused(Runnable run,String id){try{run.run();throw new AssertionError("accepted "+id);}catch(Codec.WireException expected){}}
 public static void main(String[] args)throws Exception {
  JsonNode fixture=Codec.parse(Files.readAllBytes(Path.of(args[0],"query-golden-fixtures.json")));
  for(var c:fixture.path("representations")){
   if(c.path("accepted").asBoolean())check(Codec.decode(c.path("type").asText(),c.path("input").asText()).equals(c.path("canonical")),c.path("id").asText());
   else refused(()->Codec.decode(c.path("type").asText(),c.path("input").asText()),c.path("id").asText());
  }
  for(String bad:List.of("\ud800","\udc00","a\ud800x")) {
   refused(()->Codec.bytes(Map.of("key",bad)),"native text");
   refused(()->Codec.bytes(Map.of(bad,"value")),"native key");
  }
  refused(()->Codec.bytes(Map.of("key","x".repeat(262145))),"bounded serialization");
  check(Codec.parse(Codec.bytes(Map.of("key","\ud83d\ude00\ufffd\\"))).path("key").asText().equals("\ud83d\ude00\ufffd\\"),"valid native text");
  for(var c:fixture.path("responses")) {
   if(c.path("accepted").asBoolean())Query.decode(Codec.bytes(c.path("input")),c.path("mode").asText("execute"));
   else refused(()->Query.decode(Codec.bytes(c.path("input")),c.path("mode").asText("execute")),c.path("id").asText());
  }
  for(var c:fixture.path("errors")){
   var e=PositronException.query(c.path("status").asInt(),Codec.bytes(c.path("input")),c.path("cancellation").asBoolean());
   check(e.failure.equals(c.path("failure").asText())&&e.retryClass.equals(c.path("retryClass").asText())&&e.completionState.equals(c.path("completionState").asText()),c.path("id").asText());
  }
  System.out.println("JVM canonical goldens passed");
 }
}
