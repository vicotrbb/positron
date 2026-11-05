import dev.positron.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.time.Duration;
import java.util.*;
public final class Live {
 private static String phase="input";
 @FunctionalInterface interface Call {Types.LogQueryResponse run()throws PositronException;}
 private static JsonNode admitted(Call call)throws Exception {for(int i=0;i<5;i++){try{return Codec.tree(call.run());}catch(PositronException e){if(!e.failure.equals("CapacityUnavailable"))throw e;Thread.sleep(1000);}}throw new AssertionError("admission exhausted");}
 private static void check(boolean condition){if(!condition)throw new AssertionError("live outcome differs");}
 public static void main(String[] ignored){try{run();System.out.println("Java live conformance passed");}catch(Exception|AssertionError e){System.err.println("Java live conformance failed at "+phase+": "+e.getClass().getSimpleName());System.exit(1);}}
 private static void run()throws Exception {
  var input=Codec.parse(System.in.readNBytes(16384));var client=new Client(input.path("endpoint").asText(),true);String bearer=input.path("bearer").asText();var timeout=Duration.ofSeconds(5);
  var capability=client.capabilityNegotiate(new Types.CapabilityRequest(BigInteger.ONE,null),null,timeout);check(capability.api_major().equals(BigInteger.ONE));
  var budget=new Types.LogQueryBudget("16","16","100","1048576","16384","16","1048576","5");var query=new Types.LogQueryRequest(budget,"pipeline:v1 logs | range query_time 0 100 | project commit_position | limit 2");
  phase="execute";var first=admitted(()->client.logQueryExecute(query,bearer,timeout));var tracker=new BatchTracker("session");check(tracker.filter(first).size()==1);
  phase="session";var page=admitted(()->client.logQuerySession(new Types.LogQuerySessionRequest(BigInteger.ONE,query,null,null),bearer,timeout));tracker=new BatchTracker("session");tracker.filter(page);var events=page.path("events");var terminal=events.get(events.size()-1).path("terminal");check(Query.terminalStatus(terminal).equals("continued"));String resume=terminal.path("continuationCursor").asText();
  phase="resume";var second=admitted(()->client.logQuerySession(new Types.LogQuerySessionRequest(BigInteger.ONE,null,resume,null),bearer,timeout));tracker.filter(second);
  phase="cancel";page=admitted(()->client.logQuerySession(new Types.LogQuerySessionRequest(BigInteger.ONE,query,null,null),bearer,timeout));String cursor=page.path("events").get(0).path("header").path("initialCursor").asText();check(client.logQueryCancel(new Types.LogQueryCancelRequest(cursor,null),bearer,timeout).cancelled());
  var tailQuery=new Types.LogQueryRequest(new Types.LogQueryBudget("16","16","100","1048576","16384","16","1048576","60"),"pipeline:v1 logs | range query_time 0 100 | project commit_position | limit all");
  phase="tail";var tail=admitted(()->client.logQuerySession(new Types.LogQuerySessionRequest(BigInteger.ONE,null,null,new Types.LogQueryTailRequest(null,null,null,tailQuery)),bearer,timeout));tracker=new BatchTracker("tail");tracker.filter(tail);events=tail.path("events");cursor=events.get(events.size()-1).path("terminal").path("continuationCursor").asText();check(client.logQueryCancel(new Types.LogQueryCancelRequest(null,cursor),bearer,timeout).cancelled());
  phase="authentication";try{client.logQueryExecute(query,"invalid",timeout);throw new AssertionError("authentication accepted");}catch(PositronException e){check(e.failure.equals("AuthenticationRejected")&&e.completionState.equals("COMPLETION_STATE_REJECTED"));}
  phase="administration";client.tenantList(new Types.TenantListRequest(null),input.path("admin").asText(),timeout);
 }
}
