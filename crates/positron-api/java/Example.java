import dev.positron.*;
import java.time.Duration;
public final class Example {
 public static Types.LogQueryRequest request() {
  return new Types.LogQueryRequest(new Types.LogQueryBudget("16","16","100","1048576","16384","16","1048576","5"),"pipeline:v1 logs | range query_time 0 100 | project commit_position | limit 2");
 }
 public static void main(String[] args)throws PositronException {
  Codec.encode("LogQueryRequest",request());
  if(args.length==0){System.out.println(Codec.SCHEMA_DIGEST);return;}
  var response=new Client(args[0]).logQueryExecute(request(),System.getenv("POSITRON_BEARER"),Duration.ofSeconds(5));
  var events=Codec.tree(response).path("events");
  System.out.println(Query.terminalStatus(events.get(events.size()-1).path("terminal")));
 }
}
