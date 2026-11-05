import dev.positron.*;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
public final class Refusals {
 private record Case(int status,String body,String failure,String retry,String completion){}
 private static void check(boolean condition){if(!condition)throw new AssertionError("native refusal truth differs");}
 public static void main(String[] args)throws Exception {
  for(var test:List.of(
   new Case(503,"{\"code\":\"capacity_unavailable\"}","capacity_unavailable","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   new Case(409,"{\"code\":\"idempotency_conflict\"}","idempotency_conflict","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   new Case(503,"{\"code\":\"administration_unavailable\"}","administration_unavailable","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   new Case(503,"{\"code\":\"capacity_unavailable\",\"retry_class\":\"RETRY_CLASS_AFTER_BACKOFF\",\"completion_state\":\"COMPLETION_STATE_REJECTED\"}","capacity_unavailable","RETRY_CLASS_AFTER_BACKOFF","COMPLETION_STATE_REJECTED"),
   new Case(503,"{\"code\":\"administration_unavailable\",\"retryClass\":1,\"completionState\":2}","administration_unavailable","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   new Case(503,"{\"code\":\"capacity_unavailable\",\"retry_class\":2,\"completion_state\":2}","Transport","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   new Case(503,"{\"code\":8,\"retry_class\":2,\"completion_state\":1,\"source\":4,\"safe_detail\":8}","PUBLIC_ERROR_CODE_CAPACITY_UNAVAILABLE","RETRY_CLASS_AFTER_BACKOFF","COMPLETION_STATE_REJECTED"),
   new Case(503,"{\"code\":\"capacity_unavailable\",\"retry_class\":1}","Transport","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   new Case(503,"{}","Transport","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   new Case(503,"{\"code\":\"private-secret-unknown\"}","Transport","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   new Case(503,"{","Transport","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"))) {
   var calls=new AtomicInteger();var server=HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(),0),8);
   server.createContext("/",exchange->{calls.incrementAndGet();exchange.getRequestBody().readAllBytes();byte[] body=test.body.getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(test.status,body.length);exchange.getResponseBody().write(body);exchange.close();});server.start();
   try {var client=new Client("http://127.0.0.1:"+server.getAddress().getPort(),true);try{client.call("positron.v1.BackupService/Manage",Map.of("action","capture"),"private-secret",Duration.ofSeconds(2));throw new AssertionError("refusal accepted");}catch(PositronException e){check(e.failure.equals(test.failure)&&e.retryClass.equals(test.retry)&&e.completionState.equals(test.completion));check(!e.toString().contains("private-secret"));if(test.failure.startsWith("PUBLIC_ERROR_CODE_"))check(e.source.equals("FAILURE_SOURCE_QUERY_EXECUTION")&&e.safeDetail.equals("SAFE_DETAIL_CAPACITY_UNAVAILABLE"));}check(calls.get()==1);}
   finally{server.stop(0);}
  }
  System.out.println("JVM native refusal identity and certainty passed");
 }
}
