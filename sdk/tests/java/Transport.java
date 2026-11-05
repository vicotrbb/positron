import dev.positron.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import com.fasterxml.jackson.annotation.*;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
public final class Transport {
 private static final String RPC="positron.v1.CapabilityService/Negotiate";
 private static final Map<String,Object> CAP=Map.of("api_major",1);
 private static final Duration SECOND=Duration.ofSeconds(1);
 public record Projection(@JsonIgnore String hidden,String visible){}
 public static final class Renamed { @JsonIgnore public String ignored="\ud800"; @JsonProperty("visible") public String visible(){return "okay";} }
 private static void check(boolean value,String reason){if(!value)throw new AssertionError(reason);}
 private static void refused(Runnable run){try{run.run();throw new AssertionError("invalid request accepted");}catch(Codec.WireException expected){}}
 private static PositronException failure(Client c,String rpc,Object request,Duration timeout)throws Exception{try{c.call(rpc,request,"private-secret",timeout);throw new AssertionError("invalid transport accepted");}catch(PositronException e){check(!e.toString().contains("private-secret"),"secret diagnostic");return e;}}
 private static JsonNode fixture;
 private static JsonNode query(){return Codec.tree(Map.of("pipeline","pipeline:v1 logs | range query_time 0 100 | project commit_position | limit 2","budget",Map.of("scannedBytes","1048576","decodedRecords","16","outputRows","16","outputBytes","16384","memoryBytes","1048576","cpuWorkUnits","16","wallSeconds","5","maximumTimeRangeNanoseconds","100")));}
 public static void main(String[] args)throws Exception {
  fixture=Codec.parse(Files.readAllBytes(Path.of(args[0],"query-golden-fixtures.json")));
  for(String endpoint:List.of("http://localhost","https://secret@localhost","https://localhost/?secret=value","https://localhost/path","https://localhost/#secret"))refused(()->new Client(endpoint));
  check(Codec.parse(Codec.bytes(new Projection("\ud800","okay"))).path("visible").asText().equals("okay"),"hidden native data should not be refused");check(Codec.parse(Codec.bytes(new Renamed())).path("visible").asText().equals("okay"),"native serializer projection");
  for(String mode:List.of("valid","headers","body","drip","truncated","oversize","redirect","old","deadline")) {
   try(var server=new ServerSocket(0,8,InetAddress.getLoopbackAddress())) {
    var calls=new AtomicInteger();var worker=Executors.newSingleThreadExecutor(r->{var t=new Thread(r);t.setDaemon(true);return t;});
    var serving=worker.submit(()->{try(var socket=server.accept()){calls.incrementAndGet();socket.setSoTimeout(2000);var input=new BufferedReader(new InputStreamReader(socket.getInputStream(),StandardCharsets.US_ASCII));String line;int length=0;while((line=input.readLine())!=null&&!line.isEmpty())if(line.toLowerCase(Locale.ROOT).startsWith("content-length:"))length=Integer.parseInt(line.substring(15).trim());for(int i=0;i<length;i++)if(input.read()<0)break;
     var out=socket.getOutputStream();String capability="{\"api_major\":1,\"schema_digest\":\""+Codec.SCHEMA_DIGEST+"\",\"availability\":"+(mode.equals("old")?2:1)+",\"refusal\":null,\"deprecation\":0,\"capability\":"+(mode.equals("old")?4:0)+"}";
     switch(mode){
      case "headers","deadline" -> Thread.sleep(mode.equals("deadline")?5500:300);
      case "body" -> {out.write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".getBytes());out.flush();Thread.sleep(300);}
      case "drip" -> {out.write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".getBytes());for(int i=0;i<40;i++){out.write(' ');out.flush();Thread.sleep(15);}}
      case "truncated" -> out.write(("HTTP/1.1 200 OK\r\nContent-Length: "+(capability.length()+5)+"\r\nConnection: close\r\n\r\n"+capability).getBytes());
      case "oversize" -> out.write(("HTTP/1.1 200 OK\r\nContent-Length: 8192\r\n\r\n"+" ".repeat(8192)).getBytes());
      case "redirect" -> out.write("HTTP/1.1 307 Temporary Redirect\r\nLocation: https://external.invalid\r\nContent-Length: 0\r\n\r\n".getBytes());
      default -> out.write(("HTTP/1.1 200 OK\r\nContent-Length: "+capability.length()+"\r\n\r\n"+capability).getBytes());
     }out.flush();
    }catch(Exception expected){/* interruption closes only this owned test socket */}});
    var client=new Client("http://127.0.0.1:"+server.getLocalPort(),true);
    if(mode.equals("valid")){
     refused(()->{try{client.call(RPC,CAP,"private-secret\n",SECOND);}catch(PositronException e){throw new AssertionError(e);}});check(calls.get()==0,"credential injection sent");check(client.call(RPC,CAP,"private-secret",SECOND).path("api_major").asInt()==1,"normal capability");
    }else if(mode.equals("old")){
     var e=failure(client,"positron.v1.LogQueryService/Session",Map.of("execute",query(),"batchLimit",1),SECOND);check(e.failure.equals("UnsupportedFeature")&&e.completionState.equals("COMPLETION_STATE_REJECTED"),"old peer refusal");
    }else {
     boolean finite=mode.equals("deadline");long start=System.nanoTime();var e=failure(client,finite?"positron.v1.LogQueryService/Execute":RPC,finite?query():CAP,finite?Duration.ofSeconds(30):mode.equals("truncated")||mode.equals("oversize")||mode.equals("redirect")?SECOND:Duration.ofMillis(80));long elapsed=System.nanoTime()-start;
     if(!mode.equals("redirect"))check(e.completionState.equals("COMPLETION_STATE_AMBIGUOUS")&&e.retryClass.equals("RETRY_CLASS_NEVER"),"ambiguity lost");
     check(elapsed<TimeUnit.SECONDS.toNanos(finite?6:2),"total deadline lost");
    }
    serving.get(7,TimeUnit.SECONDS);worker.shutdownNow();check(calls.get()==1,"effect retried");
   }
  }
  for(String framing:List.of("normal","chunked","truncated")) {
   try(var server=new ServerSocket(0,8,InetAddress.getLoopbackAddress())) {
    var calls=new AtomicInteger();var worker=Executors.newSingleThreadExecutor(r->{var t=new Thread(r);t.setDaemon(true);return t;});
    var serving=worker.submit(()->{try{for(int i=0;i<2;i++)try(var socket=server.accept()){
     socket.setSoTimeout(2000);calls.incrementAndGet();var input=new BufferedReader(new InputStreamReader(socket.getInputStream(),StandardCharsets.US_ASCII));String line;int length=0;while((line=input.readLine())!=null&&!line.isEmpty())if(line.toLowerCase(Locale.ROOT).startsWith("content-length:"))length=Integer.parseInt(line.substring(15).trim());for(int n=0;n<length;n++)if(input.read()<0)break;
     String payload=i==0?"{\"api_major\":1,\"schema_digest\":\""+Codec.SCHEMA_DIGEST+"\",\"availability\":1,\"refusal\":null,\"capability\":4}":"{\"cancelled\":true}";
     String wire=i==1&&framing.equals("chunked")?"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"+Integer.toHexString(payload.length())+"\r\n"+payload+"\r\n0\r\n\r\n":"HTTP/1.1 200 OK\r\nContent-Length: "+(payload.length()+(i==1&&framing.equals("truncated")?5:0))+"\r\nConnection: close\r\n\r\n"+payload;
     socket.getOutputStream().write(wire.getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().flush();
    }}catch(Exception e){throw new RuntimeException(e);}});
    var client=new Client("http://127.0.0.1:"+server.getLocalPort(),true);var cancel=Map.of("query","YQ==");
    if(framing.equals("truncated")){var e=failure(client,"positron.v1.LogQueryService/Cancel",cancel,SECOND);check(e.completionState.equals("COMPLETION_STATE_AMBIGUOUS"),"truncated cancellation acknowledged");}
    else check(client.call("positron.v1.LogQueryService/Cancel",cancel,"private-secret",SECOND).path("cancelled").asBoolean(),"valid cancellation framing refused");
    serving.get(3,TimeUnit.SECONDS);worker.shutdownNow();check(calls.get()==2,"cancellation retried");
   }
  }
  long start=System.nanoTime();var dns=failure(new Client("https://positron-missing.invalid"),RPC,CAP,Duration.ofMillis(100));check(System.nanoTime()-start<TimeUnit.SECONDS.toNanos(2)&&dns.completionState.equals("COMPLETION_STATE_AMBIGUOUS"),"DNS deadline");
  if(args.length>1) {
   var keys=java.security.KeyStore.getInstance("PKCS12");try(var in=Files.newInputStream(Path.of(args[1]))){keys.load(in,"test-only".toCharArray());}
   var manager=javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());manager.init(keys,"test-only".toCharArray());var context=javax.net.ssl.SSLContext.getInstance("TLS");context.init(manager.getKeyManagers(),null,null);
   var server=com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(),0),8);server.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(context));server.createContext("/",exchange->{exchange.sendResponseHeaders(200,-1);exchange.close();});server.start();
   try{var e=failure(new Client("https://localhost:"+server.getAddress().getPort()),RPC,CAP,SECOND);check(e.completionState.equals("COMPLETION_STATE_AMBIGUOUS"),"untrusted TLS accepted");}finally{server.stop(0);}
  }
  System.out.println("JVM transport bounds and compatibility passed");
 }
}
