using Positron;
using System.Text.Json.Nodes;
using System.Text;
using System.Net;
using System.Net.Sockets;
class Program {
 static JsonNode P(JsonNode n,string k)=>(n as JsonObject)?[k];
 static string S(JsonNode n)=>n?.GetValue<string>()??"";
 static bool B(JsonNode n)=>n?.GetValue<bool>()??false;
 static IEnumerable<JsonNode> Items(JsonNode n)=>(n as JsonArray)??new JsonArray();
 static void Check(bool b,string id){if(!b)throw new Exception(id);}
 static void Refused(Action f,string id){try{f();throw new Exception("accepted "+id);}catch(WireException){}}
 static async Task Main(string[] args){
  if(args.Length==1&&args[0]=="live"){await Live();return;}
  var fixture=Codec.Parse(File.ReadAllBytes(Path.Combine(args[0],"query-golden-fixtures.json")));
  foreach(var c in Items(P(fixture,"representations"))){var id=S(P(c,"id"));if(B(P(c,"accepted")))Check(JsonNode.DeepEquals(Codec.Decode(S(P(c,"type")),Encoding.UTF8.GetBytes(S(P(c,"input")))),P(c,"canonical")),id);else Refused(()=>Codec.Decode(S(P(c,"type")),Encoding.UTF8.GetBytes(S(P(c,"input")))),id);}
  foreach(var bad in new[]{"\ud800","\udc00","a\ud800x"}){Refused(()=>Codec.Bytes(new Dictionary<string,string>{{"key",bad}}),"native text");Refused(()=>Codec.Bytes(new Dictionary<string,string>{{bad,"value"}}),"native key");Refused(()=>Codec.Bytes(new JsonObject{{"key",bad}}),"native node");Refused(()=>Codec.Bytes(new{Payload=new JsonObject{{"key",bad}}}),"nested native node");Refused(()=>Codec.Bytes(new{Payload=new JsonObject{{bad,"value"}}}),"nested native key");}
  Refused(()=>Codec.Bytes(new{key=new string('x',262145)}),"bounded serialization");Check(S(P(Codec.Parse(Codec.Bytes(new{key="\ud83d\ude00\ufffd\\"})),"key"))=="\ud83d\ude00\ufffd\\","valid native text");
  // Non-emitted fields must not affect the serializer's accepted public shape.
  Check(S(P(Codec.Parse(Codec.Bytes(new Hidden())),"Value"))=="valid","hidden private text");
  foreach(var c in Items(P(fixture,"responses"))){var mode=S(P(c,"mode"));if(mode=="")mode="execute";if(B(P(c,"accepted")))Query.Decode(Codec.Bytes(P(c,"input")),mode);else Refused(()=>Query.Decode(Codec.Bytes(P(c,"input")),mode),S(P(c,"id")));}
  foreach(var c in Items(P(fixture,"errors"))){var e=PositronException.Query(P(c,"status").GetValue<int>(),Codec.Bytes(P(c,"input")),B(P(c,"cancellation")));Check(e.Failure==S(P(c,"failure"))&&e.RetryClass==S(P(c,"retryClass"))&&e.CompletionState==S(P(c,"completionState")),S(P(c,"id")));}
  Delivery(fixture);
  await Transport(fixture);
  await Refusals();
  await Compatibility(fixture);
  Console.WriteLine(".NET canonical goldens, delivery and transport passed");
 }
 sealed class Hidden { readonly string secret="\ud800";public string Value=>"valid";public override string ToString()=>secret; }
 static void Delivery(JsonNode fixture){
  JsonNode Response(string id)=>Items(P(fixture,"responses")).First(c=>S(P(c,"id"))==id)["input"].DeepClone();
  var tracker=new BatchTracker("session");var first=Response("one-batch-complete");Check(tracker.Filter(first).Count==1,"first delivery");Check(tracker.Filter(first).Count==0,"repeat delivery");
  var changed=first.DeepClone();changed["events"][1]["batch"]["rows"][0]["cells"][0]["nativeValue"]["textValue"]="changed";Refused(()=>tracker.Filter(changed),"changed receipt");Check(tracker.Filter(first).Count==0,"receipt failure atomic");Check(Query.TerminalStatus(first["events"][2]["terminal"])=="complete","complete terminal");
  var keyTracker=new BatchTracker("session");var objectBatch=Response("one-batch-complete");objectBatch["events"][1]["batch"]["rows"][0]["cells"][0]["nativeValue"]=Codec.Parse("{\"objectValue\":{\"entries\":[{\"key\":\"0\",\"value\":{\"textValue\":\"same\"}}]}}");Check(keyTracker.Filter(objectBatch).Count==1,"object key first delivery");var receipt=keyTracker.Acknowledgement;var changedKey=objectBatch.DeepClone();changedKey["events"][1]["batch"]["rows"][0]["cells"][0]["nativeValue"]["objectValue"]["entries"][0]["key"]="";Refused(()=>keyTracker.Filter(changedKey),"changed zero string object key");Check(keyTracker.Acknowledgement==receipt&&keyTracker.Filter(objectBatch).Count==0,"object key failure atomic");
  var tail=new BatchTracker("tail");Check(tail.Acknowledgement==null,"empty receipt");var start=Response("tail-single-incomplete");Check(tail.Filter(start).Count==1,"tail first");Check(tail.Filter(start).Count==0,"tail repeat");Check(tail.Acknowledgement.Sequence=="0","tail receipt");
  var next=Response("tail-next-incomplete");var gap=next.DeepClone();gap["events"][1]["batch"]["sequence"]="4";Refused(()=>tail.Filter(gap),"sequence gap");Check(tail.Filter(next).Count==1,"tail next");Refused(()=>tail.Filter(start),"old receipt");
  var schema=new BatchTracker("tail");schema.Filter(start);var other=next.DeepClone();other["events"][0]["header"]["columns"][0]["name"]="other";Refused(()=>schema.Filter(other),"schema changed");Check(schema.Filter(next).Count==1,"schema failure atomic");
  var rebound=new BatchTracker("tail");rebound.Filter(start);other=next.DeepClone();other["events"][0]["header"]["snapshot"]["identity"]=System.Convert.ToBase64String(Enumerable.Repeat((byte)9,32).ToArray());Check(rebound.Filter(other).Count==1,"tail snapshot may rebind");
  var terminal=start["events"][2]["terminal"].DeepClone();terminal["state"]="complete";Refused(()=>Query.TerminalStatus(terminal),"false terminal");
 }
 static async Task Transport(JsonNode fixture){
  var valid=Items(P(fixture,"responses")).First(c=>B(P(c,"accepted"))&&(S(P(c,"mode"))==""||S(P(c,"mode"))=="execute"));
  var response=Codec.Bytes(P(valid,"input"));
  var budget=new JsonObject{{"scannedBytes","1024"},{"decodedRecords","16"},{"outputRows","16"},{"outputBytes","4096"},{"memoryBytes","8192"},{"cpuWorkUnits","16"},{"wallSeconds",1},{"maximumTimeRangeNanoseconds","1000"}};
  var request=new JsonObject{{"pipeline","logs | limit 1"},{"budget",budget}};
  foreach(var mode in new[]{"headers","body","drip","truncated","tls","cancel","execute-ceiling"}){
   var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;
   using var stop=new CancellationTokenSource();var server=Task.Run(async()=>{try{using var socket=await listener.AcceptTcpClientAsync(stop.Token);using var stream=socket.GetStream();var buffer=new byte[8192];await stream.ReadAsync(buffer,stop.Token);if(mode=="headers"||mode=="tls"||mode=="cancel"||mode=="execute-ceiling"){await Task.Delay(mode=="execute-ceiling"?8000:1000,stop.Token);return;}var header=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: "+(response.Length+(mode=="truncated"?10:0))+"\r\nConnection: close\r\n\r\n");await stream.WriteAsync(header,stop.Token);if(mode=="body")await Task.Delay(1000,stop.Token);else if(mode=="drip")foreach(var b in response){await stream.WriteAsync(new[]{b},stop.Token);await Task.Delay(50,stop.Token);}else await stream.WriteAsync(response,stop.Token);}catch(Exception e) when(e is OperationCanceledException or IOException or ObjectDisposedException){} });
   using var client=new Client((mode=="tls"?"https":"http")+"://127.0.0.1:"+port,mode!="tls");var watch=System.Diagnostics.Stopwatch.StartNew();using var cancel=new CancellationTokenSource();if(mode=="cancel")cancel.CancelAfter(80);try{await client.CallAsync("positron.v1.LogQueryService/Execute",request,timeout:mode=="execute-ceiling"?TimeSpan.FromSeconds(30):mode=="cancel"?TimeSpan.FromSeconds(3):TimeSpan.FromMilliseconds(120),cancellation:cancel.Token);throw new Exception("accepted "+mode);}catch(PositronException e){Check(e.CompletionState=="COMPLETION_STATE_AMBIGUOUS"&&e.RetryClass=="RETRY_CLASS_NEVER",mode+" truth");Check(watch.Elapsed<TimeSpan.FromSeconds(mode=="execute-ceiling"?6:2),mode+" deadline");if(mode=="execute-ceiling")Check(watch.Elapsed>=TimeSpan.FromSeconds(4.5),"finite Execute ceiling");}finally{stop.Cancel();listener.Stop();await server;}
  }
 }
 static async Task Reply(int status,string body,Func<Client,Task> call,Action<JsonNode> inspectRequest=null){
  var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;int calls=0;
  var server=Task.Run(async()=>{using var socket=await listener.AcceptTcpClientAsync();Interlocked.Increment(ref calls);using var stream=socket.GetStream();var headerBytes=new List<byte>();var one=new byte[1];while(headerBytes.Count<8192){await stream.ReadExactlyAsync(one);headerBytes.Add(one[0]);if(headerBytes.Count>=4&&headerBytes.TakeLast(4).SequenceEqual(new byte[]{13,10,13,10}))break;}var headers=Encoding.ASCII.GetString(headerBytes.ToArray());var contentLength=int.Parse(headers.Split("\r\n").First(h=>h.StartsWith("Content-Length:",StringComparison.OrdinalIgnoreCase)).Split(':',2)[1]);Check(contentLength>=0&&contentLength<=8192,"bounded fixture request");var requestBody=new byte[contentLength];await stream.ReadExactlyAsync(requestBody);inspectRequest?.Invoke(Codec.Parse(requestBody));var bytes=Encoding.UTF8.GetBytes(body);await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status} test\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n"));await stream.WriteAsync(bytes);});
  try{using var client=new Client("http://127.0.0.1:"+port,true);await call(client);await server;Check(calls==1,"one effect attempt");}finally{listener.Stop();}
 }
 static async Task Refusals(){
  foreach(var test in new[]{
   ("{\"code\":\"capacity_unavailable\"}","capacity_unavailable","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   ("{\"code\":\"capacity_unavailable\",\"retry_class\":\"RETRY_CLASS_AFTER_BACKOFF\",\"completion_state\":\"COMPLETION_STATE_REJECTED\"}","capacity_unavailable","RETRY_CLASS_AFTER_BACKOFF","COMPLETION_STATE_REJECTED"),
   ("{\"code\":8,\"retry_class\":2,\"completion_state\":1,\"source\":4,\"safe_detail\":8}","PUBLIC_ERROR_CODE_CAPACITY_UNAVAILABLE","RETRY_CLASS_AFTER_BACKOFF","COMPLETION_STATE_REJECTED"),
   ("{\"code\":\"private-secret-unknown\"}","Transport","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   ("{\"code\":\"capacity_unavailable\",\"retry_class\":2,\"completion_state\":2}","Transport","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS"),
   ("{","Transport","RETRY_CLASS_NEVER","COMPLETION_STATE_AMBIGUOUS")}){
   await Reply(503,test.Item1,async client=>{try{await client.CallAsync("positron.v1.BackupService/Manage",new{action="capture"},"private-secret",TimeSpan.FromSeconds(1));throw new Exception("refusal accepted");}catch(PositronException e){Check(e.Failure==test.Item2&&e.RetryClass==test.Item3&&e.CompletionState==test.Item4,"native refusal certainty");Check(!e.ToString().Contains("private-secret"),"safe exception");if(e.Failure.StartsWith("PUBLIC_ERROR_CODE_"))Check(e.Source=="FAILURE_SOURCE_QUERY_EXECUTION"&&e.SafeDetail=="SAFE_DETAIL_CAPACITY_UNAVAILABLE","native error detail");}});
  }

 }
 // Synthetic v1 peer fixtures exercise contract skew; these are not historical release binaries.
 static async Task Compatibility(JsonNode fixture){
  var request=new Types.LogQueryRequest{Pipeline="pipeline:v1 logs | range query_time 0 100 | project commit_position | limit 1",Budget=new(){ScannedBytes="1024",DecodedRecords="16",OutputRows="16",OutputBytes="4096",MemoryBytes="8192",CpuWorkUnits="16",WallSeconds="1",MaximumTimeRangeNanoseconds="1000"}};
  void OldV1Request(JsonNode wire){Check(wire is JsonObject fields&&fields.Count==2&&fields.ContainsKey("pipeline")&&fields.ContainsKey("budget"),"old-v1 baseline request fields");var budget=(JsonObject)wire["budget"];Check(budget.Count==8&&new[]{"scannedBytes","decodedRecords","outputRows","outputBytes","memoryBytes","cpuWorkUnits","wallSeconds","maximumTimeRangeNanoseconds"}.All(budget.ContainsKey),"old-v1 baseline budget fields");}
  var baseline=Items(P(fixture,"responses")).First(c=>S(P(c,"id"))=="one-batch-complete")["input"];
  await Reply(200,baseline.ToJsonString(),async client=>{var result=await client.LogQueryExecuteAsync(request,timeout:TimeSpan.FromSeconds(1));var wire=Codec.Parse(Codec.Bytes(result));Check(Query.TerminalStatus(wire["events"][2]["terminal"])=="complete"&&new BatchTracker("session").Filter(wire).Count==1,"new client old-v1 server baseline");},OldV1Request);
  var failure=Items(P(fixture,"errors")).First(c=>S(P(c,"id"))=="capacity_unavailable");
  await Reply(P(failure,"status").GetValue<int>(),P(failure,"input").ToJsonString(),async client=>{try{await client.LogQueryExecuteAsync(request,timeout:TimeSpan.FromSeconds(1));throw new Exception("old-v1 server refusal accepted");}catch(PositronException e){Check(e.Failure==S(P(failure,"failure"))&&e.RetryClass==S(P(failure,"retryClass"))&&e.CompletionState==S(P(failure,"completionState")),"new client old-v1 server stable failure");}},OldV1Request);
  await Reply(200,"{\"api_major\":1,\"capability\":4,\"availability\":2,\"schema_digest\":\""+new string('a',64)+"\"}",async client=>{try{await client.LogQuerySessionAsync(new(){BatchLimit=1,Resume="AQ=="},timeout:TimeSpan.FromSeconds(1));throw new Exception("old-v1 peer unsupported effect sent");}catch(PositronException e){Check(e.Failure=="UnsupportedFeature"&&e.CompletionState=="COMPLETION_STATE_REJECTED","new client old-v1 server refuses before unsupported effect");}});
 }
 static async Task<JsonNode> Admitted(Func<Task<Types.LogQueryResponse>> call){for(int i=0;i<5;i++){try{return Codec.Parse(Codec.Bytes(await call()));}catch(PositronException e) when(e.Failure=="CapacityUnavailable"){await Task.Delay(1000);}}throw new Exception("admission exhausted");}
 static async Task Live(){
  var input=Codec.Parse(await Console.In.ReadToEndAsync());using var client=new Client(S(P(input,"endpoint")),true);string bearer=S(P(input,"bearer"));var timeout=TimeSpan.FromSeconds(5);
  // The canonical old-v1 request omits the additive capability field. Read only baseline response fields.
  var oldRequest=P(input,"old_client_request");Check(oldRequest is JsonObject oldShape&&oldShape.Count==1&&P(oldRequest,"api_major").GetValue<int>()==1,"pinned old-v1 request");
  var capability=await client.CallAsync("positron.v1.CapabilityService/Negotiate",oldRequest);Check(P(capability,"api_major").GetValue<int>()==1&&S(P(capability,"schema_digest"))==Codec.SchemaDigest,"old-v1 client shape new server baseline");
  var budget=new Types.LogQueryBudget{ScannedBytes="1048576",DecodedRecords="16",OutputRows="16",OutputBytes="16384",MemoryBytes="1048576",CpuWorkUnits="16",WallSeconds="5",MaximumTimeRangeNanoseconds="100"};
  var query=new Types.LogQueryRequest{Budget=budget,Pipeline="pipeline:v1 logs | range query_time 0 100 | project commit_position | limit 2"};
  var first=await Admitted(()=>client.LogQueryExecuteAsync(query,bearer,timeout));var tracker=new BatchTracker("session");Check(tracker.Filter(first).Count==1,"execute");
  var page=await Admitted(()=>client.LogQuerySessionAsync(new(){BatchLimit=1,Execute=query},bearer,timeout));tracker=new BatchTracker("session");tracker.Filter(page);var events=Items(P(page,"events")).ToList();var terminal=P(events[^1],"terminal");Check(Query.TerminalStatus(terminal)=="continued","session");string resume=S(P(terminal,"continuationCursor"));
  var second=await Admitted(()=>client.LogQuerySessionAsync(new(){BatchLimit=1,Resume=resume},bearer,timeout));tracker.Filter(second);
  page=await Admitted(()=>client.LogQuerySessionAsync(new(){BatchLimit=1,Execute=query},bearer,timeout));string cursor=S(P(P(Items(P(page,"events")).First(),"header"),"initialCursor"));Check((await client.LogQueryCancelAsync(new(){Query=cursor},bearer,timeout)).Cancelled==true,"cancel");
  var tailQuery=new Types.LogQueryRequest{Budget=budget with {WallSeconds="60"},Pipeline="pipeline:v1 logs | range query_time 0 100 | project commit_position | limit all"};
  var tail=await Admitted(()=>client.LogQuerySessionAsync(new(){BatchLimit=1,Tail=new(){Query=tailQuery}},bearer,timeout));tracker=new BatchTracker("tail");tracker.Filter(tail);cursor=S(P(P(Items(P(tail,"events")).Last(),"terminal"),"continuationCursor"));Check((await client.LogQueryCancelAsync(new(){Tail=cursor},bearer,timeout)).Cancelled==true,"tail cancel");
  try{await client.LogQueryExecuteAsync(query,"invalid",timeout);throw new Exception("authentication accepted");}catch(PositronException e){Check(e.Failure=="AuthenticationRejected"&&e.CompletionState=="COMPLETION_STATE_REJECTED","old-v1 baseline client new server stable authentication/completion");}
  await client.TenantListAsync(new Types.TenantListRequest(),S(P(input,"admin")),timeout);
  Console.WriteLine(".NET live conformance passed");
 }
}
