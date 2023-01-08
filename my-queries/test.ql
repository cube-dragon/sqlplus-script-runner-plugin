/**
 * @id my-queries/test
 * @name CVE-2020-2312
 * @description CVE-2020-2312
 * @kind problem
 * @problem.severity warning
 */

 import java
 import semmle.code.java.dataflow.FlowSources
 import semmle.code.java.security.QueryInjection
 import DataFlow::PathGraph
 
 //打通了args.toList()，可以追溯args这个变量，但是到不了常量，因为add()这个方法codeql检测不到
 predicate isTaintedString1(Expr expSrc, Expr expDest) {
  exists(Method method, MethodAccess call|
     expSrc = call.getQualifier() and 
     expDest = call and 
     call.getMethod() = method and 
     method.hasName("toList")
     ) 
}

//打通了args.add()，可以追溯到各个常量，不过出来的的结果有点多，默认先注释
predicate isTaintedString2(Expr expSrc, Expr expDest) {
  exists(Method method, MethodAccess call|
     expSrc = call.getArgument(0) and //获得add方法调用的第一个参数
     expDest = call.getQualifier() and //获得args
     call.getMethod() = method and
     method.hasName("add")
     )
}
 
 private class LoggerSink extends DataFlow::Node {
    LoggerSink() {
        exists( Method method, Callable logCall, Call callResult| 
            method.hasName("run") and
            method.getDeclaringType().hasQualifiedName("org.jenkinsci.plugins.sqlplus.script.runner", "SQLPlusRunner") and
            method.getACallee() = logCall and
            logCall.getName() = "print" and
            callResult = method.getACallSite(logCall) and
            callResult.getLocation().getEndLine() = 411 and
            this.asExpr() = callResult.getArgument(0))
    }
 }

 class Config extends TaintTracking::Configuration {
   Config() { this = "loggerPrint" }
   
   override predicate isSource(DataFlow::Node src) { any() }
 
   override predicate isSink(DataFlow::Node sink) { sink instanceof LoggerSink }

   override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    isTaintedString1(node1.asExpr(), node2.asExpr())
    or
    isTaintedString2(node1.asExpr(), node2.asExpr())
  }
 }
 
 
 from Config config, DataFlow::PathNode source, DataFlow::PathNode sink
 where config.hasFlowPath(source, sink)
 select source, "source"
