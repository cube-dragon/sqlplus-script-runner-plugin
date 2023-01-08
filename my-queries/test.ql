/**
 * @kind problem
 * @id my-queries/test
 */

 import java
//获取某个类方法里面的某种名称的方法调用，并且用行号筛选
 from Method method, Callable logCall, Call callResult
 where
   method.hasName("run") and
   method.getDeclaringType().hasQualifiedName("org.jenkinsci.plugins.sqlplus.script.runner", "SQLPlusRunner") and
   method.getACallee() = logCall and
   logCall.getName() = "print" and
   callResult = method.getACallSite(logCall) and
   callResult.getLocation().getEndLine() = 411
 select callResult.getArgument(0), "method1"
