/**
 * @kind path-problem
 */

 import cpp
 import semmle.code.cpp.dataflow.TaintTracking
 import DataFlow::PathGraph

 class NetworkByteSwap extends Expr {
    NetworkByteSwap(){
        exists(MacroInvocation mcall | mcall.getMacroName() = "ntohs" or mcall.getMacroName() = "ntohl" or mcall.getMacroName() = "ntohll" | this = mcall.getExpr())
    }
}

class Config extends TaintTracking::Configuration {
    Config() { this = "NetworkToMemFuncLength" }
    
    override predicate isSource(DataFlow::Node node) {
        node.asExpr() instanceof NetworkByteSwap
    }
    
    override predicate isSink(DataFlow::Node node) {
        exists(FunctionCall fcall 
            | node.asExpr() = fcall.getArgument(2) and fcall.getTarget().getName() = "memcpy"
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
