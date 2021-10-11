import cpp

class NetworkByteSwap extends Expr {
    NetworkByteSwap(){
        exists(MacroInvocation mcall | mcall.getMacroName() = "ntohs" or mcall.getMacroName() = "ntohl" or mcall.getMacroName() = "ntohll" | this = mcall.getExpr())
    }
}

from NetworkByteSwap n
select n, "Network byte swap"
