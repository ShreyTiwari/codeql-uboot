import cpp

predicate isNTOH(string name) {
    name = "ntohs" or name = "ntohl" or name = "ntohll"
}

from MacroInvocation mcall, Macro m
where isNTOH(m.getName()) and mcall.getMacro() = m
select mcall.getExpr()
