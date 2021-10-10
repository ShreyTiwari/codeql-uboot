import cpp

from MacroInvocation mcall, Macro m
where (m.getName() = "ntohs" or m.getName() = "ntohl" or m.getName() = "ntohll") and mcall.getMacro() = m
select mcall
