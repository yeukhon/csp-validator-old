import pyparsing
from pyparsing import alphas, Literal, nums, OneOrMore, Optional, Regex, White, Word, ZeroOrMore, Group, Dict, Suppress, Or, delimitedList, StringEnd, printables, Combine, alphanums


space = Suppress(White(" \t"))
port = Word(nums)
host_char = Word(alphas + nums + "-" + ".")
#host_char = Regex(r'[a-zA-Z][a-zA-Z0-9+.-]*')   # rfc 3986 implementation
host = Literal("*") | OneOrMore(host_char + ZeroOrMore(Literal("*") + OneOrMore(host_char)))
scheme = Literal("https") | Literal("http")
host_source = Optional(scheme + Literal("://")) + Optional(Literal("*.")) + host + Optional(port)
keyword_source = Literal("'self'") | Literal("'unsafe-inline'") | Literal("'unsafe-eval'") | Literal("'none'")
source_expression = delimitedList(host_source, combine=True, delim=Literal(".")) | keyword_source
source_list = ZeroOrMore(space) + source_expression + ZeroOrMore(OneOrMore(space) + source_expression) + ZeroOrMore(space)
directive_value = source_list
directive_name = Literal("default-src") | Literal("script-src")
directive = Dict(Group(directive_name + space + OneOrMore(directive_value + ZeroOrMore(space))))
rest_of_directives = Literal(";") + directive
policy = directive + ZeroOrMore(rest_of_directives)

strs = [
    "default-src 'self'",
    "default-src 'self';",
    "default-src 'none'",
    "default-src 'none';",
    "default-src 'self' http://example.org",
    "default-src 'self' example.org",
    "default-src 'self' *.example.org",
    "default-src 'self' 'none';",
    "default-src http://example.org 'self'",
    "default-src example.org 'self'",
    "default-src *.example.org 'self'",
    "default-src example.org http://example.org https://example.org 'none'"
]

def test():

    for str in strs:
        try:
            p = policy.parseString(str)
            print str, ' ----> ', policy.parseString(str)
        except pyparsing.ParseException:
            print "ERROR"
            
    print '++'

    for str in strs:
        try:
            str = str.replace('default-src', 'script-src')
            print str, ' ---->', policy.parseString(str)
        except pyparsing.ParseException:
            print "ERROR"


test()        
