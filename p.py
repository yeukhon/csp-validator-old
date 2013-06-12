import pyparsing
from pyparsing import alphas, Literal, nums, OneOrMore, Optional, Regex, White, Word, ZeroOrMore, Group, Dict, Suppress


space = Suppress(White(" \t"))
directive_value = Literal("'self'") | Literal("'none'") | Literal("*.foo.com")
directive_name = Literal("default-src") | Literal("script-src")
directive = Dict(Group(directive_name + space + OneOrMore(directive_value + ZeroOrMore(space))))
rest_of_directives = Literal(";") + directive
policy = directive + ZeroOrMore(rest_of_directives)
strs = [
        "default-src 'self'",
        "default-src 'self';",
        "default-src 'none'",
        "default-src 'none';",
        "default-src 'self' *.foo.com",
        "default-src 'self' 'none';"
]

def test():

    for str in strs:
        try:
            p = policy.parseString(str)
            print 'v ', p['default-src']
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
