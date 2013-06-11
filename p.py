import pyparsing
from pyparsing import alphas, Literal, Word, ZeroOrMore, Regex

directive_name = Literal("default-src") | Literal("script-src")
directive_value = Literal("'self'") | Literal("'none'") | Literal("https:")
#directive = ZeroOrMore(Regex(' \t')) + directive_name + Regex(' \t') + directive_value
directive = directive_name + directive_value
remain_policy = ';' + directive
policy = directive + ZeroOrMore(remain_policy)

strs = [
        "default-src 'self'",
        "default-src 'self';",
        "default-src 'none'",
        "default-src 'none';",
        "default-src https:",
        "default-src https:;",
        "default-src none"
]

def test():

    for str in strs:
        try:
            print str, ' ----> ', policy.parseString(str)
        except pyparsing.ParseException:
            pass
    print '++'

    for str in strs:
        try:
            str = str.replace('default-src', 'script-src')
            print str, ' ---->', policy.parseString(str)
        except pyparsing.ParseException:
            pass

test()        
