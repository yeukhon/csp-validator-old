import pyparsing
from pyparsing import alphas, Literal, nums, OneOrMore, Optional, Regex, White, Word, ZeroOrMore

directive_name = Literal("default-src") | Literal("script-src")
#directive_value = Literal("'self'") | Literal("'none'") | Literal("https:")
keyword_source = Literal("'self'") | Literal("'unsafe-inline'") | Literal("'unsafe-eval'") | Literal("'none'")
port = ":" + nums
scheme = Literal("http") | Literal("https")
host_char = Word(alphas) | Word(nums) | Literal("-")
host = Literal("*") | Literal("*.") + host_char + ZeroOrMore("." + host_char)
host_source = Optional(scheme + "://") + host + Optional(port)
source_expression = host_source | keyword_source # skip scheme_source for now
#source_list = source_expression + ZeroOrMore(OneOrMore(Regex(' \t')) + source_expression)
source_list = source_expression + ZeroOrMore(OneOrMore(Literal(" "))+ source_expression)
directive_value = source_list
directive = directive_name + directive_value
remain_policy = ';' + directive
policy = directive + ZeroOrMore(remain_policy)

strs = [
        "default-src 'self'",
        "default-src 'self';",
        "default-src 'none'",
        "default-src 'none';",
        "default-src 'self' trusted-scripts.foo.com",
        "default-src 'self' 'none';"
]

def test():

    for str in strs:
        try:
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
