import pyparsing
from pyparsing import alphas, Literal, nums, OneOrMore, Optional, Regex, White, Word, ZeroOrMore

space = White(' \t')
directive_name = Literal("default-src") | Literal("script-src")
keyword_source = Literal("'self'") | Literal("'unsafe-inline'") | Literal("'unsafe-eval'") | Literal("'none'")
port = ":" + nums
scheme = Literal("http") | Literal("https")
#host_char = Word(alphas) | Word(nums) | Literal("-")
host_char = Literal("*.foo.com")
host = Literal("*") | Literal("*.") + OneOrMore(host_char) + ZeroOrMore("." + OneOrMore(host_char))
host_source = Optional(scheme + "://") + host + Optional(port)
source_expression = host_source | keyword_source # skip scheme_source for now
source_list = ZeroOrMore(space) + source_expression + ZeroOrMore(OneOrMore(space)+ source_expression) + ZeroOrMore(space)
directive_value = ZeroOrMore(space | source_list)
directive = ZeroOrMore(space) + directive_name + space + directive_value
remain_policy = ';' + directive
policy = directive + ZeroOrMore(remain_policy)
print policy

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
