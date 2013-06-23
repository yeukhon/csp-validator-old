# -*- coding: utf-8 -*-

from parsimonious.grammar import Grammar


uri = r'(http://|https://|\*\.)?' + \
      r'([a-z0-9][-a-z0-9]+)(\.[a-z0-9][-a-z0-9]+)+(:\d+)?'

grammar = Grammar(
    """
    policy = (directive_name space directive_value semicolon? space?)+ 
    directive_name = "default-src" / "script-src"
    directive_value = "*" / "'none'" / "'self'" / "https:" / uri
    space = ~"\s*"
    semicolon = ";"
    uri = ~"%s"
    """ % uri)

strs = [
        "default-src 'self'",
        "default-src 'self';",
        "default-src 'none'",
        "default-src 'none';",
        "default-src https:",
        "default-src https:;",
        "script-src userscripts.example.com",
]

def test():

    for str in strs:
        print str, ' ----> ', grammar.parse(str)
    print '++'

    for str in strs:
        str = str.replace('default-src', 'script-src')
        print str, ' ---->', grammar.parse(str)

test()        
