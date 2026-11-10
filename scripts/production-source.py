# SPDX-License-Identifier: GPL-3.0-or-later
"""Inspect release source while excluding bounded interpreter fixtures."""
import re

MARKER = re.compile(r'#\[cfg\(all\(test, trames_interpreter_conformance\)\)\]\s*')
LITERALS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|r(\#*)"[\s\S]*?"\1|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])\'')

def production(text):
    while match := MARKER.search(text):
        start = match.end()
        # Stacked attributes belong to the same excluded item.
        while text.startswith('#[', start):
            start = text.index(']', start) + 1
            while text[start:start + 1].isspace():
                start += 1
        masked = LITERALS.sub(lambda m: ' ' * len(m[0]), text)
        if re.match(r'\w+,', text[start:]):
            end = text.index(',', start) + 1
        elif re.match(r'(?:pub(?:\([^)]*\))?\s+)?\w+\s*:', text[start:]):
            end = text.index('\n', start)
            brace = masked.find('{', start, end)
            if brace >= 0:
                end = brace + 1
                depth = 1
                while depth:
                    depth += (masked[end] == '{') - (masked[end] == '}')
                    end += 1
                end = text.index('\n', end)
        else:
            parens = brackets = 0
            end = start
            while end < len(masked):
                c = masked[end]
                if c == '(':
                    parens += 1
                elif c == ')':
                    parens -= 1
                elif c == '[':
                    brackets += 1
                elif c == ']':
                    brackets -= 1
                elif not parens and not brackets and c in '{;':
                    end += 1
                    if c == '{':
                        depth = 1
                        while depth:
                            depth += (masked[end] == '{') - (masked[end] == '}')
                            end += 1
                    break
                end += 1
        text = text[:match.start()] + text[end:]
    return text
