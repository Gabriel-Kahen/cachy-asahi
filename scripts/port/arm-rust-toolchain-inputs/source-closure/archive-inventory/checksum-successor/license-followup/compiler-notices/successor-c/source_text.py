"""Extract one docs.rs source-code element as inert UTF-8 DATA."""
from html.parser import HTMLParser


class SourceText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth, self.count, self.parts = 0, 0, []

    def handle_starttag(self, tag, attrs):
        if dict(attrs).get('id') == 'source-code':
            if self.depth:
                raise ValueError('nested source element')
            self.count += 1
            self.depth = 1
        elif self.depth:
            self.depth += 1

    def handle_endtag(self, tag):
        if self.depth:
            self.depth -= 1

    def handle_data(self, text):
        if self.depth:
            self.parts.append(text)


def extract(body):
    parser = SourceText()
    parser.feed(body.decode('utf-8', errors='strict'))
    parser.close()
    if parser.count != 1 or parser.depth:
        raise ValueError('one complete source element required')
    return ''.join(parser.parts).encode('utf-8')
