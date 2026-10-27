# Static desktop application fixtures

`environment.json` is the explicit XDG/terminal model used by the retained
payload audit. It describes staged paths; none are read from the active host.
`handler.desktop` is original fixture data for no-input field expansion and
NoDisplay MIME-handler inspection. Its `demo` executable is deliberately absent;
never launch this fixture. The unittest suite builds private temporary roots
and never executes their files.
