### Security — the console escapes mediator text before showing it

- A refusal's code and comment, and the text `ConsoleError::explain` returns,
  now have control characters, line and paragraph separators and
  bidirectional formatting marks escaped (`\u{1b}`). A mediator, or anything
  that can shape a refusal's comment, can no longer send ANSI/OSC escape
  sequences or reordering marks that rewrite the operator's terminal or
  disguise a confirmation. Other text, non-ASCII included, is shown as before.
