use crate::labels::{Cap, DataLabel, LabelRule};

// TODO: refactor this 
pub static RULES: &[LabelRule] = &[
  LabelRule { matchers: &["document.location", "window.location"], label: DataLabel::Source(Cap::all()), },
  LabelRule { matchers: &["JSON.parse"],       label: DataLabel::Sanitizer(Cap::JSON_PARSE) },
  LabelRule { matchers: &["eval"],             label: DataLabel::Sink(Cap::SHELL_ESCAPE) },
];
