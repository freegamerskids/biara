//! One line of code as a Rune element: coloured runs, plus clickable names.
//!
//! Disassembly rows, graph nodes and pseudocode lines all need "mono text where some runs
//! are colours and some runs go somewhere when clicked". [`Line`] collects the runs and
//! builds the element.

use std::ops::Range;

use rune::{Color, El, Link, Span, TextStyle, text};

/// Runs of one line, with the byte ranges that are links.
#[derive(Default)]
pub struct Line {
    text: String,
    spans: Vec<Span>,
    links: Vec<(Range<usize>, String)>,
}

impl Line {
    pub fn new() -> Line {
        Line::default()
    }

    /// Append `s` in `color`.
    pub fn push(&mut self, s: &str, color: Color) -> &mut Self {
        self.run(s, color, None, None)
    }

    /// Append `s` as a link reporting `id` when clicked.
    pub fn push_link(&mut self, s: &str, color: Color, id: String) -> &mut Self {
        self.run(s, color, Some(id), None)
    }

    /// Append `s` with every option: an optional link id and an optional background (a
    /// highlighted symbol).
    pub fn run(
        &mut self,
        s: &str,
        color: Color,
        link: Option<String>,
        background: Option<Color>,
    ) -> &mut Self {
        if s.is_empty() {
            return self;
        }
        let start = self.text.len();
        self.text.push_str(s);
        let mut span = Span::new(start, self.text.len()).color(color);
        if let Some(bg) = background {
            span.bg = Some(bg);
            span.bg_pad = 1.0;
        }
        self.spans.push(span);
        if let Some(id) = link {
            self.links.push((start..self.text.len(), id));
        }
        self
    }

    pub fn text_len(&self) -> usize {
        self.text.len()
    }

    /// The element: one unwrapped line in `font`.
    pub fn build(self, font: TextStyle) -> El {
        let mut e = text(self.text).font(font).spans(self.spans);
        for (range, id) in self.links {
            e = e.link(Link::new(range, id));
        }
        e
    }
}
