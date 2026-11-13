//! Colour off (`NO_COLOR`), for every screen at once.
//!
//! The screens style text with colours as they draw. Rather than ask every
//! one of them to check, a frame drawn for a monochrome terminal has its
//! colours taken out afterwards: text keeps its bold, dim and reversed
//! attributes, and a cell that stood out by its background (a badge, say) is
//! drawn reversed instead, so it still stands out.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier};

/// Take the colours out of `area` of `buf`.
pub(crate) fn strip_colors(buf: &mut Buffer, area: Rect) {
    let area = area.intersection(buf.area);
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let cell = &mut buf[(x, y)];
            if cell.bg != Color::Reset {
                // Reversing a reversed cell would hide what stood out.
                cell.modifier.toggle(Modifier::REVERSED);
            }
            cell.fg = Color::Reset;
            cell.bg = Color::Reset;
            cell.underline_color = Color::Reset;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Style;

    #[test]
    fn colour_goes_and_emphasis_stays() {
        let area = Rect::new(0, 0, 6, 1);
        let mut buf = Buffer::empty(area);
        buf.set_string(0, 0, "ok", Style::default().fg(Color::Green));
        buf.set_string(
            2,
            0,
            "ROOT",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        );
        strip_colors(&mut buf, area);
        for x in 0..6 {
            let cell = &buf[(x, 0)];
            assert_eq!((cell.fg, cell.bg), (Color::Reset, Color::Reset), "{x}");
        }
        // The badge stands out by being reversed, and keeps its weight.
        let badge = &buf[(2, 0)].modifier;
        assert!(badge.contains(Modifier::REVERSED | Modifier::BOLD));
        assert!(!buf[(0, 0)].modifier.contains(Modifier::REVERSED));
    }
}
