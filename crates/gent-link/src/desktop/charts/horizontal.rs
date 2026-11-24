//! Shared numeric axis for sample histories, scatter plots and signed bars.
use super::{Chart, scale::Axis, text_width};

pub(super) const EDGE: f64 = 6.0;
pub(super) const GAP: f64 = 5.0;

pub(super) struct HorizontalAxis {
    pub left: f64,
    pub right: f64,
    ticks: Vec<(f64, String)>,
    staggered: bool,
}

impl HorizontalAxis {
    pub fn new(axis: Axis, samples: Option<usize>, width: usize, left_inset: f64) -> Self {
        // More room permits more ticks, but a dashboard axis needs only a few.
        for intervals in (2..=(width / 100).clamp(2, 8)).rev() {
            let values = match samples {
                Some(n) => {
                    let mut values: Vec<_> = (0..=intervals)
                        .map(|i| (1 + (n - 1) * i / intervals) as f64)
                        .collect();
                    values.dedup();
                    values
                }
                None => axis.ticks(intervals),
            };
            let layout = Self::measure(axis, &values, width, left_inset);
            if !layout.staggered {
                return layout;
            }
        }
        // Maximize separation of long scientific tick labels. On a very
        // narrow card the second endpoint can use its own text baseline.
        Self::measure(axis, &[axis.low, axis.high], width, left_inset)
    }

    fn measure(axis: Axis, values: &[f64], width: usize, left_inset: f64) -> Self {
        let mut ticks: Vec<_> = values
            .iter()
            .map(|&n| (axis.fraction(n), axis.tick_label(n)))
            .collect();
        let left = EDGE + left_inset.max(text_width(&ticks[0].1) as f64 / 2.0);
        let right = width as f64 - EDGE - text_width(&ticks.last().unwrap().1) as f64 / 2.0;
        for (x, _) in &mut ticks {
            *x = left + *x * (right - left);
        }
        let staggered = ticks.windows(2).any(|pair| {
            let ((a, first), (b, second)) = (&pair[0], &pair[1]);
            b - a < (text_width(first) + text_width(second)) as f64 / 2.0 + GAP
        });
        Self {
            left,
            right,
            ticks,
            staggered,
        }
    }

    pub fn draw(&self, chart: &mut Chart, baseline: usize) -> usize {
        let y = baseline as f64;
        let color = chart.colors.secondary;
        chart.line(self.left, y, self.right, y, color);
        let mut bottom = baseline + 14;
        for (i, (x, label)) in self.ticks.iter().enumerate() {
            if self.staggered && i == 1 {
                bottom += 13;
            }
            chart.line(*x, y, *x, y + 3.0, color);
            chart.secondary_text(*x, bottom as f64, "middle", label);
        }
        bottom
    }
}
