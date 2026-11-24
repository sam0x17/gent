//! Numeric axes, including narrow intervals far from zero.
pub(super) fn format_number(n: f64) -> String {
    if n == 0.0 {
        return "0".into();
    }
    let (mantissa, exponent) = {
        let scientific = format!("{n:.3e}");
        let (m, e) = scientific.split_once('e').unwrap();
        (
            m.trim_end_matches('0').trim_end_matches('.').to_owned(),
            e.parse::<i32>().unwrap(),
        )
    };
    if !(-2..=4).contains(&exponent) {
        return format!("{mantissa}e{exponent}");
    }
    let places = (3 - exponent).max(0) as usize;
    let rounded = format!("{n:.places$}");
    if places > 0 {
        rounded
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_owned()
    } else {
        rounded
    }
}

// Keep source precision in accessible descriptions and offset annotations.
pub(super) fn exact_number(n: f64) -> String {
    let plain = n.to_string();
    let scientific = format!("{n:e}");
    if plain.len() <= scientific.len() {
        plain
    } else {
        scientific
    }
}

#[derive(Clone, Copy)]
pub(super) struct Axis {
    pub low: f64,
    pub high: f64,
}

impl Axis {
    pub fn new(low: f64, high: f64) -> Self {
        if low != high {
            return Self { low, high };
        }
        let pad = if low == 0.0 {
            1.0
        } else {
            (low.abs() / 10.0).max(f64::from_bits(1))
        };
        Self {
            low: (low - pad).max(-f64::MAX),
            high: (high + pad).min(f64::MAX),
        }
    }

    pub fn fraction(self, n: f64) -> f64 {
        let span = self.high - self.low;
        if span.is_finite() {
            (n - self.low) / span
        } else {
            (n / 2.0 - self.low / 2.0) / (self.high / 2.0 - self.low / 2.0)
        }
    }

    pub fn origin(self) -> Option<f64> {
        (self.high - self.low < self.low.abs() * 0.01).then_some(self.low)
    }

    pub fn origin_label(self) -> Option<String> {
        self.origin().map(|n| format!("Origin {}", exact_number(n)))
    }

    pub fn tick_label(self, n: f64) -> String {
        format_number(n - self.origin().unwrap_or(0.0))
    }

    pub fn ticks(self, intervals: usize) -> Vec<f64> {
        let origin = self.origin().unwrap_or(0.0);
        let span = self.high - self.low;
        let target = if span.is_finite() {
            span / intervals as f64
        } else {
            self.high / intervals as f64 - self.low / intervals as f64
        };
        let decade = 10.0_f64.powi(target.log10().floor().max(-308.0) as i32);
        let step = [1.0, 2.0, 5.0, 10.0]
            .into_iter()
            .map(|n| n * decade)
            .find(|&n| n >= target * (1.0 - 1e-12));
        let mut ticks = Vec::new();
        if let Some(step) = step.filter(|s| s.is_finite() && *s > 0.0) {
            let first = ((self.low - origin) / step).ceil();
            for i in 0..=intervals + 1 {
                let tick = origin + (first + i as f64) * step;
                if tick >= self.low && tick <= self.high && ticks.last() != Some(&tick) {
                    ticks.push(tick);
                }
            }
        }
        if ticks.len() < 2 {
            vec![self.low, self.high]
        } else {
            ticks
        }
    }
}
