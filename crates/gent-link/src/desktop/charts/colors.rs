//! Resolve native sRGB colors against the surface underneath the transparent SVG.
use super::Palette;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Color(pub [u8; 3]);

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [r, g, b] = self.0;
        write!(f, "#{r:02x}{g:02x}{b:02x}")
    }
}

impl Color {
    fn luminance(self) -> f64 {
        let [r, g, b] = self.0.map(|byte| {
            let c = f64::from(byte) / 255.0;
            if c <= 0.04045 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        });
        0.2126 * r + 0.7152 * g + 0.0722 * b
    }

    pub(super) fn contrast(self, other: Self) -> f64 {
        let (a, b) = (self.luminance(), other.luminance());
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    // Find the first blend that meets the requested contrast after 8-bit rounding.
    // The caller chooses an endpoint known to meet the ratio.
    fn toward(self, end: Self, background: Self, minimum: f64) -> Self {
        let mix = |weight: u16| {
            Self(std::array::from_fn(|i| {
                ((u16::from(self.0[i]) * (255 - weight) + u16::from(end.0[i]) * weight + 127) / 255)
                    as u8
            }))
        };
        let (mut lo, mut hi) = (0, 255);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if mix(mid).contrast(background) < minimum {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        mix(hi)
    }

    fn legible_on(self, surface: Self, minimum: f64) -> Self {
        if self.contrast(surface) >= minimum {
            return self;
        }
        let black = Self([0; 3]);
        let white = Self([255; 3]);
        let dark_contrast = black.contrast(surface);
        let light_contrast = white.contrast(surface);
        // On a mid-tone surface both endpoints may work. Keep light swatches
        // light and dark swatches dark, preserving luminance differences too.
        let prefer_light = if self == surface {
            light_contrast > dark_contrast
        } else {
            self.luminance() > surface.luminance()
        };
        let end = if dark_contrast < minimum || (prefer_light && light_contrast >= minimum) {
            white
        } else {
            black
        };
        self.toward(end, surface, minimum)
    }
}

#[derive(Clone, Copy)]
pub(super) struct Colors {
    pub surface: Color,
    pub text: Color,
    pub secondary: Color,
    pub grid: Color,
    pub accent: Color,
}

impl Colors {
    pub fn new(palette: &Palette) -> Self {
        let surface = Color(palette.surface);
        let text = Color(palette.text).legible_on(surface, 4.5);
        let secondary = Color(palette.secondary).legible_on(surface, 4.5);
        let accent = Color(palette.accent).legible_on(surface, 3.0);
        // Keep the grid quieter than ticks and data. Allow a stronger grid for
        // near-black/white high-contrast appearances.
        let grid_ratio = if text.contrast(surface) >= 16.0 {
            2.0
        } else {
            1.6
        };
        let grid = surface.toward(text, surface, grid_ratio);
        Self {
            surface,
            text,
            secondary,
            grid,
            accent,
        }
    }

    pub fn categories(self) -> [Color; 16] {
        // Each swatch works against the native surface, which also separates
        // adjacent slices. Indices and legend order provide a non-color key.
        let mut swatches = [
            [0, 114, 178],
            [213, 94, 0],
            [0, 158, 115],
            [204, 121, 167],
            [230, 159, 0],
            [86, 180, 233],
            [117, 84, 159],
            [135, 134, 48],
            [50, 105, 110],
            [179, 74, 100],
            [126, 96, 69],
            [83, 111, 176],
            [133, 101, 148],
            [87, 139, 72],
            [183, 99, 64],
            [91, 100, 115],
        ]
        .map(|rgb| Color(rgb).legible_on(self.surface, 3.0));

        // Lead with the native accent. Replace its nearest existing swatch so
        // choosing a system orange, for example, cannot duplicate that slice.
        let nearest = swatches
            .iter()
            .enumerate()
            .min_by_key(|(_, swatch)| {
                swatch
                    .0
                    .into_iter()
                    .zip(self.accent.0)
                    .map(|(a, b)| u32::from(a.abs_diff(b)).pow(2))
                    .sum::<u32>()
            })
            .unwrap()
            .0;
        swatches.swap(0, nearest);
        swatches[0] = self.accent;
        swatches
    }

    pub fn slice_text(self, fill: Color) -> Color {
        if self.text.contrast(fill) >= 4.5 {
            self.text
        } else {
            self.surface.legible_on(fill, 4.5)
        }
    }
}
