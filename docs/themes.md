# Themes

Servonaut ships with two themes of its own, `servonaut` (dark) and
`servonaut-light`, and offers every built-in Textual theme besides (`nord`,
`gruvbox`, `dracula`, `tokyo-night`, …). You can add your own by dropping a
small TOML file into a folder. No code is involved: a theme file is read as
data and nothing in it is ever run.

Pick a theme in **Settings → Appearance** or with **Ctrl+P → Theme**. The
choice applies at once and is saved as `theme` in `config.json`.

## Where theme files go

```
~/.servonaut/themes/<name>.toml
```

(`%USERPROFILE%\.servonaut\themes\` on Windows.) The folder is created when you
choose **Open themes folder** in Settings → Appearance or save a first theme
from there.

Servonaut reads the folder when it starts and again when you choose **Reload
themes** (or press Ctrl+R in the Appearance panel). It reads at most 50 files
of at most 64 KiB each.

The quickest way to start is **New theme from current…** in Settings →
Appearance. It writes `<name>.toml` from the theme you are using, with every
colour spelled out, ready to edit. From a shell, `servonaut theme export nord`
does the same for any theme (see [Commands](#commands)).

## A complete example

```toml
# ~/.servonaut/themes/ocean.toml
name = "ocean"
dark = true

primary    = "#5EB1FF"
secondary  = "#7DD3FC"
accent     = "#7DD3FC"
warning    = "#F5C451"
error      = "#FF8A8A"
success    = "#4ADE80"
foreground = "#EAF2FB"
background = "#0B1622"
surface    = "#10233A"
panel      = "#173252"

[variables]
text-muted = "#9FB3C8"
border-blurred = "#173252"
input-selection-background = "#5EB1FF 35%"
block-cursor-text-style = "bold"

[ansi]
normal = ["#173252", "#FF8A8A", "#4ADE80", "#F5C451", "#5EB1FF", "#C4A7FF", "#7DD3FC", "#D6E2EE"]
bright = ["#4A6584", "#FFB4B4", "#86EFAC", "#FAD97A", "#9CCBFF", "#DAC8FF", "#A5E3FD", "#EAF2FB"]
```

Only `primary` is required. Anything you leave out is derived from the colours
you did set, the way Textual derives it.

## Top-level keys

| Key | Meaning |
|-----|---------|
| `name` | The theme's name. Optional; it defaults to the file name without `.toml`. 1–40 characters: lowercase letters, digits and `-`, starting with a letter or digit. It must not clash with a built-in theme or another theme file. |
| `dark` | `true` (the default) for a dark theme, `false` for a light one. It decides how shades are derived and which ANSI palette is derived when you give none. |
| `primary` | The main colour: focus outlines, borders and primary buttons. **Required.** |
| `secondary` | A second structural colour. |
| `accent` | Highlights: titles, active markers, selected items. |
| `warning`, `error`, `success` | Status colours, used for text and for destructive, risky and confirming buttons. |
| `foreground` | Normal text. |
| `background` | The screen background. |
| `surface` | Cards, panels and inputs sitting on the background. |
| `panel` | A step lighter than `surface`: headers, selected rows and table stripes. |
| `boost` | An overlay colour used to lift a widget off its background. Rarely needed. |

A colour is a hex value (`"#5EB1FF"` or `"#5BF"`), a CSS-style name
(`"steelblue"`), `rgb(94, 177, 255)` or `hsl(...)`. Colours with transparency
and the terminal's own ANSI colours are not accepted here.

## `[variables]`

Variables fine-tune individual parts of the interface. Each one is optional and
only the names below are accepted. A value is a colour, optionally followed by
an opacity, as in `"#5EB1FF 35%"`.

| Variable | What it colours |
|----------|-----------------|
| `text` | Normal text, where it differs from `foreground`. |
| `text-muted` | Secondary text such as hints and descriptions. |
| `foreground-muted` | Muted text drawn directly with the foreground. |
| `text-primary`, `text-secondary`, `text-accent`, `text-warning`, `text-error`, `text-success` | The status and highlight colours when they are used **as text**. Set these when a colour that works as a fill is too dark or too bright to read as text. |
| `border` | The border of a focused control. |
| `border-blurred` | The border of a control that is not focused. |
| `block-cursor-background`, `block-cursor-foreground` | The cursor row in tables and lists. |
| `block-cursor-text-style` | The text style of that row: any of `none`, `bold`, `italic`, `underline`, `reverse`, `strike`, separated by spaces. |
| `button-color-foreground` | The text on a filled button. |
| `footer-key-foreground` | The key names in the footer bar. |
| `input-selection-background` | Selected text in an input. |
| `primary-background` | A muted version of the primary colour used for selections. |

## `[ansi]`: colours in command output

Output that carries ANSI colours (the result of a command run on a server, log
lines, highlighted code) cannot use theme colours directly; it is drawn through
a 16-colour palette instead. Give `[ansi]` two lists of exactly eight colours:

```toml
[ansi]
normal = ["black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"]  # entries 0-7
bright = ["black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"]  # entries 8-15
```

Both lists are needed. If you leave `[ansi]` out, a palette is derived from your
theme: red, green, yellow and blue come from `error`, `success`, `warning` and
`primary`, and the lightest and darkest entries from `foreground` and the
background. That is usually fine; write your own when command output matters to
you or the derived colours do not read well.

## Readability

Settings → Appearance measures your theme as you move over it, using WCAG
contrast ratios, and marks each pair ✓ at 4.5:1 or above and ⚠ below:

- text on the background and on cards (`foreground` on `background` and `surface`)
- muted text on cards
- accent text on cards
- error text on cards

4.5:1 is the WCAG AA minimum for normal text. A few rules of thumb:

- Muted text is the usual casualty. If it falls short, set `text-muted` (or
  `foreground-muted`) a little closer to `foreground`.
- A bright status colour can work well as a fill and still be too faint as text
  on a light background. Set the matching `text-error`, `text-warning`, … to a
  darker shade.
- Light themes need `dark = false`; otherwise shades are derived the wrong way
  round.

A theme with warnings still loads. The warning is shown on its card so you know
what to fix.

## Commands

```
servonaut theme list
servonaut theme export <name> [--output PATH] [--force]
servonaut theme check <file>
```

- `list` shows every theme with its source (`built-in` or `user`) and its
  status: `ok`, a readability warning, or the error that stopped a file loading.
- `export` prints any theme as a theme file, or writes it to `--output`. It
  refuses to replace an existing file unless you add `--force`. The two themes
  that follow your terminal's own colours (`ansi-dark`, `ansi-light`) have no
  colour values to export.
- `check` validates one file and lists every problem with its line number. It
  exits with 0 when the file is fine and 1 when it is not, so it also works in
  scripts.

## When a file has a problem

A file that cannot be loaded never stops Servonaut from starting. It is skipped,
and Settings → Appearance shows a card with the file name, the line and what is
wrong, for example `Line 4: "accent" is not a colour ("#ff88")`. Fix the file and
choose **Reload themes**.

A file is refused when it:

- is not valid TOML, not valid UTF-8, unreadable or larger than 64 KiB;
- has an unknown key, in the top level, in `[variables]` or in `[ansi]`;
- has a value that is not a colour (or, for `dark`, not `true` or `false`);
- has no `primary`;
- has a name that is invalid or already taken.

If the theme you had selected is deleted or fails to load, Servonaut starts in
the default theme. The saved name is left alone, so the theme returns when its
file does.
