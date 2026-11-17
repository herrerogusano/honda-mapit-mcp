"""Managed login style of the public web stack: the Ride Log look, dark only.

Pure data, no I/O. ``scripts/build_public_web_stack.py`` puts it in the
``WebManagedLoginBranding`` resource. The invitation-only stack keeps the
Cognito default style (``_branding`` in ``scripts/build_multiuser_stack.py``).

What Cognito lets a style change (``AWS::Cognito::ManagedLoginBranding``,
CloudFormation template reference, and the Cognito developer guide pages
"The branding editor and customizing managed login" and "Managed login"):

* colours, border radius, spacing and display mode through the ``Settings``
  document; the keys below are the ones in the official example template;
* images through ``Assets`` (at most 40; ``Bytes`` base64, at most 1,000,000
  characters; page background, form logo and SVG favicon take SVG);
* no font setting and no text change: the page text is Cognito's own, and its
  language comes from the ``lang`` query parameter of the authorize request,
  not from the style.

The three images are original drawings for this project (plain shapes; the
wordmark letters are drawn as paths, not set in a font; the one line of text
under it, ``LOGIN_HINT``, is an SVG ``text`` in a system font), except the favicon,
which is the web's own ``public/favicon.svg``. No photo, font file or third
party mark, and nothing is fetched at run time.

Colours are the web's dark tokens (``src/styles.css``) converted from OKLCH to
sRGB hex, in the ``RRGGBBAA`` form Cognito uses.
"""

from __future__ import annotations

import base64
from typing import Any

# The web's tokens, sRGB hex.
BG = "090706"
SURFACE = "130e0e"
SURFACE_2 = "1d1716"
LINE = "312928"
LINE_SOFT = "211b1b"
CONTROL_LINE = "766c6b"
FG = "f2edec"
FG_2 = "beb5b4"
FG_3 = "a69c9b"
RED = "dd0011"
RED_PRESS = "f02026"
RED_HI = "ff534b"
ON_RED = "ffffff"
AMBER = "e8aa4e"
AMBER_BG = "2a1c07"
RADIUS = 2.0

# The web's mark (a red parallelogram, ``.brand-mark``) and "RIDE LOG" in
# square condensed capitals, "RIDE" in --red-hi like ``.brand b``.
_LETTERS = {
    "R": "M0 0H11L14 3V12L11 15L14 28H9L6.5 16H5V28H0ZM5 5V11H9V5Z",
    "I": "M0 0H5V28H0Z",
    "D": "M0 0H10L14 4V24L10 28H0ZM5 5V23H8L9 22V6L8 5Z",
    "E": "M0 0H13V5H5V11.5H11V16.5H5V23H13V28H0Z",
    "L": "M0 0H5V23H13V28H0Z",
    "O": "M3 0H11L14 3V25L11 28H3L0 25V3ZM5 5V23H9V5Z",
    "G": "M3 0H11L14 3V8H9V5H5V23H9V18H7V13H14V25L11 28H3L0 25V3Z",
}
_WIDTHS = {"I": 5, "E": 13, "L": 13}


def _word(text: str, x: float, colour: str) -> tuple[str, float]:
    parts = []
    for letter in text:
        parts.append(f'<path transform="translate({x:g} 0)" d="{_LETTERS[letter]}"/>')
        x += _WIDTHS.get(letter, 14) + 3
    return f'<g fill="#{colour}" fill-rule="evenodd">{"".join(parts)}</g>', x


# Shown under the wordmark: Cognito's own field labels cannot be changed, and the
# Settings document has no text of our own ("instructions" is reserved, not
# implemented), so the only place for it is this image.
LOGIN_HINT = "Usa tu correo y contraseña de MAPIT"
HINT_FONT_SIZE = 8.5
HINT_BASELINE = 44
_HINT_FONT = "system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"


def _logo_svg() -> str:
    ride, x = _word("RIDE", 30, RED_HI)
    log, x = _word("LOG", x + 4, FG)
    width = x - 3
    # Cognito refuses a logo wider than 4:1 (its validation error; the documentation does
    # not say). The 28-unit-high wordmark gets a 6-unit margin above, then the hint line
    # and a 6-unit margin below: 139 x 56, about 2.5:1, nothing stretched.
    # The text uses a system font (an image fetches nothing) and is fitted to the wordmark
    # width with textLength, so a wider or narrower font never overflows the image.
    # FG_2 on the form background: the page is dark only and light mode carries the
    # same form colours.
    hint = (f'<text x="{width / 2:g}" y="{HINT_BASELINE}" text-anchor="middle" textLength="{width:g}" '
            f'lengthAdjust="spacingAndGlyphs" font-family="{_HINT_FONT}" font-size="{HINT_FONT_SIZE:g}" '
            f'font-weight="500" fill="#{FG_2}">{LOGIN_HINT}</text>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -6 {width:g} 56" width="{2 * width:g}" height="112">'
            f'<title>Ride Log</title><polygon points="8,0 23,0 15,28 0,28" fill="#{RED}"/>{ride}{log}{hint}</svg>')


LOGO_SVG = _logo_svg()
# Dark page with the web's slanted red band, faint so the form keeps its contrast.
BACKGROUND_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMid slice">'
    f'<rect width="1600" height="1000" fill="#{BG}"/>'
    f'<polygon points="1180,0 1420,0 1180,1000 940,1000" fill="#{RED}" fill-opacity="0.10"/>'
    f'<polygon points="1450,0 1480,0 1240,1000 1210,1000" fill="#{RED_HI}" fill-opacity="0.18"/>'
    '</svg>'
)
FAVICON_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" '
               'fill="#0b0908"/><path d="M13 5h13l-7 22H6z" fill="#d6001c"/></svg>')


def _rgba(colour: str) -> str:
    return colour + "ff"


def _modes(dark: dict[str, Any]) -> dict[str, Any]:
    """The same values for both modes: the page is dark only, so light mode never differs."""
    return {"darkMode": dark, "lightMode": dark}


def _asset(category: str, svg: str) -> dict[str, str]:
    return {"Category": category, "ColorMode": "DYNAMIC", "Extension": "SVG",
            "Bytes": base64.b64encode(svg.encode("utf-8")).decode("ascii")}


def web_branding_assets() -> list[dict[str, str]]:
    return [_asset("FORM_LOGO", LOGO_SVG), _asset("PAGE_BACKGROUND", BACKGROUND_SVG),
            _asset("FAVICON_SVG", FAVICON_SVG)]


def web_branding_settings() -> dict[str, Any]:
    button_states = {
        "defaults": {"backgroundColor": _rgba(RED), "textColor": _rgba(ON_RED)},
        "hover": {"backgroundColor": _rgba(RED_PRESS), "textColor": _rgba(ON_RED)},
        "active": {"backgroundColor": _rgba(RED_PRESS), "textColor": _rgba(ON_RED)},
        "disabled": {"backgroundColor": _rgba(SURFACE_2), "borderColor": _rgba(LINE)},
    }
    quiet_states = {
        "defaults": {"backgroundColor": _rgba(SURFACE_2), "borderColor": _rgba(CONTROL_LINE), "textColor": _rgba(FG)},
        "hover": {"backgroundColor": _rgba(LINE_SOFT), "borderColor": _rgba(FG_3), "textColor": _rgba(FG)},
        "active": {"backgroundColor": _rgba(LINE_SOFT), "borderColor": _rgba(FG_3), "textColor": _rgba(FG)},
    }
    bar = {"background": {"color": _rgba(BG)}, "borderColor": _rgba(LINE)}
    return {
        "categories": {
            "form": {"displayGraphics": True, "location": {"horizontal": "CENTER", "vertical": "CENTER"}},
            "global": {"colorSchemeMode": "DARK", "pageHeader": {"enabled": False},
                       "pageFooter": {"enabled": False}, "spacingDensity": "REGULAR"},
        },
        "componentClasses": {
            "buttons": {"borderRadius": RADIUS},
            "divider": _modes({"borderColor": _rgba(LINE)}),
            "dropDown": {"borderRadius": RADIUS, **_modes({
                "defaults": {"itemBackgroundColor": _rgba(SURFACE_2)},
                "hover": {"itemBackgroundColor": _rgba(LINE_SOFT), "itemBorderColor": _rgba(CONTROL_LINE),
                          "itemTextColor": _rgba(FG)},
                "match": {"itemBackgroundColor": _rgba(SURFACE_2), "itemTextColor": _rgba(RED_HI)},
            })},
            "focusState": _modes({"borderColor": _rgba(RED_HI)}),
            "input": {"borderRadius": RADIUS, **_modes({
                "defaults": {"backgroundColor": _rgba(SURFACE_2), "borderColor": _rgba(CONTROL_LINE)},
                "placeholderColor": _rgba(FG_3),
            })},
            "inputDescription": _modes({"textColor": _rgba(FG_3)}),
            "inputLabel": _modes({"textColor": _rgba(FG_2)}),
            "link": _modes({"defaults": {"textColor": _rgba(RED_HI)}, "hover": {"textColor": _rgba(FG)}}),
            "optionControls": _modes({
                "defaults": {"backgroundColor": _rgba(SURFACE_2), "borderColor": _rgba(CONTROL_LINE)},
                "selected": {"backgroundColor": _rgba(RED), "foregroundColor": _rgba(ON_RED)},
            }),
            "statusIndicator": _modes({
                "error": {"backgroundColor": _rgba(SURFACE), "borderColor": _rgba(RED_HI),
                          "indicatorColor": _rgba(RED_HI)},
                "pending": {"indicatorColor": _rgba(FG_3)},
                "success": {"backgroundColor": _rgba(SURFACE), "borderColor": _rgba(FG_2),
                            "indicatorColor": _rgba(FG_2)},
                "warning": {"backgroundColor": _rgba(AMBER_BG), "borderColor": _rgba(AMBER),
                            "indicatorColor": _rgba(AMBER)},
            }),
        },
        "components": {
            "alert": {"borderRadius": RADIUS, **_modes({
                "error": {"backgroundColor": _rgba(SURFACE), "borderColor": _rgba(RED_HI)}})},
            "favicon": {"enabledTypes": ["SVG"]},
            "form": {"backgroundImage": {"enabled": False}, "borderRadius": RADIUS,
                     **_modes({"backgroundColor": _rgba(SURFACE), "borderColor": _rgba(LINE)}),
                     "logo": {"enabled": True, "formInclusion": "IN", "location": "CENTER", "position": "TOP"}},
            "pageBackground": {"image": {"enabled": True}, **_modes({"color": _rgba(BG)})},
            "pageFooter": {"backgroundImage": {"enabled": False}, **_modes(bar),
                           "logo": {"enabled": False, "location": "START"}},
            "pageHeader": {"backgroundImage": {"enabled": False}, **_modes(bar),
                           "logo": {"enabled": False, "location": "START"}},
            "pageText": _modes({"headingColor": _rgba(FG), "bodyColor": _rgba(FG_2),
                                "descriptionColor": _rgba(FG_3)}),
            "primaryButton": _modes(button_states),
            "secondaryButton": _modes(quiet_states),
        },
    }
