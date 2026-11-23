# Native UI refinement

Design review guided by [Unslop](https://github.com/heydamir/unslop), created by Damir Sokolovsky, licensed CC BY 4.0. This applies its design process to a native SwiftUI/AppKit application; no web UI or external runtime was introduced.

## Audit and direction

The original screen put controls in one vertical stack, lacked an identifiable drop target and file queue, and combined all output in one preview. The large title competed with the configuration text; blank preview space did not explain the next action.

- Product: local configuration sanitization for network engineers.
- Character: precise, quiet, inspectable.
- World: configuration review at a network operations workstation.
- Moments: highlighted original/replacement lines, with actual replacement counts.
- Signature: original filename → filename-clean.extension.

## Applied passes

Spacing: 4-point rhythm, 16-point sidebar padding, 24-point workspace padding, consistent file rows.
Color: adaptive macOS surfaces, system accent for selection and export, semantic diff highlights.
Icons: SF Symbols for native consistency, no decorative imagery.
Copy: task-specific labels, local-processing status, concise output naming explanation.
Type: system UI font with medium headings; monospaced configurations and counts.
Layout: 256-point file sidebar, fluid comparison workspace, grouped options and export footer.
Details: individual removal, unreadable-file states, keyboard shortcuts, collision-safe names, selectable configuration text.
Visuals: actual configuration content carries the visual focus.
Motion: native control feedback and drag-target highlighting; no decorative animations.
