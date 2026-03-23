# CBM-SAE

**CBM-SAE** is a browser-based, offline authoring environment for building bounded CBM modules and lowering them toward **J16-L0**.

It is designed as a visual process-construction tool rather than a conventional text-first programming environment. You can define symbols, states, banks, transitions, and JSON IR, then certify, simulate, and push the current module into the embedded J16-L0 lowerer.

## What it does

- Visual graph editor for CBM state machines
- Module tree for symbols, states, and banks
- Inspector panel for structure and state details
- Built-in JSON IR editor
- Static certifier
- Simulator
- Embedded **CBM → J16-L0** lowering workbench
- Import/export for CBM module JSON
- Runs fully offline as a single HTML file

## Main workflow

1. Open the HTML file in a browser
2. Create or load a CBM module
3. Add symbols, states, and banks
4. Edit the process visually and/or through JSON
5. Run the certifier
6. Run the simulator
7. Open the **J16-L0** tab to sync the current symbol into the embedded lowerer
8. Lower and inspect the resulting J16-side output

## Interface overview

### Top bar

- **Graph** — main visual editor
- **Schema** — schema view
- **Spec** — embedded spec/reference view
- **Demo** — load demo content
- **Import / Export** — load or save CBM JSON
- **Certify** — run static checks
- **Simulate** — run the built-in simulator
- **J16-L0** — open the lowering workbench

### Left panel

The left panel contains the **Module Tree** and creation controls:

- `+ Symbol`
- `+ State`
- `+ Bank`
- `− Remove Selected`

### Center panel

The center panel is the graph canvas for editing state-machine structure and transitions.

### Right panel

The right side exposes the working panels for:

- Inspector
- Certifier
- Simulator
- JSON editor
- J16-L0 integration

## J16-L0 integration

CBM-SAE includes an embedded J16-L0 lowerer workbench so the current module can be synced directly into the J16 flow from inside the authoring tool.

The J16 section supports:

- current symbol context
- bank initialization JSON
- event queue JSON
- embedded lowering view
- lower/run status feedback

This makes CBM-SAE part of the J16 toolchain, not just a separate editor.