//! The graph view: a function's basic blocks as boxes of disassembly joined by coloured edges.
//!
//! Layout runs once per function (and when names change widths); panning and zooming move
//! only a camera, so they never rebuild the view. Wheel pans, Ctrl+wheel and pinch zoom about
//! the pointer, and dragging the background pans.

use std::sync::Arc;

use rune::{
    Drag, El, Live, MagnifyEvent, Phase, Shape, Tx, WheelEvent, canvas, col, el, row, text,
};

use crate::backend::{
    FlowError, FlowGraph,
    graph::{self, EdgeKind, Layout, Size, Spacing},
};

use super::{App, code::Line, listing::insn_line, theme::*};

const PAD_X: f32 = 12.0;
const PAD_Y: f32 = 8.0;
const MIN_ZOOM: f32 = 0.08;
const MAX_ZOOM: f32 = 4.0;

/// A laid-out function.
pub struct Model {
    pub flow: FlowGraph,
    pub layout: Layout,
    /// Which addresses the nodes show, widest first column: hex digits to pad addresses to.
    addr_digits: usize,
}

pub struct State {
    /// The function `model` shows.
    pub entry: Option<u64>,
    pub model: Option<Arc<Model>>,
    pub error: Option<String>,
    /// What the model was built against, so a rename that changes text widths relays it out.
    built_for: (u64, u64),
    pan: [f32; 2],
    zoom: f32,
    live_pan: Live<[f32; 2]>,
    live_zoom: Live<f32>,
    pan_at_press: [f32; 2],
    /// Frame the graph on the next view build.
    fit_pending: bool,
    /// The viewport's size, as last laid out.
    viewport: [f32; 2],
}

impl Default for State {
    fn default() -> Self {
        State {
            entry: None,
            model: None,
            error: None,
            built_for: (u64::MAX, 0),
            pan: [0.0; 2],
            zoom: 1.0,
            live_pan: Live::new([0.0, 0.0]),
            live_zoom: Live::new(1.0),
            pan_at_press: [0.0; 2],
            fit_pending: false,
            viewport: [1000.0, 700.0],
        }
    }
}

impl State {
    fn set_camera(&mut self, pan: [f32; 2], zoom: f32) {
        (self.pan, self.zoom) = (pan, zoom.clamp(MIN_ZOOM, MAX_ZOOM));
        self.live_pan.set(self.pan);
        self.live_zoom.set(self.zoom);
    }

    /// The world point under viewport point `q`. The camera scales about the world's centre.
    fn world(&self, q: [f32; 2], size: [f32; 2]) -> [f32; 2] {
        let c = [size[0] / 2.0, size[1] / 2.0];
        [
            c[0] + (q[0] - c[0] - self.pan[0]) / self.zoom,
            c[1] + (q[1] - c[1] - self.pan[1]) / self.zoom,
        ]
    }

    /// Zoom to `zoom`, keeping the world point under `q` fixed.
    fn zoom_about(&mut self, q: [f32; 2], zoom: f32, size: [f32; 2]) {
        let zoom = zoom.clamp(MIN_ZOOM, MAX_ZOOM);
        let p = self.world(q, size);
        let c = [size[0] / 2.0, size[1] / 2.0];
        self.set_camera(
            [
                q[0] - c[0] - (p[0] - c[0]) * zoom,
                q[1] - c[1] - (p[1] - c[1]) * zoom,
            ],
            zoom,
        );
    }

    /// Show the top of the graph, centred, at a readable zoom.
    fn fit(&mut self, size: [f32; 2]) {
        let zoom = ((self.viewport[0] - 48.0) / size[0]).clamp(0.4, 1.0);
        let c = [size[0] / 2.0, size[1] / 2.0];
        self.set_camera(
            [self.viewport[0] / 2.0 - c[0], 24.0 - c[1] * (1.0 - zoom)],
            zoom,
        );
        self.fit_pending = false;
    }

    /// Centre the camera on world point `p`.
    fn centre_on(&mut self, p: [f32; 2], size: [f32; 2]) {
        let c = [size[0] / 2.0, size[1] / 2.0];
        let pan = [
            self.viewport[0] / 2.0 - c[0] - (p[0] - c[0]) * self.zoom,
            self.viewport[1] / 2.5 - c[1] - (p[1] - c[1]) * self.zoom,
        ];
        self.set_camera(pan, self.zoom);
    }
}

/// Rebuild the model if the function or the names changed. True if it did.
pub fn refresh(app: &mut App) -> bool {
    if app.main_tab != super::MainTab::Graph {
        return false;
    }
    let Some(program) = app.program.clone() else {
        return false;
    };
    let entry = app.function_of(app.cur);
    let key = (entry.unwrap_or(0), app.display_version());
    if app.graph.entry == entry && app.graph.built_for == key {
        return false;
    }
    let same_function = app.graph.entry == entry;
    app.graph.entry = entry;
    app.graph.built_for = key;
    app.graph.model = None;
    app.graph.error = None;
    let Some(entry) = entry else {
        app.graph.error = Some("No function at this address".into());
        return true;
    };
    match FlowGraph::build(&program, entry) {
        Ok(flow) => {
            let addr_digits = flow
                .nodes
                .iter()
                .map(|n| format!("{:x}", n.end).len())
                .max()
                .unwrap_or(6);
            let sizes: Vec<Size> = flow
                .nodes
                .iter()
                .map(|n| {
                    let chars = n
                        .insns
                        .iter()
                        .map(|i| insn_line(app, i).text_len())
                        .max()
                        .unwrap_or(1)
                        + addr_digits
                        + 2;
                    Size {
                        w: chars as f32 * CHAR_W + 2.0 * PAD_X,
                        h: n.insns.len().max(1) as f32 * ROW_H + 2.0 * PAD_Y,
                    }
                })
                .collect();
            let layout = graph::layout(
                &sizes,
                &flow.edges,
                flow.entry_index,
                Spacing {
                    node: 40.0,
                    layer: 64.0,
                    margin: 40.0,
                },
            );
            app.graph.model = Some(Arc::new(Model {
                flow,
                layout,
                addr_digits,
            }));
            if !same_function {
                app.graph.fit_pending = true;
            }
        }
        Err(FlowError::TooLarge(n)) => {
            app.graph.error = Some(format!(
                "This function has {n} blocks; the graph view shows up to {}. Use the listing or pseudocode.",
                crate::backend::flow::MAX_NODES
            ))
        }
        Err(FlowError::NotAFunction) => {
            app.graph.error = Some("No control-flow graph for this address".into())
        }
    }
    true
}

/// Centre the graph on the node containing the current address.
pub fn reveal(app: &mut App) {
    let Some(model) = app.graph.model.clone() else {
        return;
    };
    let size = [model.layout.width, model.layout.height];
    if app.graph.fit_pending {
        app.graph.fit(size);
        return;
    }
    if let Some(i) = node_containing(&model, app.cur) {
        let r = model.layout.nodes[i];
        app.graph
            .centre_on([r.x + r.w / 2.0, r.y + r.h / 2.0], size);
    }
}

fn node_containing(model: &Model, addr: u64) -> Option<usize> {
    model
        .flow
        .nodes
        .iter()
        .position(|n| addr >= n.addr && addr < n.end)
}

pub fn view(app: &App) -> El {
    let p = colors();
    let message = |text_: String| {
        col()
            .w_full()
            .h_full()
            .center()
            .child(text(text_).font(UI).color(p.muted))
    };
    if let Some(e) = &app.graph.error {
        return message(e.clone());
    }
    let Some(model) = &app.graph.model else {
        return message("Building the graph…".into());
    };
    let (w, h) = (model.layout.width, model.layout.height);
    let cur_node = node_containing(model, app.cur);

    let mut world = el()
        .key("graph-world")
        .size(w, h)
        .pin(Some(0.0), Some(0.0), None, None)
        .live_offset(&app.graph.live_pan)
        .live_scale(&app.graph.live_zoom);
    world = world.child(canvas(edges(model)).size(w, h));
    for (i, node) in model.flow.nodes.iter().enumerate() {
        let r = model.layout.nodes[i];
        let mut lines = col().w_full().px(PAD_X).py(PAD_Y);
        for insn in &node.insns {
            let addr = insn.addr;
            let mut l = Line::new();
            l.push(
                &format!("{:0width$x}  ", insn.addr, width = model.addr_digits),
                p.addr,
            );
            let body = insn_line(app, insn);
            let line = row()
                .h(ROW_H)
                .items_center()
                .on_press(move |s: &mut App| s.sync_cursor(addr))
                .child(l.build(CODE));
            lines = lines.child(line.child(body.build(CODE).on_link(
                |s: &mut App, id: &str, tx: &mut Tx| {
                    if let Ok(a) = u64::from_str_radix(id, 16) {
                        s.goto(a, tx);
                    }
                },
            )));
        }
        let border = if Some(i) == cur_node {
            p.accent
        } else if i == model.flow.entry_index {
            p.good
        } else if node.exits_function {
            p.bad.alpha(0.55)
        } else {
            p.node_border
        };
        world = world.child(
            el().key(format!("n{i}"))
                .pin(Some(r.x), Some(r.y), None, None)
                .size(r.w, r.h)
                .radius(8.0)
                .fill(p.node_bg)
                .border(1.0, border)
                .child(lines),
        );
    }

    el().key("graph-vp")
        .w_full()
        .h_full()
        .clip_soft(0.0)
        .fill(p.window)
        .on_layout(|s: &mut App, r: [f32; 4]| s.graph.viewport = [r[2], r[3]])
        .on_wheel(move |s: &mut App, e: WheelEvent, tx: &mut Tx| {
            let Some(model) = s.graph.model.clone() else {
                return false;
            };
            let size = [model.layout.width, model.layout.height];
            if e.mods.cmd {
                // About the pointer: a wheel tick is about 10% of zoom.
                let zoom = s.graph.zoom * (1.0 - e.dy / 400.0);
                s.graph.zoom_about([e.x, e.y], zoom, size);
            } else {
                s.graph
                    .set_camera([s.graph.pan[0] - e.dx, s.graph.pan[1] - e.dy], s.graph.zoom);
            }
            tx.live_only();
            true
        })
        .on_magnify(move |s: &mut App, e: MagnifyEvent, tx: &mut Tx| {
            let Some(model) = s.graph.model.clone() else {
                return false;
            };
            let size = [model.layout.width, model.layout.height];
            s.graph
                .zoom_about([e.x, e.y], s.graph.zoom * (1.0 + e.delta), size);
            tx.live_only();
            true
        })
        .on_drag(|s: &mut App, d: &mut Drag, tx: &mut Tx| {
            if d.phase == Phase::Down {
                s.graph.pan_at_press = s.graph.pan;
            }
            let pan = [
                s.graph.pan_at_press[0] + d.dx,
                s.graph.pan_at_press[1] + d.dy,
            ];
            s.graph.set_camera(pan, s.graph.zoom);
            tx.live_only();
        })
        .child(world)
}

/// All edges and their arrowheads as one shape.
fn edges(model: &Model) -> Shape {
    let p = colors();
    let mut shape = Shape::new();
    for route in &model.layout.routes {
        let color = match route.kind {
            EdgeKind::Taken => p.edge_taken,
            EdgeKind::NotTaken => p.edge_not_taken,
            EdgeKind::Unconditional => p.edge_flow,
            EdgeKind::Table => p.edge_table,
        };
        let pts: Vec<[f32; 2]> = route.points.iter().map(|&(x, y)| [x, y]).collect();
        if pts.len() < 2 {
            continue;
        }
        shape = shape.stroke(pts.clone(), 1.5, color);
        // Arrowhead on the last segment.
        let (a, b) = (pts[pts.len() - 2], pts[pts.len() - 1]);
        let (dx, dy) = (b[0] - a[0], b[1] - a[1]);
        let len = dx.hypot(dy).max(0.001);
        let (ux, uy) = (dx / len, dy / len);
        let size = 7.0;
        let base = [b[0] - ux * size, b[1] - uy * size];
        let (nx, ny) = (-uy * size * 0.5, ux * size * 0.5);
        shape = shape.fill(
            vec![
                b,
                [base[0] + nx, base[1] + ny],
                [base[0] - nx, base[1] - ny],
            ],
            color,
        );
    }
    shape.view_box(model.layout.width, model.layout.height)
}
