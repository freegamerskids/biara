//! Layered layout for control-flow graphs.
//!
//! The classic Sugiyama pipeline, kept small and deterministic:
//!
//! 1. **Cycles.** A depth-first search from the entry marks back edges; they are reversed for
//!    layering only, so loops lay out downwards and the back edge is drawn going up.
//! 2. **Layers.** Longest path from the sources, so every forward edge points down.
//! 3. **Dummies.** An edge spanning several layers gets one dummy node per layer it crosses;
//!    its route is the dummies' positions.
//! 4. **Order.** Barycentre sweeps, down then up, a few rounds, keeping the best crossing count.
//! 5. **Coordinates.** Each layer is placed to be as close as possible (least squares) to the
//!    mean of its neighbours' centres while keeping its minimum spacing, solved exactly with
//!    pool-adjacent-violators, alternating down and up.
//! 6. **Routes.** Orthogonal polylines through the gaps between layers.
//!
//! Sizes are inputs, so the caller decides what a node contains.

use std::collections::{HashMap, HashSet};

/// What an edge means; the view colours by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Branch taken when the condition holds.
    Taken,
    /// Fallthrough of a conditional branch.
    NotTaken,
    Unconditional,
    /// One case of a computed jump.
    Table,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Size {
    pub w: f32,
    pub h: f32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl Rect {
    pub fn right(&self) -> f32 {
        self.x + self.w
    }
    pub fn bottom(&self) -> f32 {
        self.y + self.h
    }
}

#[derive(Clone, Debug)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub from: usize,
    pub to: usize,
    pub kind: EdgeKind,
    /// Starts at the source node's boundary and ends at the target's; the last segment
    /// carries the arrowhead. A back edge's route runs upwards.
    pub points: Vec<(f32, f32)>,
    /// The edge goes against the layering (a loop's back edge).
    pub back: bool,
}

#[derive(Clone, Debug)]
pub struct Layout {
    pub nodes: Vec<Rect>,
    pub routes: Vec<Route>,
    pub width: f32,
    pub height: f32,
}

/// Spacing between nodes.
#[derive(Clone, Copy, Debug)]
pub struct Spacing {
    /// Between neighbours in one layer.
    pub node: f32,
    /// Between layers (room for the edge routes).
    pub layer: f32,
    /// Margin around the whole drawing.
    pub margin: f32,
}

impl Default for Spacing {
    fn default() -> Self {
        Spacing {
            node: 36.0,
            layer: 56.0,
            margin: 24.0,
        }
    }
}

/// Lay out `sizes.len()` nodes joined by `edges`, with `entry` at the top.
pub fn layout(sizes: &[Size], edges: &[Edge], entry: usize, spacing: Spacing) -> Layout {
    let n = sizes.len();
    if n == 0 {
        return Layout {
            nodes: vec![],
            routes: vec![],
            width: 0.0,
            height: 0.0,
        };
    }
    // Real edges without self loops (drawn as a small loop by the caller if wanted) or
    // duplicates of the same pair and kind.
    let mut seen = HashSet::new();
    let real: Vec<&Edge> = edges
        .iter()
        .filter(|e| e.from != e.to && e.from < n && e.to < n && seen.insert((e.from, e.to, e.kind)))
        .collect();

    let back = back_edges(n, &real, entry);
    // Layering edges: back edges reversed.
    let dag: Vec<(usize, usize)> = real
        .iter()
        .enumerate()
        .map(|(i, e)| {
            if back.contains(&i) {
                (e.to, e.from)
            } else {
                (e.from, e.to)
            }
        })
        .collect();
    let layer_of = layers(n, &dag, entry);

    // Build the layered graph with dummy nodes. Node ids >= n are dummies.
    let mut layer: Vec<usize> = layer_of.clone();
    let mut size: Vec<Size> = sizes.to_vec();
    let mut chains: Vec<Vec<usize>> = Vec::with_capacity(dag.len()); // per real edge: nodes from top to bottom
    for &(a, b) in &dag {
        let mut chain = vec![a];
        for l in layer_of[a] + 1..layer_of[b] {
            layer.push(l);
            size.push(Size { w: 0.0, h: 0.0 });
            chain.push(layer.len() - 1);
        }
        chain.push(b);
        chains.push(chain);
    }
    let total = layer.len();
    let depth = layer.iter().copied().max().unwrap_or(0) + 1;
    let mut up: Vec<Vec<usize>> = vec![vec![]; total];
    let mut down: Vec<Vec<usize>> = vec![vec![]; total];
    for chain in &chains {
        for w in chain.windows(2) {
            down[w[0]].push(w[1]);
            up[w[1]].push(w[0]);
        }
    }

    let mut order = initial_order(depth, &layer, &down, entry, n);
    order = reduce_crossings(order, &up, &down);

    // y: layers stacked by their tallest node.
    let mut layer_h = vec![0f32; depth];
    for (v, &l) in layer.iter().enumerate() {
        layer_h[l] = layer_h[l].max(size[v].h);
    }
    let mut layer_y = vec![spacing.margin; depth];
    for l in 1..depth {
        layer_y[l] = layer_y[l - 1] + layer_h[l - 1] + spacing.layer;
    }

    let x = place(&order, &size, &up, &down, spacing.node);
    let min_x = order
        .iter()
        .flatten()
        .map(|&v| x[v] - size[v].w / 2.0)
        .fold(f32::INFINITY, f32::min);
    let shift = spacing.margin - min_x;
    let centre = |v: usize| x[v] + shift;

    let nodes: Vec<Rect> = (0..n)
        .map(|v| Rect {
            x: centre(v) - size[v].w / 2.0,
            y: layer_y[layer[v]],
            w: size[v].w,
            h: size[v].h,
        })
        .collect();

    // Routes. Ports spread along a node's edge, ordered by where the other end is.
    let mut out_ports: HashMap<usize, Vec<(usize, f32)>> = HashMap::new(); // node -> (chain index, other x)
    let mut in_ports: HashMap<usize, Vec<(usize, f32)>> = HashMap::new();
    for (ci, chain) in chains.iter().enumerate() {
        let (a, b) = (chain[0], chain[chain.len() - 1]);
        out_ports.entry(a).or_default().push((ci, centre(chain[1])));
        in_ports
            .entry(b)
            .or_default()
            .push((ci, centre(chain[chain.len() - 2])));
    }
    let port_x = |ports: &HashMap<usize, Vec<(usize, f32)>>, node: usize, ci: usize| -> f32 {
        let mut list = ports[&node].clone();
        list.sort_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)));
        let k = list.iter().position(|p| p.0 == ci).unwrap_or(0);
        let r = nodes[node];
        r.x + r.w * (k as f32 + 1.0) / (list.len() as f32 + 1.0)
    };

    let mut routes = Vec::with_capacity(real.len());
    // Horizontal runs in one gap are staggered so parallel edges do not overlap.
    let mut gap_use: HashMap<usize, usize> = HashMap::new();
    for (i, e) in real.iter().enumerate() {
        let chain = &chains[i];
        let is_back = back.contains(&i);
        let (top, bottom) = (chain[0], chain[chain.len() - 1]);
        let sx = port_x(&out_ports, top, i);
        let ex = port_x(&in_ports, bottom, i);
        let mut pts = vec![(sx, nodes[top].bottom())];
        let mut cur_x = sx;
        let mut cur_y = nodes[top].bottom();
        for (step, &mid) in chain[1..].iter().enumerate() {
            let from_layer = layer[chain[step]];
            let gap_top = layer_y[from_layer] + layer_h[from_layer];
            let slot = gap_use.entry(from_layer).or_default();
            let stagger = (*slot % 6) as f32 * 4.0 + 6.0;
            *slot += 1;
            let ymid = (gap_top + stagger).min(layer_y[from_layer + 1] - 6.0);
            let target_x = if mid == bottom { ex } else { centre(mid) };
            let next_y = if mid == bottom {
                nodes[bottom].y
            } else {
                layer_y[layer[mid]] + layer_h[layer[mid]] / 2.0
            };
            if (target_x - cur_x).abs() > 0.5 {
                pts.push((cur_x, ymid));
                pts.push((target_x, ymid));
            }
            pts.push((target_x, next_y));
            cur_x = target_x;
            cur_y = next_y;
            if mid != bottom {
                // Leave the dummy straight down through its layer.
                let leave = layer_y[layer[mid]] + layer_h[layer[mid]];
                pts.push((cur_x, leave));
                cur_y = leave;
            }
        }
        let _ = cur_y;
        // A reversed edge was laid out target-first; its route runs from the real source.
        let (from, to) = (e.from, e.to);
        if is_back {
            pts.reverse();
        }
        routes.push(Route {
            from,
            to,
            kind: e.kind,
            points: dedup(pts),
            back: is_back,
        });
    }

    let width = nodes.iter().map(Rect::right).fold(0.0, f32::max).max(
        routes
            .iter()
            .flat_map(|r| r.points.iter().map(|p| p.0))
            .fold(0.0, f32::max),
    ) + spacing.margin;
    let height = nodes.iter().map(Rect::bottom).fold(0.0, f32::max) + spacing.margin;
    Layout {
        nodes,
        routes,
        width,
        height,
    }
}

fn dedup(mut pts: Vec<(f32, f32)>) -> Vec<(f32, f32)> {
    pts.dedup_by(|a, b| (a.0 - b.0).abs() < 0.01 && (a.1 - b.1).abs() < 0.01);
    pts
}

/// Indices (into `edges`) of back edges, found by DFS from `entry` and then from any node it
/// did not reach, in index order.
fn back_edges(n: usize, edges: &[&Edge], entry: usize) -> HashSet<usize> {
    let mut adj: Vec<Vec<(usize, usize)>> = vec![vec![]; n];
    for (i, e) in edges.iter().enumerate() {
        adj[e.from].push((e.to, i));
    }
    let mut state = vec![0u8; n]; // 0 new, 1 on stack, 2 done
    let mut back = HashSet::new();
    let roots = std::iter::once(entry).chain(0..n);
    for root in roots {
        if state[root] != 0 {
            continue;
        }
        let mut stack = vec![(root, 0usize)];
        state[root] = 1;
        while let Some(&mut (v, ref mut next)) = stack.last_mut() {
            if let Some(&(w, ei)) = adj[v].get(*next) {
                *next += 1;
                match state[w] {
                    0 => {
                        state[w] = 1;
                        stack.push((w, 0));
                    }
                    1 => {
                        back.insert(ei);
                    }
                    _ => {}
                }
            } else {
                state[v] = 2;
                stack.pop();
            }
        }
    }
    back
}

/// Longest-path layering over an acyclic edge list. Nodes the entry cannot reach start at
/// layer 0 too, below nothing, rather than being dropped.
fn layers(n: usize, dag: &[(usize, usize)], entry: usize) -> Vec<usize> {
    let mut indeg = vec![0usize; n];
    let mut adj: Vec<Vec<usize>> = vec![vec![]; n];
    for &(a, b) in dag {
        adj[a].push(b);
        indeg[b] += 1;
    }
    let mut layer = vec![0usize; n];
    let mut queue: Vec<usize> = (0..n).filter(|&v| indeg[v] == 0).collect();
    // The entry always sits at the top: if something points at it, that edge was a back edge.
    if !queue.contains(&entry) {
        queue.push(entry);
    }
    let mut head = 0;
    while head < queue.len() {
        let v = queue[head];
        head += 1;
        for &w in &adj[v] {
            layer[w] = layer[w].max(layer[v] + 1);
            indeg[w] -= 1;
            if indeg[w] == 0 {
                queue.push(w);
            }
        }
    }
    layer
}

/// Nodes per layer in DFS discovery order, so branches start side by side in source order.
fn initial_order(
    depth: usize,
    layer: &[usize],
    down: &[Vec<usize>],
    entry: usize,
    real: usize,
) -> Vec<Vec<usize>> {
    let mut order: Vec<Vec<usize>> = vec![vec![]; depth];
    let mut seen = vec![false; layer.len()];
    let roots = std::iter::once(entry).chain(0..real);
    for root in roots {
        if seen[root] {
            continue;
        }
        let mut stack = vec![root];
        while let Some(v) = stack.pop() {
            if std::mem::replace(&mut seen[v], true) {
                continue;
            }
            order[layer[v]].push(v);
            for &w in down[v].iter().rev() {
                stack.push(w);
            }
        }
    }
    for v in 0..layer.len() {
        if !seen[v] {
            order[layer[v]].push(v);
        }
    }
    order
}

fn crossings(order: &[Vec<usize>], down: &[Vec<usize>]) -> usize {
    let mut pos = vec![0usize; down.len()];
    for layer in order {
        for (i, &v) in layer.iter().enumerate() {
            pos[v] = i;
        }
    }
    let mut total = 0;
    for layer in &order[..order.len().saturating_sub(1)] {
        // Edges leaving this layer, as (upper position, lower position); count inversions.
        let pos = &pos;
        let mut edges: Vec<(usize, usize)> = layer
            .iter()
            .flat_map(|&v| down[v].iter().map(move |&w| (pos[v], pos[w])))
            .collect();
        edges.sort();
        for i in 0..edges.len() {
            for j in i + 1..edges.len() {
                if edges[i].0 < edges[j].0 && edges[i].1 > edges[j].1 {
                    total += 1;
                }
            }
        }
    }
    total
}

fn reduce_crossings(
    mut order: Vec<Vec<usize>>,
    up: &[Vec<usize>],
    down: &[Vec<usize>],
) -> Vec<Vec<usize>> {
    let mut best = order.clone();
    let mut best_count = crossings(&order, down);
    for round in 0..8 {
        if best_count == 0 {
            break;
        }
        let downward = round % 2 == 0;
        let layers: Vec<usize> = if downward {
            (1..order.len()).collect()
        } else {
            (0..order.len().saturating_sub(1)).rev().collect()
        };
        for l in layers {
            let fixed = if downward { l - 1 } else { l + 1 };
            let mut pos = vec![0f32; down.len()];
            for (i, &v) in order[fixed].iter().enumerate() {
                pos[v] = i as f32;
            }
            let neighbours = |v: usize| if downward { &up[v] } else { &down[v] };
            // Barycentre; nodes with no neighbour on the fixed side keep their slot.
            let current: Vec<f32> = order[l]
                .iter()
                .map(|&v| {
                    let nb = neighbours(v);
                    if nb.is_empty() {
                        f32::NAN
                    } else {
                        nb.iter().map(|&w| pos[w]).sum::<f32>() / nb.len() as f32
                    }
                })
                .collect();
            let mut keyed: Vec<(f32, usize, usize)> = order[l]
                .iter()
                .enumerate()
                .map(|(i, &v)| {
                    (
                        if current[i].is_nan() {
                            i as f32
                        } else {
                            current[i]
                        },
                        i,
                        v,
                    )
                })
                .collect();
            keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
            order[l] = keyed.into_iter().map(|k| k.2).collect();
        }
        let count = crossings(&order, down);
        if count < best_count {
            best_count = count;
            best = order.clone();
        }
    }
    best
}

/// Centre x of every node: each layer as close to its neighbours' mean as spacing allows.
fn place(
    order: &[Vec<usize>],
    size: &[Size],
    up: &[Vec<usize>],
    down: &[Vec<usize>],
    gap: f32,
) -> Vec<f32> {
    let mut x = vec![0f32; size.len()];
    // Start packed from the left.
    for layer in order {
        let mut at = 0.0;
        for &v in layer {
            x[v] = at + size[v].w / 2.0;
            at += size[v].w + gap;
        }
    }
    let widest = order
        .iter()
        .map(|l| l.iter().map(|&v| size[v].w + gap).sum::<f32>())
        .fold(0.0, f32::max);
    for layer in order {
        let used: f32 = layer.iter().map(|&v| size[v].w + gap).sum();
        for &v in layer {
            x[v] += (widest - used) / 2.0;
        }
    }
    for pass in 0..10 {
        let downward = pass % 2 == 0;
        let layers: Vec<usize> = if downward {
            (1..order.len()).collect()
        } else {
            (0..order.len().saturating_sub(1)).rev().collect()
        };
        for l in layers {
            let nb = |v: usize| if downward { &up[v] } else { &down[v] };
            let desired: Vec<f32> = order[l]
                .iter()
                .map(|&v| {
                    let n = nb(v);
                    if n.is_empty() {
                        x[v]
                    } else {
                        n.iter().map(|&w| x[w]).sum::<f32>() / n.len() as f32
                    }
                })
                .collect();
            let placed = isotonic(&order[l], size, &desired, gap);
            for (&v, p) in order[l].iter().zip(placed) {
                x[v] = p;
            }
        }
    }
    x
}

/// Positions closest (least squares) to `desired` with `x[i+1] - x[i] >= (w_i + w_{i+1})/2 + gap`,
/// by pool-adjacent-violators on the offset-corrected values.
fn isotonic(layer: &[usize], size: &[Size], desired: &[f32], gap: f32) -> Vec<f32> {
    // offset[i]: minimum distance from the first node's centre to node i's centre.
    let mut offset = vec![0f32; layer.len()];
    for i in 1..layer.len() {
        offset[i] = offset[i - 1] + (size[layer[i - 1]].w + size[layer[i]].w) / 2.0 + gap;
    }
    // y_i = x_i - offset_i must be non-decreasing.
    let target: Vec<f32> = desired.iter().zip(&offset).map(|(d, o)| d - o).collect();
    let mut blocks: Vec<(f32, usize)> = Vec::new(); // (sum, count)
    for &t in &target {
        blocks.push((t, 1));
        while blocks.len() > 1 {
            let (a, b) = (blocks[blocks.len() - 2], blocks[blocks.len() - 1]);
            if a.0 / a.1 as f32 <= b.0 / b.1 as f32 {
                break;
            }
            blocks.truncate(blocks.len() - 2);
            blocks.push((a.0 + b.0, a.1 + b.1));
        }
    }
    let mut out = Vec::with_capacity(layer.len());
    for (sum, count) in blocks {
        let mean = sum / count as f32;
        out.extend(std::iter::repeat_n(mean, count));
    }
    out.iter().zip(&offset).map(|(y, o)| y + o).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(n: usize) -> Vec<Size> {
        vec![Size { w: 80.0, h: 40.0 }; n]
    }
    fn edge(from: usize, to: usize, kind: EdgeKind) -> Edge {
        Edge { from, to, kind }
    }

    #[test]
    fn a_diamond_lays_out_in_three_layers_without_overlap() {
        let edges = [
            edge(0, 1, EdgeKind::Taken),
            edge(0, 2, EdgeKind::NotTaken),
            edge(1, 3, EdgeKind::Unconditional),
            edge(2, 3, EdgeKind::Unconditional),
        ];
        let l = layout(&boxed(4), &edges, 0, Spacing::default());
        let (a, b, c, d) = (l.nodes[0], l.nodes[1], l.nodes[2], l.nodes[3]);
        assert!(
            a.y < b.y && (b.y - c.y).abs() < 0.01 && b.y < d.y,
            "layers: {l:?}"
        );
        assert!(
            b.right() + 36.0 <= c.x + 0.01 || c.right() + 36.0 <= b.x + 0.01,
            "siblings must be separated by the node gap"
        );
        // The head and the join are centred over their children.
        let mid = |r: Rect| r.x + r.w / 2.0;
        assert!(
            (mid(a) - (mid(b) + mid(c)) / 2.0).abs() < 1.0
                && (mid(d) - (mid(b) + mid(c)) / 2.0).abs() < 1.0
        );
        assert_eq!(l.routes.len(), 4);
        assert!(l.routes.iter().all(|r| r.points.len() >= 2 && !r.back));
    }

    #[test]
    fn every_route_starts_on_its_source_and_ends_on_its_target() {
        let edges = [
            edge(0, 1, EdgeKind::Taken),
            edge(0, 2, EdgeKind::NotTaken),
            edge(1, 3, EdgeKind::Unconditional),
            edge(2, 3, EdgeKind::Unconditional),
            edge(0, 3, EdgeKind::Unconditional),
        ];
        let l = layout(&boxed(4), &edges, 0, Spacing::default());
        for r in &l.routes {
            let (s, t) = (l.nodes[r.from], l.nodes[r.to]);
            let first = r.points[0];
            let last = *r.points.last().unwrap();
            assert!(
                first.0 >= s.x - 0.01
                    && first.0 <= s.right() + 0.01
                    && (first.1 - s.bottom()).abs() < 0.01,
                "start {first:?} not on bottom of {s:?}"
            );
            assert!(
                last.0 >= t.x - 0.01 && last.0 <= t.right() + 0.01 && (last.1 - t.y).abs() < 0.01,
                "end {last:?} not on top of {t:?}"
            );
        }
    }

    #[test]
    fn a_loop_keeps_its_header_above_its_body_and_marks_the_back_edge() {
        // 0 -> 1 (header) -> 2 (body) -> 1, 1 -> 3 (exit)
        let edges = [
            edge(0, 1, EdgeKind::Unconditional),
            edge(1, 2, EdgeKind::NotTaken),
            edge(2, 1, EdgeKind::Unconditional),
            edge(1, 3, EdgeKind::Taken),
        ];
        let l = layout(&boxed(4), &edges, 0, Spacing::default());
        assert!(
            l.nodes[0].y < l.nodes[1].y && l.nodes[1].y < l.nodes[2].y,
            "{:?}",
            l.nodes
        );
        let back: Vec<_> = l.routes.iter().filter(|r| r.back).collect();
        assert_eq!(back.len(), 1);
        assert_eq!((back[0].from, back[0].to), (2, 1));
        // The back edge's route runs upwards: from the body's bottom to the header's top.
        let (first, last) = (back[0].points[0], *back[0].points.last().unwrap());
        assert!(
            first.1 > last.1 || (first.1 - l.nodes[2].bottom()).abs() < 1.0,
            "{:?}",
            back[0].points
        );
    }

    #[test]
    fn long_edges_get_a_clear_channel_through_intermediate_layers() {
        // 0 -> 1 -> 2 -> 3 chain, plus 0 -> 3 skipping two layers.
        let edges = [
            edge(0, 1, EdgeKind::Taken),
            edge(1, 2, EdgeKind::Unconditional),
            edge(2, 3, EdgeKind::Unconditional),
            edge(0, 3, EdgeKind::NotTaken),
        ];
        let l = layout(&boxed(4), &edges, 0, Spacing::default());
        let long = l.routes.iter().find(|r| (r.from, r.to) == (0, 3)).unwrap();
        // Between the top of layer 1 and the bottom of layer 2 the route must not run through
        // any node.
        for w in long.points.windows(2) {
            if (w[0].0 - w[1].0).abs() < 0.01 {
                let x = w[0].0;
                let (y0, y1) = (w[0].1.min(w[1].1), w[0].1.max(w[1].1));
                for (i, n) in l.nodes.iter().enumerate() {
                    if i == 0 || i == 3 {
                        continue;
                    }
                    let inside =
                        x > n.x + 0.5 && x < n.right() - 0.5 && y1 > n.y && y0 < n.bottom();
                    assert!(!inside, "route {:?} crosses node {i} {n:?}", long.points);
                }
            }
        }
    }

    #[test]
    fn unreachable_nodes_are_still_placed_and_layout_is_deterministic() {
        let edges = [
            edge(0, 1, EdgeKind::Unconditional),
            edge(2, 3, EdgeKind::Unconditional),
        ];
        let a = layout(&boxed(4), &edges, 0, Spacing::default());
        let b = layout(&boxed(4), &edges, 0, Spacing::default());
        assert_eq!(a.nodes.len(), 4);
        for (p, q) in a.nodes.iter().zip(&b.nodes) {
            assert_eq!(p, q);
        }
        assert!(
            a.nodes.iter().all(|r| r.x >= 0.0
                && r.y >= 0.0
                && r.right() <= a.width
                && r.bottom() <= a.height)
        );
    }

    #[test]
    fn a_ladder_of_branches_has_no_crossings_after_ordering() {
        // Two parallel chains 0->{1,2}->{3,4}->5 where 1->3 and 2->4 (no cross edges).
        let edges = [
            edge(0, 1, EdgeKind::Taken),
            edge(0, 2, EdgeKind::NotTaken),
            edge(1, 3, EdgeKind::Unconditional),
            edge(2, 4, EdgeKind::Unconditional),
            edge(3, 5, EdgeKind::Unconditional),
            edge(4, 5, EdgeKind::Unconditional),
        ];
        let l = layout(&boxed(6), &edges, 0, Spacing::default());
        let left_of = |a: usize, b: usize| l.nodes[a].x < l.nodes[b].x;
        assert_eq!(
            left_of(1, 2),
            left_of(3, 4),
            "chains must not swap sides: {:?}",
            l.nodes
        );
    }

    #[test]
    fn isotonic_placement_respects_spacing_and_follows_the_targets() {
        let size = vec![Size { w: 10.0, h: 1.0 }; 3];
        let layer = [0, 1, 2];
        // Targets 0, 1, 2 are too close for width 10 + gap 4: they spread around their mean.
        let p = isotonic(&layer, &size, &[0.0, 1.0, 2.0], 4.0);
        assert!(
            (p[1] - p[0] - 14.0).abs() < 1e-3 && (p[2] - p[1] - 14.0).abs() < 1e-3,
            "{p:?}"
        );
        assert!(
            (p.iter().sum::<f32>() / 3.0 - 1.0).abs() < 1e-3,
            "the block stays centred on the mean of the targets"
        );
        // Targets already far enough apart are kept exactly.
        let q = isotonic(&layer, &size, &[0.0, 50.0, 100.0], 4.0);
        assert_eq!(
            q.iter().map(|v| v.round() as i32).collect::<Vec<_>>(),
            [0, 50, 100]
        );
    }
}
