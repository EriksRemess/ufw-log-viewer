use std::cmp::min;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

mod clipboard;
mod net;
mod parser;
mod services;

use clipboard::copy_text_via_osc52;
use crossterm::cursor::Show;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::{execute, terminal};
use net::{
    default_wan_interface, is_local_src_ip, is_wan_candidate_interface, is_wan_src_ip,
    matches_direction_filter, matches_flow_filter,
};
use parser::parse_ufw_line;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{Frame, Terminal};
use services::service_description_from_port;

const APP_TITLE: &str = "UFW Log Viewer";
const MIN_UI_WIDTH: u16 = 90;
const MIN_UI_HEIGHT: u16 = 15;

#[derive(Debug, Clone, Default)]
struct LogEntry {
    timestamp: String,
    action: String,
    in_iface: Option<String>,
    out_iface: Option<String>,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    proto: Option<String>,
    service: Option<String>,
    raw: String,
}

impl LogEntry {
    fn direction(&self) -> &'static str {
        let has_in = self.in_iface.as_deref().is_some_and(|v| !v.is_empty());
        let has_out = self.out_iface.as_deref().is_some_and(|v| !v.is_empty());
        match (has_in, has_out) {
            (true, false) => "IN",
            (false, true) => "OUT",
            (true, true) => "FWD",
            (false, false) => "?",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Filters {
    service: String,
    port: String,
    ip: String,
    action: String,
    proto: String,
    text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterField {
    Service,
    Port,
    Ip,
    Action,
    Proto,
    Text,
}

impl FilterField {
    fn label(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Port => "port",
            Self::Ip => "ip",
            Self::Action => "action",
            Self::Proto => "protocol",
            Self::Text => "text",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FlowFilter {
    #[default]
    All,
    LocalToLocal,
    LocalToExternal,
}

impl FlowFilter {
    fn next(self) -> Self {
        match self {
            Self::All => Self::LocalToLocal,
            Self::LocalToLocal => Self::LocalToExternal,
            Self::LocalToExternal => Self::All,
        }
    }

    fn chip(self) -> &'static str {
        match self {
            Self::All => "[flow: *]",
            Self::LocalToLocal => "[flow: local→local]",
            Self::LocalToExternal => "[flow: local→external]",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::LocalToLocal => "local->local",
            Self::LocalToExternal => "local->external",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum DirectionFilter {
    #[default]
    Both,
    In,
    Out,
    Forwarded,
}

impl DirectionFilter {
    fn next(self) -> Self {
        match self {
            Self::Both => Self::In,
            Self::In => Self::Out,
            Self::Out => Self::Forwarded,
            Self::Forwarded => Self::Both,
        }
    }

    fn chip(self) -> &'static str {
        match self {
            Self::Both => "[dir: ↕ both]",
            Self::In => "[dir: ↓ in]",
            Self::Out => "[dir: ↑ out]",
            Self::Forwarded => "[dir: ↔ fwd]",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Both => "in+out",
            Self::In => "in",
            Self::Out => "out",
            Self::Forwarded => "forwarded",
        }
    }
}

fn display_filter_value(value: &str) -> &str {
    if value.is_empty() { "*" } else { value }
}

#[derive(Debug, Clone)]
enum ToggleTarget {
    Local,
    WanSrc,
    Flow,
    Direction,
    PauseUpdates,
    AllIfaces,
    Interface(String),
}

struct App {
    log_path: PathBuf,
    entries: Vec<LogEntry>,
    interface_options: Vec<String>,
    selected_interface: Option<String>,
    filters: Filters,
    show_local_src: bool,
    show_wan_src: bool,
    flow_filter: FlowFilter,
    direction_filter: DirectionFilter,
    updates_paused: bool,
    selected: usize,
    log_entry_scroll: u16,
    table_state: TableState,
    last_watch_check: Instant,
    last_fingerprint: Option<FileFingerprint>,
    input_mode: Option<FilterField>,
    input_buffer: String,
    status: String,
    status_snapshot: String,
    status_since: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    modified: Option<SystemTime>,
    len: u64,
}

impl App {
    fn new(log_path: PathBuf) -> Self {
        let mut app = Self {
            log_path,
            entries: Vec::new(),
            interface_options: Vec::new(),
            selected_interface: None,
            filters: Filters::default(),
            show_local_src: false,
            show_wan_src: true,
            flow_filter: FlowFilter::All,
            direction_filter: DirectionFilter::Both,
            updates_paused: false,
            selected: 0,
            log_entry_scroll: 0,
            table_state: TableState::default().with_selected(Some(0)),
            last_watch_check: Instant::now(),
            last_fingerprint: None,
            input_mode: None,
            input_buffer: String::new(),
            status: String::new(),
            status_snapshot: String::new(),
            status_since: None,
        };
        let _ = app.reload();
        app
    }

    fn reload(&mut self) -> bool {
        let prev_selected = self.selected;
        let prev_selected_raw = self.current_selected_raw();
        let prev_iface = self.selected_interface.clone();
        match load_entries(&self.log_path) {
            Ok(entries) => {
                self.entries = entries;
                self.refresh_interface_options(prev_iface);

                let filtered = self.filtered_indices();
                self.selected = if let Some(raw) = prev_selected_raw.as_deref() {
                    selected_position_for_raw(&self.entries, &filtered, raw)
                        .unwrap_or_else(|| min(prev_selected, filtered.len().saturating_sub(1)))
                } else {
                    min(prev_selected, filtered.len().saturating_sub(1))
                };
                self.sync_selection_with_len(filtered.len());
                self.last_fingerprint = file_fingerprint(&self.log_path).ok();
                self.status.clear();
                true
            }
            Err(err) => {
                self.entries.clear();
                self.selected = 0;
                self.table_state.select(None);
                self.last_fingerprint = None;
                self.status = format!("Failed to read {}: {}", self.log_path.display(), err);
                false
            }
        }
    }

    fn current_selected_raw(&self) -> Option<String> {
        let filtered = self.filtered_indices();
        if filtered.is_empty() {
            return None;
        }
        let selected = min(self.selected, filtered.len() - 1);
        Some(self.entries[filtered[selected]].raw.clone())
    }

    fn select_visible_row_index(&mut self, row_index: usize) {
        let filtered_len = self.filtered_indices().len();
        if filtered_len == 0 {
            return;
        }
        let offset = self.table_state.offset();
        let absolute = min(
            offset.saturating_add(row_index),
            filtered_len.saturating_sub(1),
        );
        self.selected = absolute;
        self.sync_selection_with_len(filtered_len);
    }

    fn copy_selected_log_entry(&mut self) {
        let Some(raw) = self.current_selected_raw() else {
            return;
        };
        match copy_text_via_osc52(&raw) {
            Ok(()) => {
                self.status = "Copied selected log entry (OSC52)".to_string();
            }
            Err(err) => {
                self.status = format!("Clipboard copy failed: {}", err);
            }
        }
    }

    fn copy_selected_src_ip(&mut self) {
        let filtered = self.filtered_indices();
        if filtered.is_empty() {
            return;
        }
        let selected = min(self.selected, filtered.len() - 1);
        let src_ip = self.entries[filtered[selected]]
            .src_ip
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_string();
        if src_ip.is_empty() {
            self.status = "No source IP on selected row".to_string();
            return;
        }
        match copy_text_via_osc52(&src_ip) {
            Ok(()) => {
                self.status = format!("Copied source IP: {}", src_ip);
            }
            Err(err) => {
                self.status = format!("Source IP copy failed: {}", err);
            }
        }
    }

    fn clear_filters(&mut self) {
        self.filters = Filters::default();
        self.show_local_src = false;
        self.show_wan_src = true;
        self.flow_filter = FlowFilter::All;
        self.direction_filter = DirectionFilter::Both;
        self.selected_interface = default_wan_interface(&self.interface_options);
        self.selected = 0;
        self.log_entry_scroll = 0;
        self.table_state.select(Some(0));
        self.status = format!(
            "Cleared filters (local src hidden, wan src shown, flow all, dir in+out, interface: {})",
            selected_iface_label(self.selected_interface.as_deref())
        );
    }

    fn set_input_mode(&mut self, field: FilterField) {
        self.input_mode = Some(field);
        self.input_buffer = self.get_filter_value(field).to_string();
    }

    fn get_filter_value(&self, field: FilterField) -> &str {
        match field {
            FilterField::Service => &self.filters.service,
            FilterField::Port => &self.filters.port,
            FilterField::Ip => &self.filters.ip,
            FilterField::Action => &self.filters.action,
            FilterField::Proto => &self.filters.proto,
            FilterField::Text => &self.filters.text,
        }
    }

    fn set_filter_value(&mut self, field: FilterField, value: String) {
        let cleaned = value.trim().to_string();
        match field {
            FilterField::Service => self.filters.service = cleaned,
            FilterField::Port => self.filters.port = cleaned,
            FilterField::Ip => self.filters.ip = cleaned,
            FilterField::Action => self.filters.action = cleaned,
            FilterField::Proto => self.filters.proto = cleaned,
            FilterField::Text => self.filters.text = cleaned,
        }
        self.selected = 0;
        self.log_entry_scroll = 0;
    }

    fn clear_filter(&mut self, field: FilterField) {
        self.set_filter_value(field, String::new());
        let matches = self.filtered_indices().len();
        self.status = format!(
            "Cleared {} filter. Matching rows: {}",
            field.label(),
            matches
        );
    }

    fn filtered_indices(&self) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(idx, entry)| {
                if let Some(selected) = self.selected_interface.as_deref() {
                    let in_match = entry.in_iface.as_deref() == Some(selected);
                    let out_match = entry.out_iface.as_deref() == Some(selected);
                    if !in_match && !out_match {
                        return None;
                    }
                }
                if !self.show_local_src && is_local_src_ip(entry.src_ip.as_deref()) {
                    return None;
                }
                if !self.show_wan_src && is_wan_src_ip(entry.src_ip.as_deref()) {
                    return None;
                }
                if !matches_flow_filter(self.flow_filter, entry) {
                    return None;
                }
                if !matches_direction_filter(self.direction_filter, entry) {
                    return None;
                }
                self.filters.matches(entry).then_some(idx)
            })
            .collect()
    }

    fn refresh_interface_options(&mut self, previous: Option<String>) {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for entry in &self.entries {
            for iface in [&entry.in_iface, &entry.out_iface] {
                let Some(name) = iface.as_ref() else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                *counts.entry(name.clone()).or_insert(0) += 1;
            }
        }

        let mut options: Vec<(String, usize)> = counts.into_iter().collect();
        options.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        self.interface_options = options.into_iter().map(|(name, _)| name).collect();

        if let Some(prev) = previous
            && self.interface_options.iter().any(|iface| iface == &prev)
        {
            self.selected_interface = Some(prev);
            return;
        }
        self.selected_interface = default_wan_interface(&self.interface_options);
    }

    fn cycle_interface(&mut self, forward: bool) {
        if self.interface_options.is_empty() {
            self.selected_interface = None;
            self.status = "No interfaces found in logs".to_string();
            return;
        }

        let len = self.interface_options.len() as isize;
        let mut idx = self
            .selected_interface
            .as_ref()
            .and_then(|selected| {
                self.interface_options
                    .iter()
                    .position(|iface| iface == selected)
            })
            .map_or(-1, |i| i as isize);

        idx = if forward {
            if idx >= len - 1 { -1 } else { idx + 1 }
        } else if idx < 0 {
            len - 1
        } else {
            idx - 1
        };

        self.set_selected_interface(if idx < 0 {
            None
        } else {
            Some(self.interface_options[idx as usize].clone())
        });
        let matches = self.filtered_indices().len();
        self.status = format!(
            "Interface: {}. Matching rows: {}",
            selected_iface_label(self.selected_interface.as_deref()),
            matches
        );
    }

    fn select_all_interfaces(&mut self) {
        self.set_selected_interface(None);
        let matches = self.filtered_indices().len();
        self.status = format!("Interface: all. Matching rows: {}", matches);
    }

    fn select_default_wan_interface(&mut self) {
        self.set_selected_interface(default_wan_interface(&self.interface_options));
        let matches = self.filtered_indices().len();
        self.status = format!(
            "Interface: {}. Matching rows: {}",
            selected_iface_label(self.selected_interface.as_deref()),
            matches
        );
    }

    fn set_selected_interface(&mut self, interface: Option<String>) {
        self.selected_interface = interface;
        self.selected = 0;
        self.log_entry_scroll = 0;
        self.table_state.select(Some(0));
    }

    fn toggle_show_local_src(&mut self) {
        self.show_local_src = !self.show_local_src;
        self.selected = 0;
        self.log_entry_scroll = 0;
        self.table_state.select(Some(0));
        let matches = self.filtered_indices().len();
        self.status = if self.show_local_src {
            format!("Showing local source IP rows. Matching rows: {}", matches)
        } else {
            format!("Hiding local source IP rows. Matching rows: {}", matches)
        };
    }

    fn toggle_show_wan_src(&mut self) {
        self.show_wan_src = !self.show_wan_src;
        self.selected = 0;
        self.log_entry_scroll = 0;
        self.table_state.select(Some(0));
        let matches = self.filtered_indices().len();
        self.status = if self.show_wan_src {
            format!("Showing WAN source IP rows. Matching rows: {}", matches)
        } else {
            format!("Hiding WAN source IP rows. Matching rows: {}", matches)
        };
    }

    fn cycle_flow_filter(&mut self) {
        self.flow_filter = self.flow_filter.next();
        self.selected = 0;
        self.log_entry_scroll = 0;
        self.table_state.select(Some(0));
        let matches = self.filtered_indices().len();
        self.status = format!(
            "Flow filter: {}. Matching rows: {}",
            self.flow_filter.label(),
            matches
        );
    }

    fn cycle_direction_filter(&mut self) {
        self.direction_filter = self.direction_filter.next();
        self.selected = 0;
        self.log_entry_scroll = 0;
        self.table_state.select(Some(0));
        let matches = self.filtered_indices().len();
        self.status = format!(
            "Direction filter: {}. Matching rows: {}",
            self.direction_filter.label(),
            matches
        );
    }

    fn toggle_pause_updates(&mut self) {
        self.updates_paused = !self.updates_paused;
        if !self.updates_paused {
            let _ = self.reload();
        }
    }

    fn sync_selection_with_len(&mut self, len: usize) {
        let prev = self.selected;
        if len == 0 {
            self.selected = 0;
            self.log_entry_scroll = 0;
            self.table_state.select(None);
        } else {
            self.selected = min(self.selected, len - 1);
            self.table_state.select(Some(self.selected));
            if self.selected != prev {
                self.log_entry_scroll = 0;
            }
        }
    }

    fn scroll_log_entry_left(&mut self) {
        const STEP: u16 = 8;
        self.log_entry_scroll = self.log_entry_scroll.saturating_sub(STEP);
    }

    fn scroll_log_entry_right(&mut self) {
        const STEP: u16 = 8;
        let max = self.current_log_entry_max_scroll();
        self.log_entry_scroll = min(self.log_entry_scroll.saturating_add(STEP), max);
    }

    fn current_log_entry_max_scroll(&self) -> u16 {
        let filtered = self.filtered_indices();
        if filtered.is_empty() {
            return 0;
        }
        let selected = min(self.selected, filtered.len() - 1);
        self.entries[filtered[selected]]
            .raw
            .len()
            .saturating_sub(1)
            .min(u16::MAX as usize) as u16
    }

    fn maybe_reload(&mut self) {
        if self.updates_paused {
            return;
        }
        if self.last_watch_check.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_watch_check = Instant::now();

        let Ok(current) = file_fingerprint(&self.log_path) else {
            return;
        };

        if self.last_fingerprint.as_ref() != Some(&current) {
            let previous_status = self.status.clone();
            if self.reload() {
                self.status = previous_status;
            }
        }
    }

    fn refresh_status_lifetime(&mut self) {
        // Any status change restarts the visibility timer.
        if self.status != self.status_snapshot {
            self.status_snapshot = self.status.clone();
            self.status_since = if self.status.is_empty() {
                None
            } else {
                Some(Instant::now())
            };
        }

        if !self.status.is_empty()
            && let Some(since) = self.status_since
            && since.elapsed() >= Duration::from_secs(5)
        {
            self.status.clear();
            self.status_snapshot.clear();
            self.status_since = None;
        }
    }
}

impl Filters {
    fn active_count(&self) -> usize {
        [
            &self.service,
            &self.port,
            &self.ip,
            &self.action,
            &self.proto,
            &self.text,
        ]
        .into_iter()
        .filter(|value| !value.is_empty())
        .count()
    }

    fn matches(&self, entry: &LogEntry) -> bool {
        if !self.service.is_empty() {
            let term = self.service.to_ascii_lowercase();
            let service = entry.service.as_deref().unwrap_or("").to_ascii_lowercase();
            if !service.contains(&term) {
                return false;
            }
        }

        if !self.port.is_empty() {
            let wanted = self.port.trim();
            let port_match = if let Ok(port) = wanted.parse::<u16>() {
                entry.src_port == Some(port) || entry.dst_port == Some(port)
            } else {
                let src = entry.src_port.map(|p| p.to_string()).unwrap_or_default();
                let dst = entry.dst_port.map(|p| p.to_string()).unwrap_or_default();
                src.contains(wanted) || dst.contains(wanted)
            };
            if !port_match {
                return false;
            }
        }

        if !self.ip.is_empty() {
            let term = self.ip.to_ascii_lowercase();
            let src = entry.src_ip.as_deref().unwrap_or("").to_ascii_lowercase();
            let dst = entry.dst_ip.as_deref().unwrap_or("").to_ascii_lowercase();
            if !src.contains(&term) && !dst.contains(&term) {
                return false;
            }
        }

        if !self.action.is_empty() {
            let term = self.action.to_ascii_lowercase();
            if !entry.action.to_ascii_lowercase().contains(&term) {
                return false;
            }
        }

        if !self.proto.is_empty() {
            let term = self.proto.to_ascii_lowercase();
            let proto = entry.proto.as_deref().unwrap_or("").to_ascii_lowercase();
            if !proto.contains(&term) {
                return false;
            }
        }

        if !self.text.is_empty() {
            let term = self.text.to_ascii_lowercase();
            if !entry.raw.to_ascii_lowercase().contains(&term) {
                return false;
            }
        }

        true
    }
}

fn load_entries(path: &Path) -> io::Result<Vec<LogEntry>> {
    let contents = fs::read_to_string(path)?;
    let mut entries: Vec<LogEntry> = contents.lines().filter_map(parse_ufw_line).collect();
    entries.reverse();
    Ok(entries)
}

fn file_fingerprint(path: &Path) -> io::Result<FileFingerprint> {
    let meta = fs::metadata(path)?;
    Ok(FileFingerprint {
        modified: meta.modified().ok(),
        len: meta.len(),
    })
}

fn field_from_fkey(n: u8) -> Option<FilterField> {
    match n {
        1 => Some(FilterField::Service),
        2 => Some(FilterField::Port),
        3 => Some(FilterField::Ip),
        4 => Some(FilterField::Action),
        5 => Some(FilterField::Proto),
        6 => Some(FilterField::Text),
        _ => None,
    }
}

fn selected_iface_label(value: Option<&str>) -> &str {
    value.unwrap_or("all")
}

fn selected_position_for_raw(
    entries: &[LogEntry],
    filtered_indices: &[usize],
    raw: &str,
) -> Option<usize> {
    filtered_indices
        .iter()
        .position(|entry_idx| entries[*entry_idx].raw == raw)
}

fn pause_chip_label(paused: bool) -> &'static str {
    if paused { "[paused]" } else { "[live]" }
}

fn max_horizontal_scroll(text: &str, content_width: u16) -> u16 {
    if content_width == 0 {
        return 0;
    }
    let longest_line = text
        .lines()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0);
    longest_line
        .saturating_sub(content_width as usize)
        .min(u16::MAX as usize) as u16
}

fn format_timestamp_for_width(timestamp: &str, show_date: bool) -> String {
    let token = timestamp
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim();

    // ISO-8601 style: 2026-02-11T23:00:39.987820+02:00
    if let Some((date, time_part)) = token.split_once('T') {
        let time = time_part
            .split(['.', '+', 'Z'])
            .next()
            .unwrap_or_default()
            .split('-')
            .next()
            .unwrap_or_default();
        if !date.is_empty() && !time.is_empty() {
            return if show_date {
                format!("{} {}", date, time)
            } else {
                time.to_string()
            };
        }
    }

    // Syslog style: Feb 11 20:21:00 host
    let parts: Vec<&str> = timestamp.split_whitespace().collect();
    if parts.len() >= 3 && parts[2].contains(':') {
        return if show_date {
            format!("{} {} {}", parts[0], parts[1], parts[2])
        } else {
            parts[2].to_string()
        };
    }

    timestamp.to_string()
}

fn service_display_for_entry(entry: &LogEntry, show_description: bool) -> String {
    let name = entry.service.as_deref().unwrap_or("-");
    if name == "-" || !show_description {
        return name.to_string();
    }

    let port = entry.dst_port.or(entry.src_port);
    let Some(port) = port else {
        return name.to_string();
    };
    let Some(description) = service_description_from_port(port) else {
        return name.to_string();
    };
    if description.eq_ignore_ascii_case(name) {
        return name.to_string();
    }

    format!("{}: {}", name, description)
}

fn key_span(text: &'static str) -> Span<'static> {
    Span::styled(
        text,
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
}

fn desc_span(text: &'static str) -> Span<'static> {
    Span::styled(text, Style::default().fg(Color::Gray))
}

fn sep_span() -> Span<'static> {
    Span::styled(" | ", Style::default().fg(Color::DarkGray))
}

fn footer_help_lines(width: u16) -> Vec<Line<'static>> {
    let width = width.max(MIN_UI_WIDTH);

    if width >= 140 {
        vec![Line::from(vec![
            key_span("q"),
            desc_span(" quit"),
            sep_span(),
            key_span("r"),
            desc_span(" reload"),
            sep_span(),
            key_span("a"),
            desc_span(" pause/resume"),
            sep_span(),
            key_span("c"),
            desc_span(" clear"),
            sep_span(),
            key_span("l"),
            desc_span(" local"),
            sep_span(),
            key_span("p"),
            desc_span(" wan"),
            sep_span(),
            key_span("f"),
            desc_span(" flow"),
            sep_span(),
            key_span("d"),
            desc_span(" dir"),
            sep_span(),
            key_span("F1..F6"),
            desc_span(" edit"),
            sep_span(),
            key_span("Shift+F"),
            desc_span(" clear"),
            sep_span(),
            key_span(",/."),
            desc_span(" iface"),
            sep_span(),
            key_span("0"),
            desc_span(" all"),
            sep_span(),
            key_span("w"),
            desc_span(" wan"),
            sep_span(),
            key_span("<-/->"),
            desc_span(" log"),
            sep_span(),
            key_span("Ctrl+C"),
            desc_span(" copy row"),
            sep_span(),
            key_span("Ctrl+I"),
            desc_span(" copy src ip"),
        ])]
    } else if width >= 110 {
        vec![
            Line::from(vec![
                key_span("q"),
                desc_span(" quit"),
                sep_span(),
                key_span("r"),
                desc_span(" reload"),
                sep_span(),
                key_span("a"),
                desc_span(" pause"),
                sep_span(),
                key_span("c"),
                desc_span(" clear"),
                sep_span(),
                key_span("l/p/f"),
                desc_span(" toggles"),
                sep_span(),
                key_span("d"),
                desc_span(" dir"),
                sep_span(),
                key_span("F1..F6"),
                desc_span(" edit"),
                sep_span(),
                key_span("Shift+F"),
                desc_span(" clear"),
            ]),
            Line::from(vec![
                key_span(",/."),
                desc_span(" iface"),
                sep_span(),
                key_span("0"),
                desc_span(" all"),
                sep_span(),
                key_span("w"),
                desc_span(" wan"),
                sep_span(),
                key_span("<-/->"),
                desc_span(" log"),
                sep_span(),
                key_span("Ctrl+C"),
                desc_span(" row"),
                sep_span(),
                key_span("Ctrl+I"),
                desc_span(" src ip"),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                key_span("q"),
                desc_span(" quit"),
                sep_span(),
                key_span("r"),
                desc_span(" reload"),
                sep_span(),
                key_span("a"),
                desc_span(" pause"),
                sep_span(),
                key_span("c"),
                desc_span(" clear"),
                sep_span(),
                key_span("l/p/f"),
                desc_span(" toggles"),
                sep_span(),
                key_span("d"),
                desc_span(" dir"),
            ]),
            Line::from(vec![
                key_span("F1..F6"),
                desc_span(" edit"),
                sep_span(),
                key_span("Shift+F"),
                desc_span(" clear"),
                sep_span(),
                key_span(",/."),
                desc_span(" iface"),
                sep_span(),
                key_span("0"),
                desc_span(" all"),
                sep_span(),
                key_span("w"),
                desc_span(" wan"),
                sep_span(),
                key_span("<-/->"),
                desc_span(" log"),
                sep_span(),
                key_span("Ctrl+C"),
                desc_span(" row"),
                sep_span(),
                key_span("Ctrl+I"),
                desc_span(" ip"),
            ]),
        ]
    }
}

fn max_visible_ifaces(width: u16) -> usize {
    if width >= 160 {
        8
    } else if width >= 120 {
        6
    } else {
        4
    }
}

fn interface_prefix(width: u16) -> &'static str {
    if width >= 120 {
        "interface: "
    } else {
        "iface "
    }
}

fn left_toggle_width(app: &App) -> u16 {
    let local = text_cells("[local]");
    let wan = text_cells("[wan]");
    let flow = text_cells(app.flow_filter.chip());
    let dir = text_cells(app.direction_filter.chip());
    local
        .saturating_add(1)
        .saturating_add(wan)
        .saturating_add(1)
        .saturating_add(flow)
        .saturating_add(1)
        .saturating_add(dir)
}

fn interface_row_width(app: &App, max_interfaces: usize, row_width: u16) -> u16 {
    let mut width = text_cells(interface_prefix(row_width));
    let all_label = if app.selected_interface.is_none() {
        "[all]"
    } else {
        "all"
    };
    width = width.saturating_add(text_cells(all_label));

    for iface in app.interface_options.iter().take(max_interfaces) {
        let selected = app.selected_interface.as_deref() == Some(iface.as_str());
        let label = if selected {
            format!("[{}]", iface)
        } else {
            iface.clone()
        };
        width = width.saturating_add(1).saturating_add(text_cells(&label));
    }

    if app.interface_options.len() > max_interfaces {
        let extra = format!("+{}", app.interface_options.len() - max_interfaces);
        width = width.saturating_add(1).saturating_add(text_cells(&extra));
    }

    width
}

fn controls_layout(app: &App, width: u16) -> (bool, usize, u16) {
    let max_ifaces = max_visible_ifaces(width);
    let left_width = left_toggle_width(app);

    for visible_ifaces in (0..=max_ifaces).rev() {
        let right_width = interface_row_width(app, visible_ifaces, width);
        if left_width.saturating_add(2).saturating_add(right_width) <= width {
            let right_start = width.saturating_sub(right_width);
            return (true, visible_ifaces, right_start);
        }
    }

    (false, max_ifaces, 0)
}

fn left_toggle_spans(app: &App) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            "[local]",
            if app.show_local_src {
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                Style::default().fg(Color::Gray)
            },
        ),
        Span::raw(" "),
        Span::styled(
            "[wan]",
            if app.show_wan_src {
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                Style::default().fg(Color::Gray)
            },
        ),
        Span::raw(" "),
        Span::styled(
            app.flow_filter.chip(),
            if app.flow_filter == FlowFilter::All {
                Style::default().fg(Color::Gray)
            } else {
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            },
        ),
        Span::raw(" "),
        Span::styled(
            app.direction_filter.chip(),
            if app.direction_filter == DirectionFilter::Both {
                Style::default().fg(Color::Gray)
            } else {
                Style::default()
                    .fg(Color::LightMagenta)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            },
        ),
    ]
}

fn interface_display_spans(app: &App, max_interfaces: usize, row_width: u16) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::styled(
        interface_prefix(row_width),
        Style::default().fg(Color::DarkGray),
    ));

    let all_selected = app.selected_interface.is_none();
    let all_style = if all_selected {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default().fg(Color::Gray)
    };
    spans.push(Span::styled(
        if all_selected {
            "[all]".to_string()
        } else {
            "all".to_string()
        },
        all_style,
    ));

    for iface in app.interface_options.iter().take(max_interfaces) {
        spans.push(Span::raw(" "));
        let is_selected = app.selected_interface.as_deref() == Some(iface.as_str());
        let base = if is_wan_candidate_interface(iface) {
            Color::LightGreen
        } else {
            Color::LightCyan
        };
        let style = if is_selected {
            Style::default()
                .fg(base)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::default().fg(Color::Gray)
        };
        let label = if is_selected {
            format!("[{}]", iface)
        } else {
            iface.clone()
        };
        spans.push(Span::styled(label, style));
    }

    if app.interface_options.len() > max_interfaces {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            format!(" +{}", app.interface_options.len() - max_interfaces),
            Style::default().fg(Color::DarkGray),
        ));
    }

    spans
}

fn handle_modifier_shortcuts(app: &mut App, key: &crossterm::event::KeyEvent) -> bool {
    if let KeyCode::F(n) = key.code
        && let Some(field) = field_from_fkey(n)
    {
        if key.modifiers.contains(KeyModifiers::SHIFT) {
            app.clear_filter(field);
        } else {
            app.set_input_mode(field);
        }
        return true;
    }

    false
}

fn main_chunks(area: Rect, filters_height: u16) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(filters_height),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(area)
        .to_vec()
}

fn text_cells(text: &str) -> u16 {
    text.chars().count().min(u16::MAX as usize) as u16
}

fn truncate_with_ellipsis(text: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }
    let cell_count = text.chars().count();
    if cell_count <= max_width {
        return text.to_string();
    }
    if max_width <= 3 {
        return ".".repeat(max_width);
    }
    let mut out = String::with_capacity(max_width);
    for ch in text.chars().take(max_width - 3) {
        out.push(ch);
    }
    out.push_str("...");
    out
}

fn pad_to_width(text: &str, width: usize) -> String {
    let used = text.chars().count();
    if used >= width {
        return text.to_string();
    }
    format!("{}{}", text, " ".repeat(width - used))
}

fn build_three_column_line(width: u16, cells: [String; 3]) -> Line<'static> {
    let total = usize::from(width.max(3));
    let gap = if total >= 120 {
        3
    } else if total >= 90 {
        2
    } else {
        1
    };
    let usable = total.saturating_sub(gap * 2);
    let col1 = usable / 3;
    let col2 = usable / 3;
    let col3 = usable.saturating_sub(col1 + col2);
    let c1 = truncate_with_ellipsis(&cells[0], col1);
    let c2 = truncate_with_ellipsis(&cells[1], col2);
    let c3 = truncate_with_ellipsis(&cells[2], col3);
    let line = format!(
        "{}{}{}{}{}",
        pad_to_width(&c1, col1),
        " ".repeat(gap),
        pad_to_width(&c2, col2),
        " ".repeat(gap),
        c3
    );
    Line::from(vec![Span::raw(line)])
}

fn filter_summary_one_line_text(app: &App) -> String {
    format!(
        "F1 svc={} | F2 port={} | F3 ip={} | F4 action={} | F5 proto={} | F6 text={} ({} active)",
        display_filter_value(&app.filters.service),
        display_filter_value(&app.filters.port),
        display_filter_value(&app.filters.ip),
        display_filter_value(&app.filters.action),
        display_filter_value(&app.filters.proto),
        display_filter_value(&app.filters.text),
        app.filters.active_count()
    )
}

fn filter_summary_line_count(app: &App, width: u16) -> u16 {
    let one_line = filter_summary_one_line_text(app);
    if text_cells(&one_line) <= width { 1 } else { 2 }
}

fn filter_summary_lines(app: &App, width: u16) -> Vec<Line<'static>> {
    let one_line = filter_summary_one_line_text(app);
    if text_cells(&one_line) <= width {
        return vec![Line::from(one_line)];
    }

    let row1 = build_three_column_line(
        width,
        [
            format!("F1 svc={}", display_filter_value(&app.filters.service)),
            format!("F2 port={}", display_filter_value(&app.filters.port)),
            format!("F3 ip={}", display_filter_value(&app.filters.ip)),
        ],
    );
    let row2 = build_three_column_line(
        width,
        [
            format!("F4 action={}", display_filter_value(&app.filters.action)),
            format!("F5 proto={}", display_filter_value(&app.filters.proto)),
            format!(
                "F6 text={} ({} active)",
                display_filter_value(&app.filters.text),
                app.filters.active_count()
            ),
        ],
    );
    vec![row1, row2]
}

fn filter_panel_height(app: &App, width: u16) -> u16 {
    // Keep the rendered filter panel height and mouse-hitbox rows in sync.
    let summary_rows = filter_summary_line_count(app, width);
    let controls_rows = if controls_layout(app, width).0 { 1 } else { 2 };
    summary_rows.saturating_add(controls_rows)
}

fn rect_contains(rect: Rect, x: u16, y: u16) -> bool {
    x >= rect.x
        && x < rect.x.saturating_add(rect.width)
        && y >= rect.y
        && y < rect.y.saturating_add(rect.height)
}

fn push_toggle_hitbox(
    hitboxes: &mut Vec<(Rect, ToggleTarget)>,
    x: u16,
    y: u16,
    label: &str,
    target: ToggleTarget,
    bounds: Rect,
) {
    let width = text_cells(label);
    if width == 0 {
        return;
    }
    let end_x = x.saturating_add(width);
    let bounds_end_x = bounds.x.saturating_add(bounds.width);
    if x >= bounds_end_x || end_x <= bounds.x || !rect_contains(bounds, x.max(bounds.x), y) {
        return;
    }
    let rect_x = x.max(bounds.x);
    let rect_end_x = end_x.min(bounds_end_x);
    let rect_width = rect_end_x.saturating_sub(rect_x);
    if rect_width == 0 {
        return;
    }
    hitboxes.push((
        Rect {
            x: rect_x,
            y,
            width: rect_width,
            height: 1,
        },
        target,
    ));
}

fn build_toggle_hitboxes(app: &App, filters_area: Rect) -> Vec<(Rect, ToggleTarget)> {
    if filters_area.height < 2 || filters_area.width == 0 {
        return Vec::new();
    }
    let mut hitboxes = Vec::new();
    let (combined, visible_ifaces, iface_right_start) = controls_layout(app, filters_area.width);
    let summary_rows = filter_summary_line_count(app, filters_area.width);
    let toggles_y = filters_area.y.saturating_add(summary_rows);
    let mut x = filters_area.x;

    let local = "[local]";
    push_toggle_hitbox(
        &mut hitboxes,
        x,
        toggles_y,
        local,
        ToggleTarget::Local,
        filters_area,
    );
    x = x.saturating_add(text_cells(local)).saturating_add(1);

    let wan = "[wan]";
    push_toggle_hitbox(
        &mut hitboxes,
        x,
        toggles_y,
        wan,
        ToggleTarget::WanSrc,
        filters_area,
    );
    x = x.saturating_add(text_cells(wan)).saturating_add(1);

    let flow = app.flow_filter.chip();
    push_toggle_hitbox(
        &mut hitboxes,
        x,
        toggles_y,
        flow,
        ToggleTarget::Flow,
        filters_area,
    );
    x = x.saturating_add(text_cells(flow)).saturating_add(2);

    let dir = app.direction_filter.chip();
    push_toggle_hitbox(
        &mut hitboxes,
        x,
        toggles_y,
        dir,
        ToggleTarget::Direction,
        filters_area,
    );

    let iface_y = if combined {
        toggles_y
    } else if filters_area.height > summary_rows.saturating_add(1) {
        toggles_y.saturating_add(1)
    } else {
        return hitboxes;
    };
    let iface_start_x = if combined {
        filters_area.x.saturating_add(iface_right_start)
    } else {
        filters_area.x
    };
    let mut iface_x =
        iface_start_x.saturating_add(text_cells(interface_prefix(filters_area.width)));

    let all_label = if app.selected_interface.is_none() {
        "[all]"
    } else {
        "all"
    };
    push_toggle_hitbox(
        &mut hitboxes,
        iface_x,
        iface_y,
        all_label,
        ToggleTarget::AllIfaces,
        filters_area,
    );
    iface_x = iface_x.saturating_add(text_cells(all_label));

    for iface in app.interface_options.iter().take(visible_ifaces) {
        iface_x = iface_x.saturating_add(1);
        let selected = app.selected_interface.as_deref() == Some(iface.as_str());
        let label = if selected {
            format!("[{}]", iface)
        } else {
            iface.clone()
        };
        push_toggle_hitbox(
            &mut hitboxes,
            iface_x,
            iface_y,
            &label,
            ToggleTarget::Interface(iface.clone()),
            filters_area,
        );
        iface_x = iface_x.saturating_add(text_cells(&label));
    }

    hitboxes
}

fn build_header_hitboxes(app: &App, header_area: Rect) -> Vec<(Rect, ToggleTarget)> {
    if header_area.width == 0 || header_area.height == 0 {
        return Vec::new();
    }
    let mut hitboxes = Vec::new();
    let y = header_area.y;
    let x = header_area.x.saturating_add(text_cells(APP_TITLE) + 1);
    let chip = pause_chip_label(app.updates_paused);
    push_toggle_hitbox(
        &mut hitboxes,
        x,
        y,
        chip,
        ToggleTarget::PauseUpdates,
        header_area,
    );
    hitboxes
}

fn apply_toggle_target(app: &mut App, target: ToggleTarget) {
    match target {
        ToggleTarget::Local => app.toggle_show_local_src(),
        ToggleTarget::WanSrc => app.toggle_show_wan_src(),
        ToggleTarget::Flow => app.cycle_flow_filter(),
        ToggleTarget::Direction => app.cycle_direction_filter(),
        ToggleTarget::PauseUpdates => app.toggle_pause_updates(),
        ToggleTarget::AllIfaces => app.select_all_interfaces(),
        ToggleTarget::Interface(name) => {
            app.set_selected_interface(Some(name));
            let matches = app.filtered_indices().len();
            app.status = format!(
                "Interface: {}. Matching rows: {}",
                selected_iface_label(app.selected_interface.as_deref()),
                matches
            );
        }
    }
}

fn handle_mouse_event(app: &mut App, mouse: MouseEvent, area: Rect) {
    let filters_height = filter_panel_height(app, area.width);
    let chunks = main_chunks(area, filters_height);
    let mouse_x = mouse.column;
    let mouse_y = mouse.row;

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            for (rect, target) in build_header_hitboxes(app, chunks[0]) {
                if rect_contains(rect, mouse_x, mouse_y) {
                    apply_toggle_target(app, target);
                    return;
                }
            }

            for (rect, target) in build_toggle_hitboxes(app, chunks[1]) {
                if rect_contains(rect, mouse_x, mouse_y) {
                    apply_toggle_target(app, target);
                    return;
                }
            }

            let table_area = chunks[2];
            if rect_contains(table_area, mouse_x, mouse_y) && table_area.height >= 3 {
                let rows_start_y = table_area.y + 2;
                let rows_end_y = table_area.y + table_area.height - 1;
                if mouse_y >= rows_start_y && mouse_y < rows_end_y {
                    let visible_row_index = (mouse_y - rows_start_y) as usize;
                    app.select_visible_row_index(visible_row_index);
                }
            }
        }
        MouseEventKind::ScrollUp => {
            let table_area = chunks[2];
            if rect_contains(table_area, mouse_x, mouse_y) {
                let filtered_len = app.filtered_indices().len();
                if filtered_len > 0 {
                    app.selected = app.selected.saturating_sub(1);
                    app.sync_selection_with_len(filtered_len);
                }
            }
        }
        MouseEventKind::ScrollDown => {
            let table_area = chunks[2];
            if rect_contains(table_area, mouse_x, mouse_y) {
                let filtered_len = app.filtered_indices().len();
                if filtered_len > 0 {
                    app.selected = min(app.selected + 1, filtered_len.saturating_sub(1));
                    app.sync_selection_with_len(filtered_len);
                }
            }
        }
        _ => {}
    }
}

fn ui(frame: &mut Frame, app: &mut App) {
    app.refresh_status_lifetime();
    let area = frame.area();
    if area.width < MIN_UI_WIDTH || area.height < MIN_UI_HEIGHT {
        let target_w = min(area.width.saturating_sub(2), 56).max(20);
        let target_h = min(area.height.saturating_sub(2), 7).max(5);
        let vpad = area.height.saturating_sub(target_h) / 2;
        let hpad = area.width.saturating_sub(target_w) / 2;
        let popup = Rect {
            x: area.x.saturating_add(hpad),
            y: area.y.saturating_add(vpad),
            width: target_w,
            height: target_h,
        };
        let msg = Paragraph::new(vec![
            Line::from(format!(
                "Terminal too small: {}x{}",
                area.width, area.height
            )),
            Line::from(format!("Need at least {}x{}", MIN_UI_WIDTH, MIN_UI_HEIGHT)),
            Line::from("Resize terminal to continue"),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(APP_TITLE));
        frame.render_widget(msg, popup);
        return;
    }

    let filters_height = filter_panel_height(app, area.width);
    let chunks = main_chunks(area, filters_height);

    let filtered_indices = app.filtered_indices();
    app.sync_selection_with_len(filtered_indices.len());
    let count_text = format!("{}/{}", filtered_indices.len(), app.entries.len());
    let live_style = if app.updates_paused {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default()
            .fg(Color::LightGreen)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    };
    let pause_chip_width = text_cells("[live]").max(text_cells("[paused]"));
    let left_width = text_cells(APP_TITLE)
        .saturating_add(1)
        .saturating_add(pause_chip_width);
    let count_width = text_cells(&count_text);
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(left_width),
            Constraint::Min(1),
            Constraint::Length(count_width),
        ])
        .split(chunks[0]);

    let header_left = Paragraph::new(Line::from(vec![
        Span::styled(APP_TITLE, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(pause_chip_label(app.updates_paused), live_style),
    ]));
    frame.render_widget(header_left, header_chunks[0]);

    let center_text = if app.status.is_empty() {
        app.log_path.display().to_string()
    } else {
        app.status.clone()
    };
    let center_style = if app.status.to_ascii_lowercase().contains("failed") {
        Style::default().fg(Color::LightRed)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let header_center = Paragraph::new(Line::from(Span::styled(center_text, center_style)))
        .alignment(Alignment::Center);
    frame.render_widget(header_center, header_chunks[1]);

    let header_count = Paragraph::new(Line::from(Span::styled(
        count_text,
        Style::default().fg(Color::Yellow),
    )))
    .alignment(Alignment::Right);
    frame.render_widget(header_count, header_chunks[2]);

    let filter_summary = filter_summary_lines(app, chunks[1].width);
    let (combined_controls, visible_ifaces, iface_right_start) =
        controls_layout(app, chunks[1].width);
    let mut control_line_spans = left_toggle_spans(app);
    if combined_controls {
        let gap = iface_right_start.saturating_sub(left_toggle_width(app));
        control_line_spans.push(Span::raw(" ".repeat(gap as usize)));
        control_line_spans.extend(interface_display_spans(
            app,
            visible_ifaces,
            chunks[1].width,
        ));
    }
    let mut filter_lines = filter_summary;
    filter_lines.push(Line::from(control_line_spans));
    if !combined_controls {
        filter_lines.push(Line::from(interface_display_spans(
            app,
            visible_ifaces,
            chunks[1].width,
        )));
    }
    let filters = Paragraph::new(filter_lines);
    frame.render_widget(filters, chunks[1]);

    let selected = app.selected;
    let entries = &app.entries;
    let table_width = chunks[2].width;
    let show_date_in_time_col = chunks[2].width >= 120;
    let show_service_description = table_width >= 150;
    let rows = filtered_indices.iter().map(|entry_idx| {
        let entry = &entries[*entry_idx];

        let action_color = match entry.action.as_str() {
            "ALLOW" => Color::Green,
            "BLOCK" => Color::Red,
            _ => Color::Yellow,
        };
        let direction = entry.direction();
        let dir_color = match direction {
            "IN" => Color::LightBlue,
            "OUT" => Color::LightMagenta,
            "FWD" => Color::LightCyan,
            _ => Color::DarkGray,
        };

        Row::new(vec![
            Cell::from(format_timestamp_for_width(
                &entry.timestamp,
                show_date_in_time_col,
            )),
            Cell::from(entry.action.clone()).style(Style::default().fg(action_color)),
            Cell::from(direction).style(Style::default().fg(dir_color)),
            Cell::from(entry.src_ip.as_deref().unwrap_or("-").to_string()),
            Cell::from(entry.dst_ip.as_deref().unwrap_or("-").to_string()),
            Cell::from(entry.proto.as_deref().unwrap_or("-").to_string()),
            Cell::from(
                entry
                    .src_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::from(
                entry
                    .dst_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::from(service_display_for_entry(entry, show_service_description)),
        ])
    });

    let time_col = if show_date_in_time_col { 16 } else { 8 };
    let (action_col, dir_col, proto_col, port_col, src_weight, dst_weight, service_weight) =
        if table_width >= 150 {
            (8, 5, 6, 6, 5, 5, 3)
        } else if table_width >= 120 {
            (7, 4, 5, 5, 4, 4, 2)
        } else {
            (6, 3, 4, 5, 3, 3, 2)
        };
    let columns = [
        Constraint::Length(time_col),
        Constraint::Length(action_col),
        Constraint::Length(dir_col),
        Constraint::Fill(src_weight),
        Constraint::Fill(dst_weight),
        Constraint::Length(proto_col),
        Constraint::Length(port_col),
        Constraint::Length(port_col),
        Constraint::Fill(service_weight),
    ];

    let table = Table::new(rows, columns)
        .header(
            Row::new(vec![
                if show_date_in_time_col {
                    "Date/Time"
                } else {
                    "Time"
                },
                "Action",
                "Dir",
                "Source",
                "Dest",
                "Proto",
                "SPT",
                "DPT",
                "Service",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title("UFW Events"))
        .row_highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(table, chunks[2], &mut app.table_state);

    let detail = if let Some(field) = app.input_mode {
        format!(
            "Edit {}: {} (Enter apply, Esc cancel)",
            field.label(),
            if app.input_buffer.is_empty() {
                "_"
            } else {
                &app.input_buffer
            }
        )
    } else if filtered_indices.is_empty() {
        "No rows match current view (filters/interface/local+wan/flow/dir).".to_string()
    } else {
        let current = &app.entries[filtered_indices[selected]];
        current.raw.clone()
    };
    let detail_title = if app.input_mode.is_some() {
        "Edit Filter"
    } else {
        "Log Entry"
    };
    let detail_content_width = chunks[3].width.saturating_sub(2);
    let detail_max_scroll = max_horizontal_scroll(&detail, detail_content_width);
    app.log_entry_scroll = min(app.log_entry_scroll, detail_max_scroll);
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(detail_title))
            .scroll((0, app.log_entry_scroll)),
        chunks[3],
    );

    let help = Paragraph::new(footer_help_lines(chunks[4].width)).wrap(Wrap { trim: true });
    frame.render_widget(help, chunks[4]);
}

fn resolve_log_path_from_args() -> PathBuf {
    let arg_path = std::env::args().nth(1).map(PathBuf::from);
    if let Some(path) = arg_path {
        return path;
    }

    let preferred = PathBuf::from("/var/log/ufw-firewall.log");
    if preferred.exists() {
        return preferred;
    }

    let fallback = PathBuf::from("/var/log/ufw.log");
    if fallback.exists() {
        return fallback;
    }

    PathBuf::from("/var/log/kern.log")
}

fn run_app() -> Result<(), Box<dyn std::error::Error>> {
    struct TerminalCleanup;
    impl Drop for TerminalCleanup {
        fn drop(&mut self) {
            let _ = disable_raw_mode();
            let mut stdout = io::stdout();
            let _ = execute!(
                stdout,
                Show,
                DisableMouseCapture,
                terminal::LeaveAlternateScreen
            );
        }
    }

    let log_path = resolve_log_path_from_args();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen, EnableMouseCapture)?;
    let _cleanup = TerminalCleanup;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(log_path);

    'mainloop: loop {
        app.maybe_reload();
        terminal.draw(|frame| ui(frame, &mut app))?;
        if event::poll(Duration::from_millis(250))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
                    {
                        app.copy_selected_log_entry();
                        continue;
                    }

                    if let Some(field) = app.input_mode {
                        match key.code {
                            KeyCode::Esc => {
                                app.input_mode = None;
                                app.input_buffer.clear();
                            }
                            KeyCode::Enter => {
                                app.set_filter_value(field, app.input_buffer.clone());
                                let current_value = app.get_filter_value(field).to_string();
                                let matches = app.filtered_indices().len();
                                app.status = if current_value.is_empty() {
                                    format!(
                                        "Removed {} filter. Matching rows: {}",
                                        field.label(),
                                        matches
                                    )
                                } else {
                                    format!(
                                        "Set {} filter='{}'. Matching rows: {}",
                                        field.label(),
                                        current_value,
                                        matches
                                    )
                                };
                                app.input_mode = None;
                                app.input_buffer.clear();
                            }
                            KeyCode::Backspace => {
                                app.input_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                app.input_buffer.push(c);
                            }
                            _ => {}
                        }
                        continue;
                    }

                    if handle_modifier_shortcuts(&mut app, &key) {
                        continue;
                    }

                    if (key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('i') | KeyCode::Char('I')))
                        || matches!(key.code, KeyCode::Tab)
                    {
                        app.copy_selected_src_ip();
                        continue;
                    }

                    let filtered_len = app.filtered_indices().len();
                    match key.code {
                        KeyCode::Char('q') => break 'mainloop,
                        KeyCode::Char('r') => {
                            let _ = app.reload();
                        }
                        KeyCode::Char('a') | KeyCode::Char('A') => app.toggle_pause_updates(),
                        KeyCode::Char('c') => app.clear_filters(),
                        KeyCode::Char('l') | KeyCode::Char('L') => app.toggle_show_local_src(),
                        KeyCode::Char('p') | KeyCode::Char('P') => app.toggle_show_wan_src(),
                        KeyCode::Char('f') | KeyCode::Char('F') => app.cycle_flow_filter(),
                        KeyCode::Char('d') | KeyCode::Char('D') => app.cycle_direction_filter(),
                        KeyCode::Char(',') => app.cycle_interface(false),
                        KeyCode::Char('.') => app.cycle_interface(true),
                        KeyCode::Char('0') => app.select_all_interfaces(),
                        KeyCode::Char('w') | KeyCode::Char('W') => {
                            app.select_default_wan_interface()
                        }
                        KeyCode::Left => app.scroll_log_entry_left(),
                        KeyCode::Right => app.scroll_log_entry_right(),
                        KeyCode::Up | KeyCode::Char('k') => {
                            if filtered_len > 0 {
                                app.selected = app.selected.saturating_sub(1);
                                app.sync_selection_with_len(filtered_len);
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if filtered_len > 0 {
                                app.selected =
                                    min(app.selected + 1, filtered_len.saturating_sub(1));
                                app.sync_selection_with_len(filtered_len);
                            }
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    let size = terminal.size()?;
                    handle_mouse_event(
                        &mut app,
                        mouse,
                        Rect {
                            x: 0,
                            y: 0,
                            width: size.width,
                            height: size.height,
                        },
                    );
                }
                _ => {
                    continue;
                }
            }
        }
    }

    terminal.show_cursor()?;

    Ok(())
}

fn main() {
    if let Err(err) = run_app() {
        eprintln!("Error: {}", err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ufw_line_extracts_core_fields() {
        let line = "Feb 11 20:21:00 host kernel: [UFW BLOCK] IN=wlan0 OUT= MAC= SRC=10.0.0.5 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=443 DPT=52910 WINDOW=64240 RES=0x00 ACK URGP=0";
        let entry = parse_ufw_line(line).expect("line should parse");
        assert_eq!(entry.action, "BLOCK");
        assert_eq!(entry.src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(entry.dst_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(entry.proto.as_deref(), Some("TCP"));
        assert_eq!(entry.src_port, Some(443));
        assert_eq!(entry.dst_port, Some(52910));
        assert_eq!(entry.service.as_deref(), Some("https"));
    }

    #[test]
    fn filters_match_expected_fields() {
        let entry = LogEntry {
            timestamp: "Feb 11 20:21:00".to_string(),
            action: "ALLOW".to_string(),
            in_iface: Some("eth0".to_string()),
            out_iface: Some("".to_string()),
            src_ip: Some("1.2.3.4".to_string()),
            dst_ip: Some("10.0.0.1".to_string()),
            src_port: Some(51234),
            dst_port: Some(22),
            proto: Some("TCP".to_string()),
            service: Some("ssh".to_string()),
            raw: "raw log line".to_string(),
        };

        let mut filters = Filters {
            service: "ssh".to_string(),
            port: "22".to_string(),
            ip: "1.2.3".to_string(),
            action: "allow".to_string(),
            proto: "tcp".to_string(),
            ..Default::default()
        };
        assert!(filters.matches(&entry));

        filters.port = "443".to_string();
        assert!(!filters.matches(&entry));
    }

    #[test]
    fn local_src_ip_detection_works_for_common_ranges() {
        assert!(is_local_src_ip(Some("192.168.1.10")));
        assert!(is_local_src_ip(Some("10.1.2.3")));
        assert!(is_local_src_ip(Some("172.16.0.1")));
        assert!(is_local_src_ip(Some("172.31.255.254")));
        assert!(is_local_src_ip(Some("127.0.0.1")));
        assert!(is_local_src_ip(Some("169.254.20.1")));
        assert!(is_local_src_ip(Some("::1")));
        assert!(is_local_src_ip(Some("fe80::1234")));
        assert!(is_local_src_ip(Some("fd12::abcd")));

        assert!(!is_local_src_ip(Some("8.8.8.8")));
        assert!(!is_local_src_ip(Some("1.1.1.1")));
        assert!(!is_local_src_ip(Some("2001:4860:4860::8888")));
        assert!(!is_local_src_ip(None));
        assert!(!is_local_src_ip(Some("")));
    }

    #[test]
    fn wan_src_ip_detection_works() {
        assert!(is_wan_src_ip(Some("8.8.8.8")));
        assert!(is_wan_src_ip(Some("1.1.1.1")));
        assert!(is_wan_src_ip(Some("2001:4860:4860::8888")));

        assert!(!is_wan_src_ip(Some("192.168.1.10")));
        assert!(!is_wan_src_ip(Some("10.1.2.3")));
        assert!(!is_wan_src_ip(Some("172.16.0.1")));
        assert!(!is_wan_src_ip(Some("127.0.0.1")));
        assert!(!is_wan_src_ip(Some("::1")));
        assert!(!is_wan_src_ip(Some("fe80::1")));
        assert!(!is_wan_src_ip(None));
        assert!(!is_wan_src_ip(Some("")));
        assert!(!is_wan_src_ip(Some("not-an-ip")));
    }

    #[test]
    fn flow_filter_matches_local_to_local_and_local_to_external() {
        let mut entry = LogEntry {
            src_ip: Some("192.168.1.10".to_string()),
            dst_ip: Some("192.168.1.20".to_string()),
            ..Default::default()
        };
        assert!(matches_flow_filter(FlowFilter::All, &entry));
        assert!(matches_flow_filter(FlowFilter::LocalToLocal, &entry));
        assert!(!matches_flow_filter(FlowFilter::LocalToExternal, &entry));

        entry.dst_ip = Some("8.8.8.8".to_string());
        assert!(matches_flow_filter(FlowFilter::LocalToExternal, &entry));
        assert!(!matches_flow_filter(FlowFilter::LocalToLocal, &entry));
    }

    #[test]
    fn default_wan_interface_prefers_wan_like_names() {
        let options = vec![
            "docker0".to_string(),
            "lo".to_string(),
            "wlan0".to_string(),
            "br-123".to_string(),
        ];
        assert_eq!(default_wan_interface(&options).as_deref(), Some("wlan0"));

        let options = vec!["docker0".to_string(), "lo".to_string()];
        assert_eq!(default_wan_interface(&options).as_deref(), Some("docker0"));
    }

    #[test]
    fn selected_position_for_raw_finds_matching_row_in_filtered_view() {
        let entries = vec![
            LogEntry {
                raw: "newest".to_string(),
                ..Default::default()
            },
            LogEntry {
                raw: "kept".to_string(),
                ..Default::default()
            },
            LogEntry {
                raw: "older".to_string(),
                ..Default::default()
            },
        ];
        let filtered = vec![0, 1, 2];
        assert_eq!(
            selected_position_for_raw(&entries, &filtered, "kept"),
            Some(1)
        );
        assert_eq!(
            selected_position_for_raw(&entries, &filtered, "missing"),
            None
        );
    }
}
