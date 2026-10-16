#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Align, Align2, Color32, Layout, RichText};
use nfc_studio::apdu::{self, KeyType};
use nfc_studio::card::{CardInfo, CardKind, Reader};
use nfc_studio::ndef::{Record, RecordKind, WriteKind};
use nfc_studio::tag::{self, ReadOutcome, TagContent, Transport};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(600);
const ACCENT: Color32 = Color32::from_rgb(37, 99, 235);
const GOOD: Color32 = Color32::from_rgb(22, 163, 74);
const BAD: Color32 = Color32::from_rgb(220, 38, 38);

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("NFC Studio")
        .with_inner_size([1000.0, 720.0])
        .with_min_inner_size([720.0, 520.0]);
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon-256.png")) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "NFC Studio",
        options,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            Ok(Box::new(App::new()))
        }),
    )
}

fn setup_style(ctx: &egui::Context) {
    use egui::{FontId, TextStyle};
    ctx.all_styles_mut(|s| {
        s.text_styles.insert(TextStyle::Heading, FontId::proportional(24.0));
        s.text_styles.insert(TextStyle::Body, FontId::proportional(15.0));
        s.text_styles.insert(TextStyle::Button, FontId::proportional(15.0));
        s.text_styles.insert(TextStyle::Small, FontId::proportional(12.5));
        s.text_styles.insert(TextStyle::Monospace, FontId::monospace(13.5));
        s.spacing.item_spacing = egui::vec2(10.0, 8.0);
        s.spacing.button_padding = egui::vec2(12.0, 6.0);
    });
}

fn section(ui: &egui::Ui) -> egui::Frame {
    egui::Frame::none()
        .fill(ui.visuals().faint_bg_color)
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .rounding(10.0)
        .inner_margin(16.0)
}

fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).size(16.0).strong().color(Color32::WHITE))
        .fill(ACCENT)
        .min_size(egui::vec2(170.0, 38.0))
}

fn push_log(log: &mut Vec<String>, msg: impl Into<String>) {
    log.push(msg.into());
    if log.len() > 500 {
        log.drain(..100);
    }
}

/// Turns low-level reader errors into something a person can act on.
fn friendly_error(e: &str) -> String {
    let lower = e.to_lowercase();
    if lower.contains("no card present") || lower.contains("removed") || lower.contains("not connected") || lower.contains("reset") {
        "The card was moved away from the reader. Place it back, hold it still and try again.".into()
    } else if lower.contains("writing stopped") {
        "Writing stopped part-way. Hold the card still on the reader and try again.".into()
    } else if e.starts_with("Card returned") || e.starts_with("Transmit failed") || lower.contains("reactivate") {
        "The card didn't respond as expected. Hold it still on the reader and try again.".into()
    } else {
        e.to_string()
    }
}

/// Sends commands through the reader and records them in the advanced log.
struct Link<'a> {
    reader: &'a mut Reader,
    log: &'a mut Vec<String>,
}

impl Transport for Link<'_> {
    fn transmit(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let resp = self.reader.transmit(cmd);
        match &resp {
            Ok(r) => push_log(self.log, format!(">> {}\n<< {}", apdu::to_hex(cmd), apdu::to_hex(r))),
            Err(e) => push_log(self.log, format!(">> {}\n!! {e}", apdu::to_hex(cmd))),
        }
        resp
    }

    fn reactivate(&mut self) -> Result<(), String> {
        push_log(self.log, "Reactivating card");
        self.reader.reactivate()
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Apdu,
    Classic,
    Ultralight,
}

#[derive(PartialEq, Clone, Copy)]
enum Action {
    Write,
    Erase,
    Format,
}

struct Notice {
    ok: bool,
    text: String,
    at: Instant,
}

struct App {
    reader: Option<Reader>,
    readers: Vec<String>,
    selected: usize,
    card_present: bool,
    info: Option<CardInfo>,
    connect_error: Option<String>,
    contents: Option<Result<ReadOutcome, String>>,
    last_poll: Option<Instant>,

    write_kind: WriteKind,
    write_text: String,
    notice: Option<Notice>,
    confirm: Option<Action>,

    advanced: bool,
    tab: Tab,
    log: Vec<String>,
    apdu_input: String,
    key_hex: String,
    key_type: KeyType,
    block: u8,
    block_data: String,
    allow_trailer: bool,
    page: u8,
    page_data: String,
}

impl App {
    fn new() -> Self {
        Self {
            reader: None,
            readers: Vec::new(),
            selected: 0,
            card_present: false,
            info: None,
            connect_error: None,
            contents: None,
            last_poll: None,
            write_kind: WriteKind::Text,
            write_text: String::new(),
            notice: None,
            confirm: None,
            advanced: false,
            tab: Tab::Apdu,
            log: Vec::new(),
            apdu_input: "FF CA 00 00 00".into(),
            key_hex: "FFFFFFFFFFFF".into(),
            key_type: KeyType::A,
            block: 4,
            block_data: String::new(),
            allow_trailer: false,
            page: 4,
            page_data: String::new(),
        }
    }

    fn log(&mut self, msg: impl Into<String>) {
        push_log(&mut self.log, msg);
    }

    fn notify(&mut self, ok: bool, text: impl Into<String>) {
        self.notice = Some(Notice { ok, text: text.into(), at: Instant::now() });
    }

    // ---- Reader / card lifecycle -------------------------------------------

    /// Detects readers and cards being plugged in, placed or removed.
    fn poll(&mut self) {
        if self.reader.is_none() {
            match Reader::new() {
                Ok(r) => self.reader = Some(r),
                Err(_) => {
                    self.readers.clear();
                    self.forget_card();
                    return;
                }
            }
        }
        let Some(reader) = self.reader.as_ref() else { return };
        match reader.list_readers() {
            Ok(list) if list != self.readers => {
                let current = self.readers.get(self.selected).cloned();
                self.selected = current.and_then(|c| list.iter().position(|r| *r == c)).unwrap_or(0);
                self.log(format!("Readers: {}", if list.is_empty() { "none".into() } else { list.join(", ") }));
                self.readers = list;
                self.forget_card();
            }
            Ok(_) => {}
            Err(e) => {
                // The PC/SC service can go away when the last reader is unplugged; start over.
                self.log(e);
                self.reader = None;
                self.readers.clear();
                self.forget_card();
                return;
            }
        }
        let Some(reader) = self.reader.as_ref() else { return };
        let has_card = |name: &String| reader.card_present(name).unwrap_or(false);
        if !self.card_present {
            // Follow the card: switch to whichever reader it was placed on.
            if let Some(i) = self.readers.iter().position(has_card) {
                self.selected = i;
            }
        }
        let Some(name) = self.readers.get(self.selected).cloned() else { return };
        let present = has_card(&name);
        if present && !self.card_present {
            self.card_present = true;
            self.connect_and_read();
        } else if !present && self.card_present {
            self.forget_card();
        }
    }

    fn forget_card(&mut self) {
        if self.info.take().is_some() {
            if let Some(r) = self.reader.as_mut() {
                r.disconnect();
            }
            self.log("Card removed");
        }
        self.card_present = false;
        self.connect_error = None;
        self.contents = None;
        self.confirm = None;
    }

    fn connect_and_read(&mut self) {
        let Some(name) = self.readers.get(self.selected).cloned() else { return };
        let Some(reader) = self.reader.as_mut() else { return };
        match reader.connect(&name) {
            Ok(info) => {
                let msg = format!(
                    "Connected: {} | ATR {} | UID {}",
                    info.kind.label(),
                    apdu::to_hex(&info.atr),
                    info.uid.as_deref().map(apdu::to_hex).unwrap_or_else(|| "?".into())
                );
                self.log(msg);
                self.info = Some(info);
                self.connect_error = None;
                self.read_contents();
            }
            Err(e) => {
                self.log(format!("Connect failed: {e}"));
                self.info = None;
                self.connect_error = Some(friendly_error(&e));
            }
        }
    }

    fn read_contents(&mut self) {
        let Some(kind) = self.info.as_ref().map(|i| i.kind) else { return };
        let techs = kind.techs();
        if techs.is_empty() {
            self.contents = Some(Ok(ReadOutcome::Unsupported(kind.description().into())));
            return;
        }
        let App { reader: Some(reader), log, .. } = self else { return };
        let mut link = Link { reader, log };
        let mut result = Err(String::new());
        for tech in techs {
            result = tag::read(&mut link, tech);
            if matches!(result, Ok(ReadOutcome::Ndef(_) | ReadOutcome::ClassicBlank)) {
                break;
            }
        }
        self.contents = Some(result.map_err(|e| friendly_error(&e)));
    }

    fn ndef_content(&self) -> Option<&TagContent> {
        match &self.contents {
            Some(Ok(ReadOutcome::Ndef(c))) => Some(c),
            _ => None,
        }
    }

    fn run(&mut self, action: Action) {
        let result = match action {
            Action::Write => match self.write_kind.build(&self.write_text) {
                Ok(rec) => self.write_records(&[rec]).map(|_| "Saved to the card."),
                Err(e) => Err(e),
            },
            Action::Erase => self.write_records(&[]).map(|_| "The card is now empty."),
            Action::Format => self.format().map(|_| "The card is set up. You can now write to it."),
        };
        match result {
            Ok(msg) => {
                if action == Action::Write {
                    self.write_text.clear();
                }
                self.notify(true, msg);
            }
            Err(e) => self.notify(false, friendly_error(&e)),
        }
        self.read_contents();
    }

    fn write_records(&mut self, records: &[Record]) -> Result<(), String> {
        let tech = self.ndef_content().map(|c| c.tech).ok_or("Read the card first.")?;
        let App { reader: Some(reader), log, .. } = self else { return Err("No reader".into()) };
        tag::write(&mut Link { reader, log }, tech, records)
    }

    fn format(&mut self) -> Result<(), String> {
        let sectors = match self.info.as_ref().map(|i| i.kind) {
            Some(CardKind::MifareClassic1K) => 16,
            _ => return Err("Only MIFARE Classic 1K cards can be set up here.".into()),
        };
        let App { reader: Some(reader), log, .. } = self else { return Err("No reader".into()) };
        tag::format_classic(&mut Link { reader, log }, sectors)
    }

    // ---- Simple view ---------------------------------------------------------

    fn header_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("📶 NFC Studio").size(22.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.toggle_value(&mut self.advanced, "🛠 Advanced tools")
                    .on_hover_text("Low-level tools for raw commands, MIFARE blocks and NTAG pages");
                ui.separator();
                match self.readers.len() {
                    0 => {
                        ui.label(RichText::new("No reader").color(BAD));
                    }
                    1 => {
                        ui.label(RichText::new(&self.readers[0]).color(GOOD));
                    }
                    _ => {
                        let before = self.selected;
                        egui::ComboBox::from_id_salt("reader_combo")
                            .width(260.0)
                            .selected_text(self.readers[self.selected].clone())
                            .show_ui(ui, |ui| {
                                for (i, r) in self.readers.iter().enumerate() {
                                    ui.selectable_value(&mut self.selected, i, r);
                                }
                            });
                        if before != self.selected {
                            self.forget_card();
                        }
                    }
                }
                ui.label("Reader:");
            });
        });
    }

    fn notice_ui(&mut self, ui: &mut egui::Ui) {
        let Some(n) = &self.notice else { return };
        let mut close = false;
        egui::Frame::none()
            .fill(if n.ok { GOOD } else { BAD })
            .rounding(8.0)
            .inner_margin(egui::Margin::symmetric(14.0, 10.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let icon = if n.ok { "✔" } else { "⚠" };
                    ui.add(egui::Label::new(RichText::new(format!("{icon}  {}", n.text)).color(Color32::WHITE).size(15.0)).wrap());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.add(egui::Button::new(RichText::new("✕").color(Color32::WHITE)).frame(false)).clicked() {
                            close = true;
                        }
                    });
                });
            });
        ui.add_space(8.0);
        if close {
            self.notice = None;
        }
    }

    fn status_ui(&mut self, ui: &mut egui::Ui) {
        let reader_name = self.readers.get(self.selected).cloned();
        let (icon, title, subtitle) = match (&reader_name, &self.info) {
            (None, _) => (
                "🔌",
                "Connect an NFC reader".to_string(),
                "Plug a USB NFC or smart-card reader (for example an ACR122U) into this computer. \
                 It will be detected automatically."
                    .to_string(),
            ),
            (Some(_), None) if self.card_present => (
                "⚠",
                "Couldn't talk to the card".to_string(),
                format!(
                    "{} Lift the card off the reader and place it back.",
                    self.connect_error.clone().unwrap_or_default()
                ),
            ),
            (Some(name), None) => (
                "💳",
                "Place a card on the reader".to_string(),
                format!("Hold an NFC card, tag or sticker flat on “{name}”. It will be read automatically."),
            ),
            (Some(_), Some(info)) => ("✅", info.kind.friendly_name().to_string(), info.kind.description().to_string()),
        };
        let uid = self.info.as_ref().and_then(|i| i.uid.as_deref().map(apdu::to_hex));
        let kind_label = self.info.as_ref().filter(|i| i.kind != CardKind::Unknown).map(|i| i.kind.label());

        section(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon).size(44.0));
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).size(21.0).strong());
                    ui.add(egui::Label::new(RichText::new(subtitle).weak()).wrap());
                    if let Some(uid) = uid {
                        ui.horizontal(|ui| {
                            ui.label("Card ID:");
                            ui.label(RichText::new(&uid).monospace().strong());
                            if ui.small_button("📋 Copy").on_hover_text("Copy the card ID").clicked() {
                                ui.ctx().copy_text(uid.replace(' ', ""));
                                self.notify(true, "Card ID copied.");
                            }
                            if let Some(kind) = kind_label {
                                ui.label(RichText::new(format!("·  {kind}")).weak());
                            }
                        });
                    }
                });
            });
        });
    }

    fn contents_ui(&mut self, ui: &mut egui::Ui) {
        let contents = self.contents.clone();
        let kind = self.info.as_ref().map(|i| i.kind);
        section(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("📖 On this card").size(18.0).strong());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("⟳ Read again").clicked() {
                        self.read_contents();
                    }
                });
            });
            ui.add_space(4.0);
            match contents {
                None => {
                    ui.weak("Reading…");
                }
                Some(Err(e)) => {
                    ui.add(egui::Label::new(RichText::new(format!("⚠ {e}")).color(BAD)).wrap());
                }
                Some(Ok(ReadOutcome::Unsupported(msg))) => {
                    ui.add(egui::Label::new(format!("ℹ {msg}")).wrap());
                }
                Some(Ok(ReadOutcome::ClassicBlank)) => {
                    ui.label(RichText::new("This card is blank.").size(16.0));
                    ui.add(
                        egui::Label::new(
                            "It isn't set up to hold messages yet. Setting it up takes a few seconds and lets \
                             phones and this app read and write it.",
                        )
                        .wrap(),
                    );
                    ui.add_space(4.0);
                    if kind == Some(CardKind::MifareClassic1K) {
                        if ui.add(primary("✨ Set up card")).clicked() {
                            self.confirm = Some(Action::Format);
                        }
                    } else {
                        ui.weak("Setting up this size of MIFARE Classic card isn't supported.");
                    }
                }
                Some(Ok(ReadOutcome::Ndef(c))) => {
                    if c.records.is_empty() {
                        ui.add_space(6.0);
                        ui.label(RichText::new("This card is empty.").size(16.0));
                        ui.weak("Use “Write to card” to put a website, text, phone number or email on it.");
                        ui.add_space(6.0);
                    } else {
                        for rec in &c.records {
                            self.record_ui(ui, rec);
                        }
                    }
                    ui.add_space(4.0);
                    let frac = c.used as f32 / c.capacity.max(1) as f32;
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .text(format!("{} of {} bytes used", c.used, c.capacity)),
                    );
                    if !c.writable {
                        ui.label("🔒 This card is locked, so its contents can't be changed.");
                    }
                }
            }
        });
    }

    fn record_ui(&mut self, ui: &mut egui::Ui, rec: &Record) {
        let kind = rec.kind();
        let summary = rec.summary();
        egui::Frame::none()
            .fill(ui.visuals().extreme_bg_color)
            .rounding(8.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(kind.icon()).size(26.0));
                    ui.vertical(|ui| {
                        ui.label(RichText::new(kind.label()).small().weak());
                        ui.add(egui::Label::new(RichText::new(&summary).size(16.0)).wrap());
                        ui.horizontal(|ui| {
                            if let Some(url) = rec.open_target() {
                                let label = match kind {
                                    RecordKind::Phone => "📞 Call",
                                    RecordKind::Email => "✉ Send email",
                                    RecordKind::Sms => "💬 Message",
                                    _ => "🌐 Open",
                                };
                                if ui.small_button(label).clicked() {
                                    ui.ctx().open_url(egui::OpenUrl::new_tab(url));
                                }
                            }
                            if ui.small_button("📋 Copy").clicked() {
                                ui.ctx().copy_text(summary.clone());
                                self.notify(true, "Copied.");
                            }
                        });
                    });
                });
            });
        ui.add_space(2.0);
    }

    fn write_ui(&mut self, ui: &mut egui::Ui) {
        section(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("✏ Write to card").size(18.0).strong());
            ui.add_space(4.0);
            let Some(content) = self.ndef_content().cloned() else {
                ui.weak(match &self.contents {
                    Some(Ok(ReadOutcome::ClassicBlank)) => "Set up the card first, then you can write to it.",
                    Some(Ok(ReadOutcome::Unsupported(_))) => "This card can't be written here.",
                    _ => "Once the card has been read, you can write to it here.",
                });
                return;
            };
            if !content.writable {
                ui.label("🔒 This card is locked (read-only).");
                return;
            }

            ui.label("What do you want to put on the card?");
            ui.horizontal_wrapped(|ui| {
                for k in WriteKind::ALL {
                    let name = match k {
                        WriteKind::Text => "Text",
                        WriteKind::Website => "Website",
                        WriteKind::Phone => "Phone",
                        WriteKind::Email => "Email",
                    };
                    let text = RichText::new(format!("{} {name}", k.record_kind().icon())).size(15.0);
                    if ui.selectable_label(self.write_kind == k, text).clicked() {
                        self.write_kind = k;
                    }
                }
            });
            let edit = if self.write_kind == WriteKind::Text {
                egui::TextEdit::multiline(&mut self.write_text).desired_rows(3)
            } else {
                egui::TextEdit::singleline(&mut self.write_text)
            };
            ui.add(edit.hint_text(self.write_kind.hint()).desired_width(f32::INFINITY));

            let built = (!self.write_text.trim().is_empty()).then(|| self.write_kind.build(&self.write_text));
            let mut can_write = false;
            match &built {
                Some(Ok(rec)) => {
                    let size = tag::encoded_size(content.tech, std::slice::from_ref(rec));
                    can_write = size <= content.capacity;
                    ui.horizontal_wrapped(|ui| {
                        ui.weak("Will write:");
                        ui.label(format!("{} {}", rec.kind().icon(), rec.summary()));
                    });
                    let size_text = format!("Needs {size} of {} bytes", content.capacity);
                    if can_write {
                        ui.weak(size_text);
                    } else {
                        ui.colored_label(BAD, format!("{size_text}. Please shorten it."));
                    }
                }
                Some(Err(e)) => {
                    ui.colored_label(BAD, e);
                }
                None => {}
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(can_write, primary("💾 Write to card")).clicked() {
                    if content.records.is_empty() {
                        self.run(Action::Write);
                    } else {
                        self.confirm = Some(Action::Write);
                    }
                }
                if ui.add_enabled(!content.records.is_empty(), egui::Button::new("🧹 Erase card")).clicked() {
                    self.confirm = Some(Action::Erase);
                }
            });
            if !content.records.is_empty() {
                ui.weak("Writing replaces everything currently on the card.");
            }
        });
    }

    fn confirm_ui(&mut self, ctx: &egui::Context) {
        let Some(action) = self.confirm else { return };
        let (title, body, button) = match action {
            Action::Write => (
                "Replace what's on the card?",
                "Everything currently on the card will be replaced with the new content.",
                "Replace",
            ),
            Action::Erase => (
                "Erase this card?",
                "Everything on the card will be deleted. This can't be undone.",
                "Erase",
            ),
            Action::Format => (
                "Set up this card?",
                "NFC Studio will prepare this blank card to hold messages, the same way phones do. \
                 Keep the card still on the reader until it finishes.",
                "Set up card",
            ),
        };
        let (mut go, mut cancel) = (false, false);
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(380.0);
                ui.add(egui::Label::new(body).wrap());
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    go = ui.add(primary(button)).clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
        if go {
            self.confirm = None;
            self.run(action);
        } else if cancel {
            self.confirm = None;
        }
    }

    fn simple_ui(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(16.0))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    self.notice_ui(ui);
                    self.status_ui(ui);
                    if self.info.is_none() {
                        return;
                    }
                    ui.add_space(8.0);
                    if ui.available_width() >= 820.0 {
                        ui.columns(2, |cols| {
                            self.contents_ui(&mut cols[0]);
                            self.write_ui(&mut cols[1]);
                        });
                    } else {
                        self.contents_ui(ui);
                        ui.add_space(8.0);
                        self.write_ui(ui);
                    }
                });
            });
    }

    // ---- Advanced tools -------------------------------------------------------

    fn transmit(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let App { reader: Some(reader), log, .. } = self else { return Err("PC/SC unavailable".into()) };
        if !reader.is_connected() {
            return Err("No card connected".into());
        }
        Link { reader, log }.transmit(cmd)
    }

    fn transmit_ok(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let resp = self.transmit(cmd)?;
        apdu::expect_ok(&resp)
    }

    fn classic_auth(&mut self, block: u8) -> Result<(), String> {
        let key = apdu::parse_hex(&self.key_hex)?;
        let key: [u8; 6] = key.try_into().map_err(|_| "Key must be exactly 6 bytes".to_string())?;
        let r = self
            .transmit_ok(&apdu::load_key(0, &key))
            .and_then(|_| self.transmit_ok(&apdu::authenticate(block, self.key_type, 0)));
        if r.is_err() {
            if let Some(reader) = self.reader.as_mut() {
                let _ = reader.reactivate();
            }
        }
        r.map(|_| ())
    }

    fn classic_read_block(&mut self) {
        let block = self.block;
        let r = self.classic_auth(block).and_then(|_| self.transmit_ok(&apdu::read_binary(block, 16)));
        match r {
            Ok(data) => {
                self.block_data = apdu::to_hex(&data);
                self.log(format!("Block {block}: {} |{}|", apdu::to_hex(&data), apdu::to_ascii(&data)));
            }
            Err(e) => self.log(format!("Read block {block} failed: {e}")),
        }
    }

    fn classic_read_sector(&mut self) {
        let first = self.block - self.block % 4;
        if let Err(e) = self.classic_auth(first) {
            self.log(format!("Auth sector {} failed: {e}", first / 4));
            return;
        }
        for b in first..first + 4 {
            match self.transmit_ok(&apdu::read_binary(b, 16)) {
                Ok(d) => self.log(format!("Block {b:>3}: {} |{}|", apdu::to_hex(&d), apdu::to_ascii(&d))),
                Err(e) => self.log(format!("Block {b:>3}: {e}")),
            }
        }
    }

    fn classic_write_block(&mut self) {
        let block = self.block;
        if block == 0 {
            self.log("Refusing to write block 0 (manufacturer block)");
            return;
        }
        if apdu::is_sector_trailer(block) && !self.allow_trailer {
            self.log("Block is a sector trailer; tick the confirmation box to write it");
            return;
        }
        let data = match apdu::parse_hex(&self.block_data) {
            Ok(d) if d.len() == 16 => d,
            Ok(d) => {
                self.log(format!("Block data must be 16 bytes (got {})", d.len()));
                return;
            }
            Err(e) => {
                self.log(e);
                return;
            }
        };
        let r = self.classic_auth(block).and_then(|_| self.transmit_ok(&apdu::update_binary(block, &data)));
        match r {
            Ok(_) => self.log(format!("Wrote block {block}")),
            Err(e) => self.log(format!("Write block {block} failed: {e}")),
        }
    }

    fn ul_read(&mut self) {
        let page = self.page;
        match self.transmit_ok(&apdu::read_binary(page, 16)) {
            Ok(d) => {
                self.page_data = apdu::to_hex(&d[..d.len().min(4)]);
                for (i, chunk) in d.chunks(4).enumerate() {
                    self.log(format!(
                        "Page {:>3}: {} |{}|",
                        page as usize + i,
                        apdu::to_hex(chunk),
                        apdu::to_ascii(chunk)
                    ));
                }
            }
            Err(e) => self.log(format!("Read page {page} failed: {e}")),
        }
    }

    fn ul_write(&mut self) {
        let page = self.page;
        if page < 4 {
            self.log("Pages 0-3 hold UID/lock/OTP bits; writing them is refused");
            return;
        }
        let data = match apdu::parse_hex(&self.page_data) {
            Ok(d) if d.len() == 4 => d,
            Ok(d) => {
                self.log(format!("Page data must be 4 bytes (got {})", d.len()));
                return;
            }
            Err(e) => {
                self.log(e);
                return;
            }
        };
        match self.transmit_ok(&apdu::update_binary(page, &data)) {
            Ok(_) => self.log(format!("Wrote page {page}")),
            Err(e) => self.log(format!("Write page {page} failed: {e}")),
        }
    }

    fn advanced_ui(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("advanced_bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                match &self.info {
                    Some(info) => {
                        ui.strong(info.kind.label());
                        ui.label(format!("ATR: {}", apdu::to_hex(&info.atr)));
                        ui.label(format!(
                            "UID: {}",
                            info.uid.as_deref().map(apdu::to_hex).unwrap_or_else(|| "?".into())
                        ));
                    }
                    None => {
                        ui.weak("No card connected. Place a card on the reader.");
                    }
                }
                if ui.small_button("⟳ Reconnect").clicked() {
                    self.forget_card();
                }
            });
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Apdu, "Raw commands (APDU)");
                ui.selectable_value(&mut self.tab, Tab::Classic, "MIFARE Classic blocks");
                ui.selectable_value(&mut self.tab, Tab::Ultralight, "NTAG / Ultralight pages");
            });
            ui.add_space(2.0);
        });

        egui::TopBottomPanel::bottom("log")
            .resizable(true)
            .default_height(240.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("Log");
                    if ui.small_button("Clear").clicked() {
                        self.log.clear();
                    }
                });
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in &self.log {
                            ui.monospace(line);
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Apdu => {
                ui.label("Command APDU (hex):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.apdu_input)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
                ui.horizontal(|ui| {
                    if ui.button("Send").clicked() {
                        match apdu::parse_hex(&self.apdu_input) {
                            Ok(cmd) => match self.transmit(&cmd) {
                                Ok(resp) => {
                                    if let Ok((_, sw)) = apdu::split_sw(&resp) {
                                        self.log(format!("SW {sw:04X}: {}", apdu::describe_sw(sw)));
                                    }
                                }
                                Err(e) => self.log(e),
                            },
                            Err(e) => self.log(e),
                        }
                    }
                    for (label, cmd) in [
                        ("Get UID", "FF CA 00 00 00"),
                        ("Get ATS", "FF CA 01 00 00"),
                        ("Select PPSE", "00 A4 04 00 0E 32 50 41 59 2E 53 59 53 2E 44 44 46 30 31 00"),
                    ] {
                        if ui.small_button(label).clicked() {
                            self.apdu_input = cmd.into();
                        }
                    }
                });
            }
            Tab::Classic => {
                egui::Grid::new("classic").num_columns(2).show(ui, |ui| {
                    ui.label("Key (6 bytes hex):");
                    ui.text_edit_singleline(&mut self.key_hex);
                    ui.end_row();
                    ui.label("Key type:");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.key_type, KeyType::A, "A");
                        ui.radio_value(&mut self.key_type, KeyType::B, "B");
                    });
                    ui.end_row();
                    ui.label("Block:");
                    ui.horizontal(|ui| {
                        ui.add(egui::DragValue::new(&mut self.block).range(0..=255));
                        ui.weak(format!(
                            "sector {}{}",
                            self.block / 4,
                            if apdu::is_sector_trailer(self.block) { " (trailer)" } else { "" }
                        ));
                    });
                    ui.end_row();
                    ui.label("Data (16 bytes hex):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.block_data)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(420.0),
                    );
                    ui.end_row();
                });
                ui.weak("Blocks ≥128 on 4K cards use 16-block sectors; sector read covers 4-block sectors.");
                ui.horizontal(|ui| {
                    if ui.button("Read block").clicked() {
                        self.classic_read_block();
                    }
                    if ui.button("Read sector").clicked() {
                        self.classic_read_sector();
                    }
                    if ui.button("Write block").clicked() {
                        self.classic_write_block();
                    }
                });
                ui.checkbox(
                    &mut self.allow_trailer,
                    "I understand writing a sector trailer can permanently lock the sector",
                );
            }
            Tab::Ultralight => {
                egui::Grid::new("ul").num_columns(2).show(ui, |ui| {
                    ui.label("Page:");
                    ui.add(egui::DragValue::new(&mut self.page).range(0..=255));
                    ui.end_row();
                    ui.label("Data (4 bytes hex):");
                    ui.add(egui::TextEdit::singleline(&mut self.page_data).font(egui::TextStyle::Monospace));
                    ui.end_row();
                });
                ui.horizontal(|ui| {
                    if ui.button("Read 4 pages").clicked() {
                        self.ul_read();
                    }
                    if ui.button("Write page").clicked() {
                        self.ul_write();
                    }
                });
                ui.weak("Pages 0–3 (UID, lock bytes, capability container) are protected.");
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_poll.map_or(true, |t| t.elapsed() >= POLL) {
            self.last_poll = Some(Instant::now());
            self.poll();
        }
        ctx.request_repaint_after(POLL);
        if let Some(n) = &self.notice {
            if n.at.elapsed() > Duration::from_secs(if n.ok { 5 } else { 12 }) {
                self.notice = None;
            }
        }

        let was_advanced = self.advanced;
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::side_top_panel(&ctx.style()).inner_margin(egui::Margin::symmetric(16.0, 10.0)))
            .show(ctx, |ui| self.header_ui(ui));
        if was_advanced && !self.advanced {
            // Advanced tools may have changed the card; refresh the friendly view.
            self.read_contents();
        }

        if self.advanced {
            self.advanced_ui(ctx);
        } else {
            self.simple_ui(ctx);
            self.confirm_ui(ctx);
        }
    }
}
