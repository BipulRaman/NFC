#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Align, Align2, Color32, Layout, RichText};
use nfc_studio::apdu::{self, KeyType};
use nfc_studio::badge::{self, WedgeDecoder};
use nfc_studio::card::{CardInfo, CardKind, RawMode, Reader};
use nfc_studio::ndef::{self, Record, RecordKind, WriteKind};
use nfc_studio::ntag::{self, Raw};
use nfc_studio::rawjson;
use nfc_studio::seal::{self, RawRecord, SealStatus, SigningKey};
use nfc_studio::tag::{self, ReadOutcome, TagContent, Tech, Transport};
use std::collections::HashMap;
use std::path::PathBuf;
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

/// Monospace, selectable JSON in a tinted box.
fn json_block(ui: &mut egui::Ui, json: &str) {
    egui::Frame::none()
        .fill(ui.visuals().extreme_bg_color)
        .rounding(6.0)
        .inner_margin(8.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(json).monospace()).wrap().selectable(true));
        });
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

/// Raw tag commands (passwords, permanent lock) through the reader's transparent channel.
struct RawLink<'a> {
    reader: &'a mut Reader,
    mode: RawMode,
    log: &'a mut Vec<String>,
}

impl<'a> RawLink<'a> {
    fn open(reader: &'a mut Reader, log: &'a mut Vec<String>) -> Option<Self> {
        let mode = reader.raw_begin()?;
        push_log(log, format!("Raw channel: {mode:?}"));
        Some(Self { reader, mode, log })
    }
}

impl Raw for RawLink<'_> {
    fn raw(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let r = self.reader.raw(self.mode, frame);
        // Never log password bytes.
        let shown = match frame.first() {
            Some(0x1B) => "1B ** ** ** **".to_string(),
            Some(0xA2) if frame.len() == 6 => format!("A2 {:02X} ** ** ** **", frame[1]),
            _ => apdu::to_hex(frame),
        };
        match &r {
            Ok(d) => push_log(self.log, format!("raw >> {shown}\nraw << {}", apdu::to_hex(d))),
            Err(e) => push_log(self.log, format!("raw >> {shown}\nraw !! {e}")),
        }
        r
    }
}

impl Drop for RawLink<'_> {
    fn drop(&mut self) {
        self.reader.raw_end(self.mode);
    }
}

const NO_RAW: &str = "This reader can't send the commands needed for card passwords. Readers such as the \
     ACR122U, ACR1252U or OMNIKEY 5022 can, and so can the Android app.";

/// Where this computer's tamper-seal signing key is kept.
fn seal_key_path() -> Option<PathBuf> {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return Some(PathBuf::from(appdata).join("NFC Studio").join("seal-key"));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("nfc-studio").join("seal-key"))
}

fn load_seal_key() -> Option<SigningKey> {
    seal::key_from_bytes(&std::fs::read(seal_key_path()?).ok()?)
}

fn create_seal_key() -> Result<SigningKey, String> {
    let path = seal_key_path().ok_or("Couldn't find a folder to keep the seal key in.")?;
    let key = seal::generate_key();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Couldn't save the seal key: {e}"))?;
    }
    std::fs::write(&path, seal::key_to_bytes(&key)).map_err(|e| format!("Couldn't save the seal key: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(key)
}

#[derive(Clone, Copy)]
struct Protection {
    /// The reader can send raw tag commands.
    raw: bool,
    model: Option<ntag::Model>,
    status: ntag::Status,
}

#[derive(Clone, Copy, PartialEq)]
enum PwMode {
    /// Ask for the card password, then run the action.
    Unlock(Action),
    Set,
    Change,
    Remove,
    Lock,
    /// Wipe all memory and remove the password.
    Erase,
}

struct PwDialog {
    mode: PwMode,
    current: String,
    new1: String,
    new2: String,
    limit: bool,
    understood: bool,
    scheme: ntag::PwScheme,
    error: Option<String>,
}

impl PwDialog {
    fn new(mode: PwMode) -> Self {
        Self {
            mode,
            current: String::new(),
            new1: String::new(),
            new2: String::new(),
            limit: true,
            understood: false,
            scheme: ntag::PwScheme::NfcStudio,
            error: None,
        }
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
    Seal,
}

#[derive(PartialEq, Clone, Copy)]
enum View {
    Cards,
    Badges,
}

struct BadgeScan {
    id: String,
    at: Instant,
    count: u32,
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

    seal: SealStatus,
    /// The card's records without the seal, exactly as stored.
    content_raw: Vec<RawRecord>,
    seal_key: Option<SigningKey>,
    seal_on_write: bool,
    protection: Option<Protection>,
    /// Card passwords entered this session, by card ID (memory only).
    card_passwords: HashMap<Vec<u8>, String>,
    pw_dialog: Option<PwDialog>,
    show_raw: bool,

    view: View,
    wedge: WedgeDecoder,
    badges: Vec<BadgeScan>,

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
            seal: SealStatus::None,
            content_raw: Vec::new(),
            seal_key: load_seal_key(),
            seal_on_write: true,
            protection: None,
            card_passwords: HashMap::new(),
            pw_dialog: None,
            show_raw: false,
            view: View::Cards,
            wedge: WedgeDecoder::default(),
            badges: Vec::new(),
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
        self.pw_dialog = None;
        self.show_raw = false;
        self.seal = SealStatus::None;
        self.content_raw.clear();
        self.protection = None;
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
            if matches!(result, Ok(ReadOutcome::Ndef(_) | ReadOutcome::Blank(_))) {
                break;
            }
        }

        self.seal = SealStatus::None;
        self.content_raw.clear();
        self.protection = None;
        let uid = self.uid();
        if let Ok(ReadOutcome::Ndef(c)) = &mut result {
            if let Ok(raws) = seal::decode_raw(&c.message) {
                let (status, content) = seal::verify(&uid, &raws);
                let content: Vec<RawRecord> = content.into_iter().filter(|r| !r.is_empty_record()).collect();
                if status != SealStatus::None {
                    c.records = ndef::decode_message(&seal::encode_raw(&content)).unwrap_or_default();
                }
                self.seal = status;
                self.content_raw = content;
            }
            if c.tech == Tech::Type2 {
                self.protection = self.probe_protection(c.writable);
            }
        }
        self.contents = Some(result.map_err(|e| friendly_error(&e)));
    }

    fn uid(&self) -> Vec<u8> {
        self.info.as_ref().and_then(|i| i.uid.clone()).unwrap_or_default()
    }

    /// Asks an NTAG / Ultralight EV1 tag whether it has a write password or is locked.
    fn probe_protection(&mut self, writable: bool) -> Option<Protection> {
        let fallback = if writable { ntag::Status::Open } else { ntag::Status::Locked };
        let App { reader: Some(reader), log, .. } = self else { return None };
        let Some(mut raw) = RawLink::open(reader, log) else {
            return Some(Protection { raw: false, model: None, status: fallback });
        };
        let model = ntag::identify(&mut raw);
        let status = model.and_then(|m| ntag::status(&mut raw, m).ok()).unwrap_or(fallback);
        Some(Protection { raw: true, model, status })
    }

    fn needs_password(&self) -> bool {
        matches!(self.protection, Some(Protection { status: ntag::Status::Password { .. }, .. }))
    }

    fn will_seal(&self) -> bool {
        self.seal_on_write && seal::uid_is_stable(&self.uid())
    }

    fn seal_key(&mut self) -> Result<SigningKey, String> {
        if let Some(k) = &self.seal_key {
            return Ok(k.clone());
        }
        let key = create_seal_key()?;
        self.seal_key = Some(key.clone());
        Ok(key)
    }

    /// Bytes `records` (plus a seal, if one will be added) take on this card.
    fn planned_size(&self, tech: Tech, records: &[Record]) -> usize {
        let mut raws = seal::decode_raw(&ndef::encode_message(records)).unwrap_or_default();
        if self.will_seal() && !raws.is_empty() {
            raws.push(RawRecord { tnf: 4, rtype: seal::SEAL_TYPE.to_vec(), id: Vec::new(), payload: vec![0; 98] });
        }
        tag::message_size(tech, &seal::encode_raw(&raws))
    }

    fn ndef_content(&self) -> Option<&TagContent> {
        match &self.contents {
            Some(Ok(ReadOutcome::Ndef(c))) => Some(c),
            _ => None,
        }
    }

    fn run(&mut self, action: Action) {
        let changes_card = matches!(action, Action::Write | Action::Erase | Action::Seal);
        if changes_card && self.needs_password() && !self.card_passwords.contains_key(&self.uid()) {
            self.pw_dialog = Some(PwDialog::new(PwMode::Unlock(action)));
            return;
        }
        let result = match action {
            Action::Write => match self.write_kind.build(&self.write_text) {
                Ok(rec) => self.write_records(&[rec]).map(|_| "Saved to the card."),
                Err(e) => Err(e),
            },
            Action::Erase => self.write_records(&[]).map(|_| "The card is now empty."),
            Action::Format => self.format().map(|_| "The card is set up. You can now write to it."),
            Action::Seal => self
                .write_raws(self.content_raw.clone(), true)
                .map(|_| "The card is sealed. Any change or copy will now be detected."),
        };
        match result {
            Ok(msg) => {
                if action == Action::Write {
                    self.write_text.clear();
                }
                self.notify(true, msg);
            }
            Err(e) if e == ntag::WRONG_PASSWORD => {
                self.card_passwords.remove(&self.uid());
                let mut d = PwDialog::new(PwMode::Unlock(action));
                d.error = Some(e);
                self.pw_dialog = Some(d);
            }
            Err(e) => self.notify(false, friendly_error(&e)),
        }
        self.read_contents();
    }

    fn write_records(&mut self, records: &[Record]) -> Result<(), String> {
        let raws = seal::decode_raw(&ndef::encode_message(records))?;
        self.write_raws(raws, self.seal_on_write)
    }

    fn write_raws(&mut self, mut raws: Vec<RawRecord>, add_seal: bool) -> Result<(), String> {
        let tech = self.ndef_content().map(|c| c.tech).ok_or("Read the card first.")?;
        let uid = self.uid();
        if add_seal && !raws.is_empty() && seal::uid_is_stable(&uid) {
            let key = self.seal_key()?;
            let seal = seal::seal_record(&key, &uid, &raws);
            raws.push(seal);
        }
        let msg = seal::encode_raw(&raws);
        let password = if self.needs_password() {
            Some(self.card_passwords.get(&uid).cloned().ok_or(ntag::WRONG_PASSWORD)?)
        } else {
            None
        };
        let App { reader: Some(reader), log, .. } = self else { return Err("No reader".into()) };
        match password {
            None => tag::write_message(&mut Link { reader, log }, tech, &msg),
            Some(pw) => {
                let mut raw = RawLink::open(reader, log).ok_or(NO_RAW)?;
                ntag::authenticate(&mut raw, &pw, &uid)?;
                tag::write_message(&mut ntag::RawTransport(&mut raw), tech, &msg)
            }
        }
    }

    /// Runs a password / lock change from the dialog; returns the success message.
    fn apply_protection(&mut self, d: &PwDialog) -> Result<&'static str, String> {
        let uid = self.uid();
        let model = self.protection.and_then(|p| p.model);
        let current = (!d.current.is_empty()).then_some(d.current.as_str());
        if matches!(d.mode, PwMode::Set | PwMode::Change) {
            if d.new1.chars().count() < 4 {
                return Err("Choose a password of at least 4 characters.".into());
            }
            if d.new1 != d.new2 {
                return Err("The two passwords don't match.".into());
            }
        }
        if matches!(d.mode, PwMode::Lock | PwMode::Erase) && !d.understood {
            return Err("Tick the box to confirm you understand this can't be undone.".into());
        }
        if d.mode == PwMode::Erase && d.limit && d.current.is_empty() {
            return Err("Enter the card's current password.".into());
        }
        let App { reader: Some(reader), log, .. } = self else { return Err("No reader".into()) };
        let mut raw = RawLink::open(reader, log).ok_or(NO_RAW)?;
        let need_model = || model.ok_or_else(|| "This tag type doesn't support a password.".to_string());
        let msg = match d.mode {
            PwMode::Set | PwMode::Change => {
                ntag::set_password(&mut raw, need_model()?, &uid, &d.new1, d.limit, current)?;
                "Password set. The card can now only be changed with it."
            }
            PwMode::Remove => {
                ntag::remove_password(&mut raw, need_model()?, &uid, &d.current)?;
                "Password removed. Anyone can change the card again."
            }
            PwMode::Lock => {
                ntag::lock_forever(&mut raw, model, &uid, current)?;
                "The card is now locked permanently."
            }
            PwMode::Erase => {
                ntag::factory_reset(&mut raw, need_model()?, &uid, current, d.scheme)?;
                "The card is completely erased and has no password. It's like new."
            }
            PwMode::Unlock(_) => unreachable!(),
        };
        drop(raw);
        match d.mode {
            PwMode::Set | PwMode::Change => {
                self.card_passwords.insert(uid, d.new1.clone());
            }
            _ => {
                self.card_passwords.remove(&uid);
            }
        }
        Ok(msg)
    }

    fn format(&mut self) -> Result<(), String> {
        let Some(Ok(ReadOutcome::Blank(tech))) = self.contents else {
            return Err("Read the card first.".into());
        };
        let App { reader: Some(reader), log, .. } = self else { return Err("No reader".into()) };
        tag::format(&mut Link { reader, log }, tech)
    }

    // ---- 125 kHz badges --------------------------------------------------------

    /// Watches keyboard input for card numbers typed by a USB badge reader.
    fn capture_badges(&mut self, ctx: &egui::Context) {
        if ctx.memory(|m| m.focused().is_some()) {
            return;
        }
        let now = Instant::now();
        let events = ctx.input(|i| i.events.clone());
        for event in events {
            match event {
                egui::Event::Text(text) => self.wedge.push(&text, now),
                egui::Event::Key { key: egui::Key::Enter | egui::Key::Tab, pressed: true, .. } => {
                    if let Some(id) = self.wedge.finish(now) {
                        self.on_badge(id);
                    }
                }
                _ => {}
            }
        }
    }

    fn on_badge(&mut self, id: String) {
        self.log(format!("125 kHz badge: {id}"));
        match self.badges.first_mut() {
            // Readers repeat the number while the badge stays in the field.
            Some(last) if last.id == id && last.at.elapsed() < Duration::from_secs(3) => {
                last.count += 1;
                last.at = Instant::now();
            }
            _ => {
                self.badges.insert(0, BadgeScan { id, at: Instant::now(), count: 1 });
                self.badges.truncate(100);
            }
        }
        if !self.advanced {
            self.view = View::Badges;
        }
    }

    fn badges_ui(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(16.0))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    self.notice_ui(ui);
                    let latest = self.badges.first().map(|b| (b.id.clone(), b.at));
                    section(ui).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("🏷").size(44.0));
                            ui.vertical(|ui| match &latest {
                                None => {
                                    ui.label(RichText::new("Scan a 125 kHz badge").size(21.0).strong());
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(
                                                "Plug in a USB 125 kHz RFID reader (EM4100 / HID Prox / T5577 badge \
                                                 readers that type the card number) and hold a badge to it. Keep \
                                                 this window in front while scanning.",
                                            )
                                            .weak(),
                                        )
                                        .wrap(),
                                    );
                                }
                                Some((id, at)) => {
                                    ui.label(RichText::new("Badge number").weak());
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(id).monospace().size(28.0).strong());
                                        if ui.button("📋 Copy").clicked() {
                                            ui.ctx().copy_text(id.clone());
                                            self.notify(true, "Badge number copied.");
                                        }
                                    });
                                    ui.weak(format!("Scanned {}", ago(*at)));
                                }
                            });
                        });
                        if let Some((id, _)) = &latest {
                            let formats = badge::interpret(id);
                            if !formats.is_empty() {
                                ui.add_space(8.0);
                                egui::Grid::new("badge_formats").num_columns(3).spacing([16.0, 6.0]).show(ui, |ui| {
                                    for (label, value) in formats {
                                        ui.weak(label);
                                        ui.label(RichText::new(&value).monospace().size(16.0));
                                        if ui.small_button("📋").on_hover_text("Copy").clicked() {
                                            ui.ctx().copy_text(value.clone());
                                            self.notify(true, format!("{label} copied."));
                                        }
                                        ui.end_row();
                                    }
                                });
                            }
                        }
                    });

                    ui.add_space(8.0);
                    section(ui).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("🕘 Scan history").size(18.0).strong());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add_enabled(!self.badges.is_empty(), egui::Button::new("🗑 Clear")).clicked() {
                                    self.badges.clear();
                                }
                                if ui.add_enabled(!self.badges.is_empty(), egui::Button::new("📋 Copy list")).clicked() {
                                    let list = self.badges.iter().map(|b| b.id.as_str()).collect::<Vec<_>>().join("\n");
                                    ui.ctx().copy_text(list);
                                    self.notify(true, "Scan history copied.");
                                }
                            });
                        });
                        if self.badges.is_empty() {
                            ui.weak("Scanned badges appear here.");
                        }
                        let mut copied = None;
                        for b in &self.badges {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&b.id).monospace());
                                if b.count > 1 {
                                    ui.weak(format!("×{}", b.count));
                                }
                                ui.weak(ago(b.at));
                                if ui.small_button("📋").on_hover_text("Copy").clicked() {
                                    copied = Some(b.id.clone());
                                }
                            });
                        }
                        if let Some(id) = copied {
                            ui.ctx().copy_text(id);
                            self.notify(true, "Badge number copied.");
                        }
                    });
                    ui.add_space(6.0);
                    ui.weak(
                        "13.56 MHz NFC and RFID cards (MIFARE, NTAG, ICODE, …) are read on the Cards tab with a \
                         PC/SC reader.",
                    );
                });
            });
    }

    // ---- Simple view ---------------------------------------------------------

    fn header_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("📶 NFC Studio").size(22.0).strong());
            ui.add_space(12.0);
            if !self.advanced {
                ui.selectable_value(&mut self.view, View::Cards, RichText::new("💳 NFC & RFID cards").size(15.0));
                ui.selectable_value(&mut self.view, View::Badges, RichText::new("🏷 125 kHz badges").size(15.0))
                    .on_hover_text("Badges read with a USB 125 kHz reader that types the card number");
            }
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
                "Connect an NFC / RFID reader".to_string(),
                "Plug a USB NFC or smart-card reader (for example an ACR122U or OMNIKEY) into this computer. \
                 It will be detected automatically. Using a 125 kHz badge reader? Open the “125 kHz badges” tab."
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
                format!("Hold an NFC or RFID card, tag or sticker flat on “{name}”. It will be read automatically."),
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
        section(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("📖 On this card").size(18.0).strong());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("⟳ Read again").clicked() {
                        self.read_contents();
                    }
                    if self.ndef_content().is_some()
                        && ui.button("{ } Raw data").on_hover_text("Everything on the card as JSON").clicked()
                    {
                        self.show_raw = true;
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
                Some(Ok(ReadOutcome::Blank(tech))) => {
                    ui.label(RichText::new("This card is blank.").size(16.0));
                    ui.add(
                        egui::Label::new(
                            "It isn't set up to hold messages yet. Setting it up takes a few seconds and lets \
                             phones and this app read and write it.",
                        )
                        .wrap(),
                    );
                    ui.add_space(4.0);
                    if tag::can_format(tech) {
                        if ui.add(primary("✨ Set up card")).clicked() {
                            self.confirm = Some(Action::Format);
                        }
                    } else {
                        ui.weak("Setting up this size of MIFARE Classic card isn't supported.");
                    }
                }
                Some(Ok(ReadOutcome::Ndef(c))) => {
                    self.seal_badge_ui(ui);
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
                    } else if self.needs_password() {
                        ui.label("🔑 Changes to this card need its password.");
                    }
                }
            }
        });
    }

    fn seal_badge_ui(&mut self, ui: &mut egui::Ui) {
        let mine = self.seal_key.as_ref().map(seal::public_key);
        let (color, text) = match &self.seal {
            SealStatus::None => return,
            SealStatus::Valid { key } if Some(key) == mine.as_ref() => {
                (GOOD, "🛡 Sealed by you. Nothing has changed since it was sealed.".to_string())
            }
            SealStatus::Valid { key } => (
                GOOD,
                format!(
                    "🛡 Sealed by another device (key {}). Nothing has changed since it was sealed.",
                    seal::fingerprint(key)
                ),
            ),
            SealStatus::Broken => (
                BAD,
                "⚠ Seal broken! This card was changed, or its content was copied from another card, after it \
                 was sealed. Don't trust what's on it."
                    .to_string(),
            ),
        };
        egui::Frame::none()
            .stroke(egui::Stroke::new(1.5_f32, color))
            .rounding(8.0)
            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(egui::Label::new(RichText::new(text).color(color).strong()).wrap());
            });
        ui.add_space(4.0);
    }

    fn protection_ui(&mut self, ui: &mut egui::Ui) {
        let Some(content) = self.ndef_content().cloned() else { return };
        let uid = self.uid();
        section(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("🛡 Protection").size(18.0).strong());
            ui.add_space(4.0);

            ui.label(RichText::new("Tamper seal").strong());
            if seal::uid_is_stable(&uid) {
                ui.checkbox(&mut self.seal_on_write, "Seal the card whenever I write to it");
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "A digital signature tied to this card's ID. If anyone changes the content, or copies \
                             it to another card, NFC Studio shows “Seal broken”.",
                        )
                        .weak(),
                    )
                    .wrap(),
                );
                let mine = self.seal_key.as_ref().map(seal::public_key);
                let sealed_by_me = matches!(&self.seal, SealStatus::Valid { key } if Some(key) == mine.as_ref());
                if content.writable && !self.content_raw.is_empty() && !sealed_by_me {
                    if ui.button("🛡 Seal what's on the card now").clicked() {
                        self.confirm = Some(Action::Seal);
                    }
                }
                if let Some(key) = &mine {
                    ui.weak(format!("This computer's seal key: {}", seal::fingerprint(key)));
                }
            } else {
                ui.weak("This card's ID changes every time it's read, so it can't be sealed.");
            }

            ui.add_space(8.0);
            ui.label(RichText::new("Write protection").strong());
            match self.protection {
                None => {
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "A write password and permanent lock are available for NTAG213/215/216 and \
                                 MIFARE Ultralight EV1 tags. Use the tamper seal to protect this card.",
                            )
                            .weak(),
                        )
                        .wrap(),
                    );
                }
                Some(Protection { raw: false, .. }) => {
                    ui.add(egui::Label::new(RichText::new(NO_RAW).weak()).wrap());
                }
                Some(p) => {
                    match p.status {
                        ntag::Status::Open => {
                            ui.label("🔓 Anyone can change this card.");
                        }
                        ntag::Status::Password { limited } => {
                            ui.label("🔑 Changes need the card password. Anyone can still read it.");
                            if limited {
                                ui.weak(format!(
                                    "After {} wrong passwords in a row the card can never be changed again.",
                                    p.model.map_or(8, ntag::Model::max_attempts)
                                ));
                            }
                        }
                        ntag::Status::Locked => {
                            ui.label("🔒 Locked permanently. Nobody can ever change this card.");
                            ui.add(egui::Label::new(RichText::new(ntag::LOCKED_FOREVER).weak()).wrap());
                        }
                    }
                    ui.horizontal_wrapped(|ui| {
                        let has_pw = matches!(p.status, ntag::Status::Password { .. });
                        if p.model.is_some() {
                            match p.status {
                                ntag::Status::Open => {
                                    if ui.button("🔑 Set password…").clicked() {
                                        self.pw_dialog = Some(PwDialog::new(PwMode::Set));
                                    }
                                }
                                ntag::Status::Password { .. } => {
                                    if ui.button("Change password…").clicked() {
                                        self.pw_dialog = Some(PwDialog::new(PwMode::Change));
                                    }
                                    if ui.button("Remove password…").clicked() {
                                        self.pw_dialog = Some(PwDialog::new(PwMode::Remove));
                                    }
                                }
                                ntag::Status::Locked => {}
                            }
                        } else if p.status != ntag::Status::Locked {
                            ui.weak("This tag type doesn't support a password.");
                        }
                        if p.status != ntag::Status::Locked && (p.model.is_some() || content.capacity <= 48) {
                            let mut d = PwDialog::new(PwMode::Lock);
                            // For locking, `limit` records whether the current password must be entered.
                            d.limit = has_pw;
                            if ui.button("🔒 Lock permanently…").clicked() {
                                self.pw_dialog = Some(d);
                            }
                        }
                        if p.model.is_some() && p.status != ntag::Status::Locked {
                            let mut d = PwDialog::new(PwMode::Erase);
                            // For erasing, `limit` records whether the current password must be entered.
                            d.limit = has_pw;
                            if ui
                                .button("🧹 Erase completely…")
                                .on_hover_text("Wipe every byte and remove the password, like a new card")
                                .clicked()
                            {
                                self.pw_dialog = Some(d);
                            }
                        }
                    });
                }
            }
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Write protection stops changes but not reading. Keep secrets in the Android app's \
                         PIN-protected items.",
                    )
                    .weak()
                    .small(),
                )
                .wrap(),
            );
        });
    }

    fn pw_dialog_ui(&mut self, ctx: &egui::Context) {
        let Some(mut d) = self.pw_dialog.take() else { return };
        let needs_current = match d.mode {
            PwMode::Unlock(_) | PwMode::Change | PwMode::Remove => true,
            PwMode::Lock | PwMode::Erase => d.limit,
            PwMode::Set => false,
        };
        let needs_new = matches!(d.mode, PwMode::Set | PwMode::Change);
        let attempts = self.protection.and_then(|p| p.model).map_or(8, ntag::Model::max_attempts);
        let (title, body, button) = match d.mode {
            PwMode::Unlock(_) => ("Card password", "This card is write-protected. Enter its password to save changes.", "Continue"),
            PwMode::Set => (
                "Set a card password",
                "The card stays readable by anyone, but changing or erasing it will need this password. \
                 It's stored in the card's chip.",
                "Set password",
            ),
            PwMode::Change => ("Change card password", "Enter the current password, then the new one.", "Change password"),
            PwMode::Remove => ("Remove card password", "Anyone will be able to change the card again.", "Remove password"),
            PwMode::Lock => (
                "Lock card permanently?",
                "The card becomes read-only forever. Nobody, including you, will ever be able to change or erase \
                 it again. Its current content stays readable.",
                "Lock forever",
            ),
            PwMode::Erase => (
                "Erase card completely?",
                "Every byte of the card's memory is wiped, including any seal, and its password is removed. \
                 The card ends up empty and unprotected, like new.",
                "Erase everything",
            ),
        };
        let (mut submit, mut cancel) = (false, false);
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(400.0);
                ui.add(egui::Label::new(body).wrap());
                ui.add_space(8.0);
                let field = |ui: &mut egui::Ui, label: &str, value: &mut String| {
                    ui.label(label);
                    ui.add(egui::TextEdit::singleline(value).password(true).desired_width(f32::INFINITY))
                };
                if needs_current {
                    if d.mode == PwMode::Erase {
                        ui.label("The password was set with:");
                        for s in ntag::PwScheme::ALL {
                            ui.radio_value(&mut d.scheme, s, s.label());
                        }
                    }
                    let label = if d.scheme == ntag::PwScheme::Hex && d.mode == PwMode::Erase {
                        "Password (8 hex digits)"
                    } else {
                        "Current card password"
                    };
                    let r = field(ui, label, &mut d.current);
                    if !needs_new && r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        submit = true;
                    }
                    if d.mode == PwMode::Erase
                        && matches!(self.protection, Some(Protection { status: ntag::Status::Password { limited: true }, .. }))
                    {
                        ui.colored_label(
                            BAD,
                            format!("Careful: this card freezes for good after {attempts} wrong passwords in a row."),
                        );
                    }
                }
                if needs_new {
                    field(ui, "New password", &mut d.new1);
                    field(ui, "Repeat new password", &mut d.new2);
                    ui.checkbox(&mut d.limit, format!("Freeze the card after {attempts} wrong passwords (stops guessing)"));
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "Tags only hold a short (32-bit) password, so keep the freeze on. There's no way to \
                                 recover a forgotten password, though the card stays readable.",
                            )
                            .weak()
                            .small(),
                        )
                        .wrap(),
                    );
                }
                if matches!(d.mode, PwMode::Lock | PwMode::Erase) {
                    ui.checkbox(&mut d.understood, "I understand this can never be undone");
                }
                if let Some(e) = &d.error {
                    ui.colored_label(BAD, e);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    submit |= ui.add(primary(button)).clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
        if cancel {
            return;
        }
        if !submit {
            self.pw_dialog = Some(d);
            return;
        }
        if let PwMode::Unlock(action) = d.mode {
            if d.current.is_empty() {
                d.error = Some("Enter the card password.".into());
                self.pw_dialog = Some(d);
                return;
            }
            self.card_passwords.insert(self.uid(), d.current.clone());
            self.run(action);
            return;
        }
        match self.apply_protection(&d) {
            Ok(msg) => {
                self.notify(true, msg);
                self.read_contents();
            }
            Err(e) => {
                d.error = Some(friendly_error(&e));
                self.pw_dialog = Some(d);
            }
        }
    }

    fn record_ui(&mut self, ui: &mut egui::Ui, rec: &Record) {
        let kind = rec.kind();
        let summary = rec.summary();
        let raw_json = match rec {
            Record::Other { tnf, rtype, payload } => Some(rawjson::pretty(&rawjson::record(&RawRecord {
                tnf: *tnf,
                rtype: rtype.clone(),
                id: Vec::new(),
                payload: payload.clone(),
            }))),
            _ => None,
        };
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
                            if let Some(json) = &raw_json {
                                if ui.small_button("📋 Copy JSON").clicked() {
                                    ui.ctx().copy_text(json.clone());
                                    self.notify(true, "Raw data copied as JSON.");
                                }
                            }
                        });
                        if let Some(json) = &raw_json {
                            ui.weak("Unrecognised format, shown as raw data:");
                            json_block(ui, json);
                        }
                    });
                });
            });
        ui.add_space(2.0);
    }

    fn raw_window_ui(&mut self, ctx: &egui::Context) {
        if !self.show_raw {
            return;
        }
        let Some(c) = self.ndef_content() else {
            self.show_raw = false;
            return;
        };
        let info = self.info.as_ref();
        let card = serde_json::json!({
            "id": info.and_then(|i| i.uid.as_deref()).map(apdu::to_hex),
            "type": info.map(|i| i.kind.label()),
            "capacity": c.capacity,
            "used": c.used,
            "writable": c.writable,
            "seal": match &self.seal {
                SealStatus::None => "none".to_string(),
                SealStatus::Valid { key } => format!("valid (key {})", seal::fingerprint(key)),
                SealStatus::Broken => "broken".to_string(),
            },
            "protection": match self.protection.map(|p| p.status) {
                None | Some(ntag::Status::Open) => "none",
                Some(ntag::Status::Password { .. }) => "password",
                Some(ntag::Status::Locked) => "locked permanently",
            },
        });
        let raws = seal::decode_raw(&c.message).unwrap_or_default();
        let json = rawjson::pretty(&serde_json::json!({ "card": card, "records": rawjson::records(&raws) }));
        let mut open = true;
        let mut copy = false;
        egui::Window::new("Raw data (JSON)")
            .open(&mut open)
            .default_size([520.0, 420.0])
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                copy = ui.button("📋 Copy JSON").clicked();
                egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| json_block(ui, &json));
            });
        if copy {
            ctx.copy_text(json);
            self.notify(true, "Raw data copied as JSON.");
        }
        self.show_raw = open;
    }

    fn write_ui(&mut self, ui: &mut egui::Ui) {
        section(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("✏ Write to card").size(18.0).strong());
            ui.add_space(4.0);
            let Some(content) = self.ndef_content().cloned() else {
                ui.weak(match &self.contents {
                    Some(Ok(ReadOutcome::Blank(_))) => "Set up the card first, then you can write to it.",
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
                    let size = self.planned_size(content.tech, std::slice::from_ref(rec));
                    can_write = size <= content.capacity;
                    ui.horizontal_wrapped(|ui| {
                        ui.weak("Will write:");
                        ui.label(format!("{} {}", rec.kind().icon(), rec.summary()));
                    });
                    let seal_note = if self.will_seal() { " (including the tamper seal)" } else { "" };
                    let size_text = format!("Needs {size} of {} bytes{seal_note}", content.capacity);
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
            Action::Seal => (
                "Seal this card?",
                "A digital seal tied to this card's ID is added to its current content. From now on, any change \
                 to the content, or copying it to another card, will show as “Seal broken”.",
                "Seal card",
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
                            cols[1].add_space(8.0);
                            self.protection_ui(&mut cols[1]);
                        });
                    } else {
                        self.contents_ui(ui);
                        ui.add_space(8.0);
                        self.write_ui(ui);
                        ui.add_space(8.0);
                        self.protection_ui(ui);
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
        self.capture_badges(ctx);
        egui::TopBottomPanel::top("header")
            .frame(egui::Frame::side_top_panel(&ctx.style()).inner_margin(egui::Margin::symmetric(16.0, 10.0)))
            .show(ctx, |ui| self.header_ui(ui));
        if was_advanced && !self.advanced {
            // Advanced tools may have changed the card; refresh the friendly view.
            self.read_contents();
        }

        if self.advanced {
            self.advanced_ui(ctx);
        } else if self.view == View::Badges {
            self.badges_ui(ctx);
        } else {
            self.simple_ui(ctx);
            self.confirm_ui(ctx);
            self.pw_dialog_ui(ctx);
            self.raw_window_ui(ctx);
        }
    }
}

fn ago(at: Instant) -> String {
    match at.elapsed().as_secs() {
        0..=4 => "just now".into(),
        s @ 5..=59 => format!("{s} s ago"),
        s @ 60..=3599 => format!("{} min ago", s / 60),
        s => format!("{} h ago", s / 3600),
    }
}
